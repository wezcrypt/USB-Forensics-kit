"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from typing import List, Optional

from . import ABOUT, __app_name__, __version__
from .core.config import Config
from .core.custody import CustodyLog
from .core.logging_setup import setup_app_logging
from .core.paths import LOGS_DIR_NAME, application_dir, default_output_root, detect_run_location
from .core.winapi import is_admin

EXIT_OK, EXIT_ERROR, EXIT_VERIFY_FAILED, EXIT_CANCELLED = 0, 1, 2, 130


def _print(msg: str = "") -> None:
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:  # legacy console code pages
        print(msg.encode(sys.stdout.encoding or "ascii", "replace").decode(sys.stdout.encoding or "ascii"), flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="WezCryptUFK", description=f"{__app_name__} {__version__} - portable DFIR collection & analysis")
    p.add_argument("--version", action="version", version=f"{__app_name__} {__version__}")
    p.add_argument("--config", help="path to configuration JSON (default: wezcrypt_config.json next to the kit)")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose console output")
    p.add_argument("--debug", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("gui", help="start the graphical interface (default when no command is given)")
    sub.add_parser("about", help="show application information")
    sub.add_parser("info", help="show environment: privileges, run location, output folder")
    lm = sub.add_parser("list-modules", help="list collection modules")
    lm.add_argument("--json", action="store_true")

    c = sub.add_parser("collect", help="run a collection session")
    c.add_argument("-m", "--modules", default="all", help="comma-separated module names or 'all' (see list-modules)")
    c.add_argument("--exclude", default="", help="comma-separated modules to skip")
    c.add_argument("--case-id", default="", help="case identifier (default: generated)")
    c.add_argument("--examiner", default=None, help="examiner name (recorded in chain of custody)")
    c.add_argument("--notes", default="", help="case notes / authorisation reference")
    c.add_argument("-o", "--output", default=None, help="output root (default: <kit>/WezCrypt_Cases)")
    c.add_argument("-f", "--formats", default="html,json,csv,pdf", help="report formats (html,json,csv,pdf) or 'none'")
    c.add_argument("-w", "--workers", type=int, default=None, help="parallel modules (1-16)")
    c.add_argument("--ioc-file", default=None, help="IOC list (hashes/IPs/domains, one per line)")
    c.add_argument("--vss", action="store_true", help="allow esentutl /vss for locked browser databases (Administrator)")
    c.add_argument("--yes", action="store_true", help="confirm authorisation non-interactively")

    v = sub.add_parser("verify", help="verify evidence integrity of a session folder")
    v.add_argument("session_dir")
    v.add_argument("--json", action="store_true")

    a = sub.add_parser("analyze", help="re-run analysis on a session folder")
    a.add_argument("session_dir")
    a.add_argument("--ioc-file", default=None)

    r = sub.add_parser("report", help="(re)generate reports for a session folder")
    r.add_argument("session_dir")
    r.add_argument("-f", "--formats", default="html,json,csv,pdf")

    s = sub.add_parser("sessions", help="list sessions in the output folder")
    s.add_argument("-o", "--output", default=None)
    return p


def _load_config(args) -> Config:
    return Config.load(args.config) if args.config else Config.load()


def cmd_list_modules(args) -> int:
    from .collectors.base import all_collectors

    infos = [c.info() for c in sorted(all_collectors(), key=lambda c: (c.category, c.name))]
    if args.json:
        _print(json.dumps(infos, indent=2))
        return EXIT_OK
    _print(f"{'MODULE':<20} {'CATEGORY':<12} {'ADMIN':<8} TITLE")
    for i in infos:
        _print(f"{i['name']:<20} {i['category']:<12} {i['requires_admin']:<8} {i['title']}")
    return EXIT_OK


def _resolve_modules(spec: str, exclude: str) -> List[str]:
    from .collectors.base import all_collectors

    names = [c.name for c in all_collectors()]
    if spec.strip().lower() == "all":
        chosen = names
    else:
        chosen = [m.strip() for m in spec.split(",") if m.strip()]
        bad = [m for m in chosen if m not in names]
        if bad:
            raise SystemExit(f"unknown module(s): {', '.join(bad)}. Use list-modules.")
    skip = {m.strip() for m in exclude.split(",") if m.strip()}
    return [m for m in chosen if m not in skip]


def cmd_collect(args) -> int:
    from .core.orchestrator import Orchestrator

    cfg = _load_config(args)
    if args.workers:
        cfg.max_workers = max(1, min(16, args.workers))
    if args.ioc_file:
        cfg.ioc_file = args.ioc_file
    if args.vss:
        cfg.use_vss_for_locked = True
    modules = _resolve_modules(args.modules, args.exclude)
    if not modules:
        _print("No modules selected.")
        return EXIT_ERROR
    formats = [] if args.formats.strip().lower() == "none" else [f.strip() for f in args.formats.split(",") if f.strip()]
    if not args.yes:
        _print("This tool must only be used on systems you are authorised to examine.")
        try:
            answer = input("Confirm you have authorisation for this host [y/N]: ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            _print("Aborted: authorisation not confirmed.")
            return EXIT_ERROR
    if not is_admin():
        _print("NOTE: running without Administrator rights - modules marked 'yes'/'partial' will be limited.")

    def progress(module, frac, msg):
        if args.verbose:
            _print(f"  [{module}] {int(frac * 100):3d}% {msg}")

    def status(event, data):
        if event == "module_finished":
            r = data["result"]
            _print(f"  {r['title']:<32} {r['status']:<10} files={r['files_acquired']:<5} errors={r['errors']}")
        elif event == "phase":
            _print(f"-- {data['name']} --")
        elif event == "session_started":
            _print(f"Session {data['session_id']}\nOutput  {data['session_dir']}\n-- collection --")

    orch = Orchestrator(cfg, modules, case_id=args.case_id, examiner=args.examiner if args.examiner is not None else cfg.examiner,
                        notes=args.notes, output_root=args.output, progress_cb=progress, status_cb=status,
                        report_formats=formats)

    def on_sigint(signum, frame):
        _print("\nCancellation requested - finishing current file safely...")
        orch.cancel()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, on_sigint)
    session = orch.run()
    _print(f"Status: {session.status}")
    _print(f"Findings: {session.stats.get('analysis', {}).get('severity_counts', {})}")
    _print(f"Reports: {os.path.join(session.session_dir, 'reports')}")
    ver = session.stats.get("post_collection_verification", {})
    _print(f"Integrity verification: {'PASSED' if ver.get('passed') else 'FAILED'}")
    if session.status == "cancelled":
        return EXIT_CANCELLED
    return EXIT_OK if ver.get("passed") else EXIT_VERIFY_FAILED


def cmd_verify(args) -> int:
    from .core.integrity import verify_manifest

    res = verify_manifest(args.session_dir)
    CustodyLog(os.path.join(args.session_dir, "chain_of_custody.jsonl")).append(
        "integrity_verification", {"passed": res.passed, "modified": len(res.modified), "missing": len(res.missing)})
    if args.json:
        _print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print(f"Manifest: {res.manifest_message}")
        _print(f"Verified OK: {len(res.ok)}  Modified: {len(res.modified)}  Missing: {len(res.missing)}  "
               f"Unlisted: {len(res.unexpected)}")
        for m in res.modified:
            _print(f"  MODIFIED {m['path']}")
        for m in res.missing:
            _print(f"  MISSING  {m}")
        for p in res.custody_problems:
            _print(f"  CUSTODY  {p}")
        _print("RESULT: " + ("PASSED" if res.passed else "FAILED"))
    return EXIT_OK if res.passed else EXIT_VERIFY_FAILED


def cmd_analyze(args) -> int:
    from .analysis.engine import run_analysis

    cfg = _load_config(args)
    if args.ioc_file:
        cfg.ioc_file = args.ioc_file
    summary = run_analysis(args.session_dir, cfg)
    CustodyLog(os.path.join(args.session_dir, "chain_of_custody.jsonl")).append("analysis_rerun", summary, examiner=cfg.examiner)
    _print(json.dumps(summary, indent=2))
    return EXIT_OK


def cmd_report(args) -> int:
    from .reporting.generator import generate_reports

    cfg = _load_config(args)
    if not os.path.isfile(os.path.join(args.session_dir, "analysis", "summary.json")):
        from .analysis.engine import run_analysis

        run_analysis(args.session_dir, cfg)
    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    out = generate_reports(args.session_dir, formats, cfg)
    CustodyLog(os.path.join(args.session_dir, "chain_of_custody.jsonl")).append("reports_generated", {"files": out}, examiner=cfg.examiner)
    for o in out:
        _print(f"{o['sha256']}  {o['path']}")
    return EXIT_OK


def cmd_sessions(args) -> int:
    from .core.session import list_sessions

    cfg = _load_config(args)
    root = args.output or cfg.output_dir or default_output_root()
    rows = list_sessions(root)
    if not rows:
        _print(f"No sessions in {root}")
    for r in rows:
        _print(f"{r.get('started_utc')}  {r.get('status'):<10} {r.get('case_id'):<24} {r.get('session_dir')}")
    return EXIT_OK


def cmd_info(args) -> int:
    cfg = _load_config(args)
    loc = detect_run_location()
    _print(f"{__app_name__} {__version__}")
    _print(f"Administrator: {is_admin()}")
    _print(f"Kit folder:    {loc.app_dir} (drive type: {loc.drive_type})")
    _print(f"Output root:   {cfg.output_dir or default_output_root()}")
    _print(f"Config file:   {Config.path()}")
    for w in loc.warnings():
        _print("WARNING: " + w)
    return EXIT_OK


def cmd_about(args) -> int:
    for k, v in ABOUT.items():
        _print(f"{k + ':':<13}{v}")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        setup_app_logging(os.path.join(application_dir(), LOGS_DIR_NAME), args.verbose, args.debug,
                          console=args.command not in (None, "gui"))
    except OSError as exc:
        _print(f"WARNING: cannot write application log: {exc}")
    command = args.command or "gui"
    if command == "gui":
        from .gui.app import run_gui

        return run_gui(_load_config(args))
    handlers = {"about": cmd_about, "info": cmd_info, "list-modules": cmd_list_modules, "collect": cmd_collect,
                "verify": cmd_verify, "analyze": cmd_analyze, "report": cmd_report, "sessions": cmd_sessions}
    try:
        return handlers[command](args)
    except KeyboardInterrupt:
        return EXIT_CANCELLED
    except SystemExit:
        raise
    except Exception as exc:
        _print(f"ERROR: {exc}")
        if args.debug:
            raise
        return EXIT_ERROR
