"""Runs a collection session end to end: collectors -> integrity -> analysis -> reports."""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from .. import __version__
from .config import Config
from .context import CollectionCancelled, CollectionContext, SharedState
from .custody import CustodyLog
from .integrity import build_manifest, verify_manifest
from .logging_setup import attach_session_log, detach_handler, get_logger
from .models import ModuleResult
from .paths import default_output_root, detect_run_location
from .session import Session
from .timeutil import utc_now_iso
from .winapi import IS_WINDOWS, is_admin, long_path

log = get_logger("orchestrator")

ProgressCB = Callable[[str, float, str], None]
StatusCB = Callable[[str, Dict], None]


class Orchestrator:
    def __init__(self, config: Config, modules: List[str], case_id: str = "", examiner: str = "",
                 notes: str = "", output_root: Optional[str] = None,
                 progress_cb: Optional[ProgressCB] = None, status_cb: Optional[StatusCB] = None,
                 report_formats: Optional[List[str]] = None):
        from ..collectors.base import get_collector

        self.config = config
        self.collectors = [get_collector(m)() for m in modules]
        self.case_id = case_id
        self.examiner = examiner or config.examiner
        self.notes = notes
        self.output_root = output_root or config.output_dir or default_output_root()
        self.progress_cb = progress_cb
        self.status_cb = status_cb
        self.cancel_event = threading.Event()
        self.shared = SharedState()
        self.session: Optional[Session] = None
        self.results: Dict[str, ModuleResult] = {}
        self.report_formats = report_formats if report_formats is not None else ["html", "json", "csv", "pdf"]

    def cancel(self) -> None:
        self.cancel_event.set()

    def _status(self, event: str, **data) -> None:
        if self.status_cb:
            try:
                self.status_cb(event, data)
            except Exception:  # GUI callbacks must never break collection
                log.exception("status callback failed")

    def _progress(self, module: str, fraction: float, message: str) -> None:
        if self.progress_cb:
            try:
                self.progress_cb(module, fraction, message)
            except Exception:
                log.exception("progress callback failed")

    def run(self) -> Session:
        os.makedirs(long_path(self.output_root), exist_ok=True)
        session = Session.create(self.output_root, self.case_id, self.examiner, self.config.organization,
                                 self.notes, self.config.case_prefix)
        self.session = session
        handler = attach_session_log(session.path("logs", "collection.log"))
        custody = CustodyLog(session.path("chain_of_custody.jsonl"))
        try:
            location = detect_run_location()
            session.run_location = location.to_dict()
            session.modules_requested = [c.name for c in self.collectors]
            session.config_snapshot = self.config.to_dict()
            session.status = "collecting"
            session.save()
            custody.append("session_created", {
                "session_id": session.session_id, "case_id": session.case_id, "tool_version": __version__,
                "host": session.hostname, "examiner_os_account": session.os_user, "is_admin": session.is_admin,
                "modules": session.modules_requested, "notes": self.notes,
            }, examiner=self.examiner)
            for w in location.warnings():
                log.warning(w)
            log.info("session %s started in %s (admin=%s)", session.session_id, session.session_dir, is_admin())
            self._status("session_started", session_dir=session.session_dir, session_id=session.session_id)
            self._run_collectors(session)
            from ..collectors.common import RegistryProvider

            RegistryProvider.release(session.session_id)
            self._finalize_collection(session, custody)
            if not self.cancel_event.is_set():
                self._status("phase", name="analysis")
                from ..analysis.engine import run_analysis

                summary = run_analysis(session.session_dir, self.config)
                session.stats["analysis"] = summary
                custody.append("analysis_completed", summary, examiner=self.examiner)
                if self.report_formats:
                    self._status("phase", name="reports")
                    from ..reporting.generator import generate_reports

                    outputs = generate_reports(session.session_dir, self.report_formats, self.config)
                    custody.append("reports_generated", {"files": outputs}, examiner=self.examiner)
            session.status = "cancelled" if self.cancel_event.is_set() else "completed"
        except Exception as exc:
            log.exception("session failed")
            session.status = "failed"
            session.stats["fatal_error"] = str(exc)
            custody.append("session_failed", {"error": str(exc)}, examiner=self.examiner)
            raise
        finally:
            session.finished_utc = utc_now_iso()
            session.save()
            shutil.rmtree(session.path("analysis", "tmp"), ignore_errors=True)
            custody.append("session_closed", {"status": session.status}, examiner=self.examiner)
            self._status("session_finished", status=session.status, session_dir=session.session_dir)
            detach_handler(handler)
        return session

    def _run_collectors(self, session: Session) -> None:
        for c in self.collectors:
            self.results[c.name] = ModuleResult(c.name, c.title)
        runnable = []
        for c in self.collectors:
            res = self.results[c.name]
            if c.windows_only and not IS_WINDOWS:
                res.status = "skipped"
                res.message = "Windows-only module"
                self._status("module_finished", module=c.name, result=res.to_dict())
                continue
            runnable.append(c)
        workers = max(1, min(self.config.max_workers, len(runnable) or 1))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="collector") as pool:
            futures = {pool.submit(self._run_one, session, c): c for c in runnable}
            for fut in as_completed(futures):
                c = futures[fut]
                fut.result()  # _run_one never raises
                self._status("module_finished", module=c.name, result=self.results[c.name].to_dict())

    def _run_one(self, session: Session, collector) -> None:
        res = self.results[collector.name]
        if self.cancel_event.is_set():
            res.status = "cancelled"
            return
        ctx = CollectionContext(session, self.config, collector.name, self.shared, self.cancel_event, self._progress)
        res.status = "running"
        res.started_utc = utc_now_iso()
        self._status("module_started", module=collector.name)
        self._progress(collector.name, 0.0, "starting")
        t0 = time.monotonic()
        try:
            collector.run(ctx)
            res.status = "partial" if ctx.error_count else "completed"
        except CollectionCancelled:
            res.status = "cancelled"
            res.message = "cancelled by examiner"
        except Exception as exc:  # isolate module failures
            log.exception("module %s failed", collector.name)
            ctx.error(f"module failed: {exc.__class__.__name__}: {exc}", "error")
            res.status = "failed"
            res.message = str(exc)
        finally:
            ctx.close()
            res.finished_utc = utc_now_iso()
            res.duration_seconds = round(time.monotonic() - t0, 2)
            res.record_counts = dict(ctx.record_counts)
            res.files_acquired = ctx.files_acquired
            res.errors = ctx.error_count
            self._progress(collector.name, 1.0, res.status)

    def _finalize_collection(self, session: Session, custody: CustodyLog) -> None:
        self._status("phase", name="integrity")
        with open(long_path(session.path("logs", "errors.json")), "w", encoding="utf-8") as fh:
            json.dump([e.to_dict() for e in self.shared.errors], fh, indent=1, ensure_ascii=False)
        with open(long_path(session.path("logs", "live_actions.json")), "w", encoding="utf-8") as fh:
            json.dump([a.to_dict() for a in self.shared.live_actions], fh, indent=1, ensure_ascii=False)
        with open(long_path(session.path("logs", "acquired_files.json")), "w", encoding="utf-8") as fh:
            json.dump([a.to_dict() for a in self.shared.acquired], fh, indent=1, ensure_ascii=False)
        session.module_results = {k: v.to_dict() for k, v in self.results.items()}
        known = {a.evidence_path: a.to_dict() for a in self.shared.acquired}
        manifest = build_manifest(session.session_dir, session.session_id, __version__, known)
        session.manifest_sha256 = manifest["_manifest_sha256"]
        session.stats.update({
            "files_acquired": len(self.shared.acquired),
            "bytes_acquired": sum(a.size for a in self.shared.acquired),
            "manifest_files": manifest["file_count"],
            "errors": len(self.shared.errors),
            "live_actions": len(self.shared.live_actions),
        })
        session.status = "verifying"
        session.save()
        custody.append("evidence_manifest_created", {
            "manifest_sha256": manifest["_manifest_sha256"], "file_count": manifest["file_count"],
            "total_bytes": manifest["total_bytes"],
        }, examiner=self.examiner)
        result = verify_manifest(session.session_dir)
        session.stats["post_collection_verification"] = {
            "passed": result.passed, "modified": len(result.modified), "missing": len(result.missing),
        }
        custody.append("post_collection_verification", result.to_dict() | {"ok_count": len(result.ok)},
                       examiner=self.examiner)
        session.save()
