"""Report generation entry point (HTML, per-browser HTML, JSON, CSV, PDF) with report hashing."""

from __future__ import annotations

import csv
import json
import os
from typing import Dict, Iterable, List, Optional

from ..analysis.data import SessionData
from ..core.config import Config
from ..core.hashing import sha256_file
from ..core.logging_setup import get_logger
from ..core.timeutil import utc_now_iso
from ..core.winapi import long_path
from .data import gather
from .html_report import BROWSER_TABLES, build_browser_report, build_main_report

log = get_logger("report")
FORMATS = ("html", "json", "csv", "pdf")


def _csv_value(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)
    return v


def write_csv(path: str, rows: Iterable[Dict], columns: Optional[List[str]] = None) -> int:
    rows = list(rows) if columns is None else rows
    if columns is None:
        columns = []
        for r in rows:
            for k in r.keys():
                if k not in columns:
                    columns.append(k)
    n = 0
    # utf-8-sig so Excel opens Arabic/Unicode text correctly
    with open(long_path(path), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(columns)
        for r in rows:
            w.writerow([_csv_value(r.get(c)) for c in columns])
            n += 1
    return n


def _jsonl_columns(path: str) -> List[str]:
    cols: List[str] = []
    with open(long_path(path), "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                for k in json.loads(line).keys():
                    if k not in cols:
                        cols.append(k)
    return cols


def _jsonl_rows(path: str):
    with open(long_path(path), "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def generate_reports(session_dir: str, formats: Optional[List[str]] = None, config: Optional[Config] = None) -> List[Dict]:
    """Generate the requested formats; returns [{path, sha256, size}] (paths relative to the session)."""
    config = config or Config()
    formats = [f.lower() for f in (formats or FORMATS)]
    unknown = set(formats) - set(FORMATS)
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(sorted(unknown))}")
    out_dir = os.path.join(session_dir, "reports")
    os.makedirs(long_path(out_dir), exist_ok=True)
    d = gather(session_dir, config.html_timeline_limit)
    written: List[str] = []

    if "html" in formats:
        path = os.path.join(out_dir, "report.html")
        with open(long_path(path), "w", encoding="utf-8") as fh:
            fh.write(build_main_report(d))
        written.append(path)
        data = SessionData(session_dir)
        bdir = os.path.join(out_dir, "browsers")
        for module in data.modules():
            if not module.startswith("browser_"):
                continue
            artifacts = {key: data.all(module, key) for key, _, _, _ in BROWSER_TABLES}
            if not any(artifacts.values()):
                continue
            title = next((r.get("browser") for rows in artifacts.values() for r in rows if r.get("browser")), module)
            os.makedirs(long_path(bdir), exist_ok=True)
            bpath = os.path.join(bdir, f"{module}.html")
            with open(long_path(bpath), "w", encoding="utf-8") as fh:
                fh.write(build_browser_report(title, artifacts, d["session"], d["about"]))
            written.append(bpath)

    if "json" in formats:
        path = os.path.join(out_dir, "report.json")
        payload = {k: v for k, v in d.items()}
        payload["generated_utc"] = utc_now_iso()
        payload["timeline_note"] = ("timeline holds the most recent events up to the configured limit; the complete "
                                    "timeline is analysis/timeline.jsonl") if d["timeline_truncated"] else "complete"
        with open(long_path(path), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, ensure_ascii=False, default=str)
        written.append(path)

    if "csv" in formats:
        cdir = os.path.join(out_dir, "csv")
        os.makedirs(long_path(cdir), exist_ok=True)
        findings = [{**f, "evidence_count": len(f.get("evidence") or [])} for f in d["findings"]]
        written.append(_w(cdir, "findings.csv", findings, ["severity", "rule_id", "title", "category", "description", "first_seen",
                                                          "last_seen", "confidence", "mitre", "evidence_count", "evidence", "recommendation"]))
        tl_path = os.path.join(session_dir, "analysis", "timeline.jsonl")
        if os.path.isfile(long_path(tl_path)):
            p = os.path.join(cdir, "timeline.csv")
            write_csv(p, _jsonl_rows(tl_path), ["timestamp", "source", "event_type", "description", "module", "artifact", "details"])
            written.append(p)
        written.append(_w(cdir, "evidence_hashes.csv", d["hashes"], ["evidence_path", "sha256", "size", "source_path", "method",
                                                                     "acquired_utc", "source_modified"]))
        written.append(_w(cdir, "errors.csv", d["errors"], ["utc", "module", "kind", "message", "path", "detail"]))
        written.append(_w(cdir, "modules.csv", d["modules"], None))
        written.append(_w(cdir, "observables.csv", d["observables"], ["type", "value", "sources"]))
        written.append(_w(cdir, "live_actions.csv", d["live_actions"], ["utc", "module", "action", "impact"]))
        data = SessionData(session_dir)
        adir = os.path.join(cdir, "artifacts")
        os.makedirs(long_path(adir), exist_ok=True)
        for module in data.modules():
            for artifact in data.artifacts(module):
                src = os.path.join(session_dir, "parsed", module, artifact + ".jsonl")
                cols = _jsonl_columns(src)
                if not cols:
                    continue
                p = os.path.join(adir, f"{module}__{artifact}.csv")
                write_csv(p, _jsonl_rows(src), cols)
                written.append(p)

    if "pdf" in formats:
        from .pdf_report import build_pdf, pdf_available

        problem = pdf_available()
        if problem:
            log.error("PDF report skipped: %s", problem)
        else:
            path = os.path.join(out_dir, "report.pdf")
            build_pdf(d, path)
            written.append(path)

    results = []
    for path in written:
        rel = os.path.relpath(path, session_dir).replace("\\", "/")
        results.append({"path": rel, "sha256": sha256_file(path), "size": os.path.getsize(long_path(path))})
    with open(long_path(os.path.join(out_dir, "report_hashes.json")), "w", encoding="utf-8") as fh:
        json.dump({"generated_utc": utc_now_iso(), "files": results}, fh, indent=1, ensure_ascii=False)
    return results


def _w(folder: str, name: str, rows: List[Dict], columns: Optional[List[str]]) -> str:
    path = os.path.join(folder, name)
    write_csv(path, rows, columns)
    return path
