"""Collects everything a report needs from a session folder."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .. import ABOUT
from ..analysis.timeline import iter_timeline
from ..core.custody import CustodyLog
from ..core.winapi import long_path


def _load(path: str, default: Any) -> Any:
    if not os.path.isfile(long_path(path)):
        return default
    with open(long_path(path), "r", encoding="utf-8") as fh:
        return json.load(fh)


def gather(session_dir: str, timeline_limit: int = 25000) -> Dict[str, Any]:
    p = lambda *parts: os.path.join(session_dir, *parts)  # noqa: E731
    session = _load(p("session.json"), {})
    manifest = _load(p("manifest.json"), {"files": []})
    summary = _load(p("analysis", "summary.json"), {})
    timeline_total = (summary.get("timeline") or {}).get("events", 0)
    timeline = iter_timeline(session_dir, limit=timeline_limit) if timeline_limit else []
    acquired = _load(p("logs", "acquired_files.json"), [])
    by_path = {a["evidence_path"]: a for a in acquired}
    hashes: List[Dict] = []
    for f in manifest.get("files", []):
        src = by_path.get(f["path"], {})
        hashes.append({"evidence_path": f["path"], "size": f["size"], "sha256": f["sha256"],
                       "source_path": src.get("source_path"), "method": src.get("method"),
                       "acquired_utc": src.get("acquired_utc"), "source_modified": src.get("source_modified")})
    return {
        "about": ABOUT,
        "session": session,
        "modules": list((session.get("module_results") or {}).values()),
        "summary": summary,
        "findings": _load(p("analysis", "findings.json"), []),
        "observables": _load(p("analysis", "observables.json"), []),
        "timeline": timeline,
        "timeline_total": timeline_total,
        "timeline_truncated": timeline_total > len(timeline),
        "hashes": hashes,
        "manifest_sha256": session.get("manifest_sha256"),
        "errors": _load(p("logs", "errors.json"), []),
        "live_actions": _load(p("logs", "live_actions.json"), []),
        "custody": CustodyLog(p("chain_of_custody.jsonl")).entries(),
    }
