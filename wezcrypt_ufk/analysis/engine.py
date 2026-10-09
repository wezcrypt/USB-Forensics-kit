"""Analysis engine: timeline merge, rules, observables extraction, executive summary and recommendations."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Dict, List, Optional

from ..core.config import Config
from ..core.logging_setup import get_logger
from ..core.models import SEVERITY_ORDER, Finding
from ..core.timeutil import utc_now_iso
from ..core.winapi import long_path
from .data import SessionData
from .rules import RULES, RuleContext, is_public_ip, load_ioc_file
from .timeline import build_timeline

log = get_logger("analysis")

URL_RE = re.compile(r"https?://[^\s'\"<>|]{4,300}", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def extract_observables(findings: List[Finding], data: SessionData) -> List[Dict]:
    """Observables (URLs, public IPs, hashes) referenced by findings and live remote connections.

    These are leads for enrichment, not verdicts: inclusion does not mean an observable is malicious."""
    seen: Dict[tuple, Dict] = {}

    def add(kind: str, value: str, source: str) -> None:
        key = (kind, value.lower())
        item = seen.setdefault(key, {"type": kind, "value": value, "sources": []})
        if source not in item["sources"] and len(item["sources"]) < 10:
            item["sources"].append(source)

    for f in findings:
        if f.severity == "info":
            continue
        for ev in f.evidence:
            blob = json.dumps(ev, ensure_ascii=False)
            for url in URL_RE.findall(blob):
                add("url", url.rstrip("\\\",)"), f.rule_id)
            for ip in IPV4_RE.findall(blob):
                if is_public_ip(ip):
                    add("ipv4", ip, f.rule_id)
            for key in ("sha256", "sha1"):
                if ev.get(key):
                    add(key, ev[key], f.rule_id)
    for c in data.records("network", "connections"):
        if is_public_ip(c.get("remote_address")) and c.get("state") in ("ESTABLISHED", None):
            add("ip", c["remote_address"], f"connection:{c.get('process')}")
    return sorted(seen.values(), key=lambda x: (x["type"], x["value"]))


RECOMMENDATIONS_BASE = [
    "Preserve this session folder unmodified; work on copies and re-verify the manifest before analysis.",
]


def build_recommendations(findings: List[Finding], errors: List[Dict], session: Dict) -> List[str]:
    recs = list(RECOMMENDATIONS_BASE)
    for f in sorted(findings, key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
        if f.recommendation and f.severity != "info":
            line = f"[{f.severity.upper()}] {f.title}: {f.recommendation}"
            if line not in recs:
                recs.append(line)
    admin_errors = [e for e in errors if e.get("kind") == "requires_admin"]
    if admin_errors and not session.get("is_admin"):
        mods = sorted({e.get("module") for e in admin_errors})
        recs.append("Collection ran without Administrator rights; re-run elevated to acquire: " + ", ".join(mods) + ".")
    locked = [e for e in errors if e.get("kind") == "locked"]
    if locked:
        recs.append(f"{len(locked)} file(s) were locked. Close the owning applications or enable 'Use VSS for locked "
                    "files' (Administrator) and re-run the affected modules.")
    if any(e.get("module") == "event_logs" and "limit" in (e.get("message") or "") for e in errors):
        recs.append("Event log parsing hit the configured event limit; the full EVTX exports are preserved in evidence "
                    "and can be analysed with dedicated tooling.")
    if not any(f.severity in ("medium", "high", "critical") for f in findings):
        recs.append("No medium or higher severity findings were produced by the rule set. This does not prove the host "
                    "is clean; review the timeline around the incident window.")
    return recs


def executive_summary(findings: List[Finding], session: Dict, timeline: Dict, counts: Dict[str, int], errors: int) -> str:
    sev = Counter(f.severity for f in findings)
    top = [f for f in sorted(findings, key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)) if f.severity in ("critical", "high")][:5]
    parts = [
        f"Host {session.get('hostname')} was examined on {session.get('started_utc')} (session {session.get('session_id')}) "
        f"by {session.get('examiner') or 'an unnamed examiner'} using {session.get('tool_name')} {session.get('tool_version')}"
        f"{' with' if session.get('is_admin') else ' without'} Administrator rights.",
        f"{sum(counts.values())} artifact records and {timeline.get('events', 0)} timeline events were produced"
        + (f", spanning {timeline.get('first')} to {timeline.get('last')}." if timeline.get("first") else "."),
        "Findings: " + ", ".join(f"{sev.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info")) + ".",
    ]
    if top:
        parts.append("Most significant: " + "; ".join(f"{f.title} ({f.severity})" for f in top) + ".")
    else:
        parts.append("No high or critical severity findings were produced by the rule set.")
    if errors:
        parts.append(f"{errors} collection error(s)/limitation(s) were recorded and are listed in the report.")
    return " ".join(parts)


def run_analysis(session_dir: str, config: Optional[Config] = None) -> Dict:
    config = config or Config()
    data = SessionData(session_dir)
    out_dir = os.path.join(session_dir, "analysis")
    os.makedirs(long_path(out_dir), exist_ok=True)
    timeline = build_timeline(session_dir)
    iocs = load_ioc_file(config.ioc_file) if config.ioc_file else {}
    rc = RuleContext(data, config, iocs)
    findings: List[Finding] = []
    rule_errors = []
    for rule in RULES:
        try:
            findings.extend(rule(rc))
        except Exception as exc:  # one broken rule must not stop analysis
            log.exception("rule %s failed", rule.__name__)
            rule_errors.append({"rule": rule.__name__, "error": str(exc)})
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.first_seen or ""))
    observables = extract_observables(findings, data)
    session = {}
    spath = os.path.join(session_dir, "session.json")
    if os.path.isfile(long_path(spath)):
        with open(long_path(spath), "r", encoding="utf-8") as fh:
            session = json.load(fh)
    errors = []
    epath = os.path.join(session_dir, "logs", "errors.json")
    if os.path.isfile(long_path(epath)):
        with open(long_path(epath), "r", encoding="utf-8") as fh:
            errors = json.load(fh)
    counts: Dict[str, int] = {}
    for m in data.modules():
        for a in data.artifacts(m):
            counts[f"{m}/{a}"] = data.count(m, a)
    summary = {
        "analyzed_utc": utc_now_iso(),
        "finding_count": len(findings),
        "severity_counts": dict(Counter(f.severity for f in findings)),
        "observable_count": len(observables),
        "timeline": timeline,
        "record_counts": counts,
        "rule_errors": rule_errors,
        "ioc_file_used": bool(iocs),
        "executive_summary": executive_summary(findings, session, timeline, counts, len(errors)),
        "recommendations": build_recommendations(findings, errors, session),
    }
    with open(long_path(os.path.join(out_dir, "findings.json")), "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=1, ensure_ascii=False)
    with open(long_path(os.path.join(out_dir, "observables.json")), "w", encoding="utf-8") as fh:
        json.dump(observables, fh, indent=1, ensure_ascii=False)
    with open(long_path(os.path.join(out_dir, "summary.json")), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False)
    return {"findings": len(findings), "severity_counts": summary["severity_counts"],
            "timeline_events": timeline["events"], "observables": len(observables)}
