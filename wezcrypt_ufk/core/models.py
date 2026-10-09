"""Shared data structures."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ErrorRecord:
    module: str
    message: str
    kind: str = "error"  # error | access_denied | locked | not_found | requires_admin | skipped
    path: Optional[str] = None
    utc: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LiveAction:
    """An operation performed on the live system that may alter its state (documented for the examiner)."""

    module: str
    action: str
    impact: str
    utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AcquiredFile:
    module: str
    source_path: str
    evidence_path: str  # relative to the session directory, forward slashes
    size: int
    sha256: str
    method: str
    acquired_utc: str
    source_created: Optional[str] = None
    source_modified: Optional[str] = None
    source_accessed: Optional[str] = None
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    timestamp: str
    source: str
    event_type: str
    description: str
    module: str = ""
    artifact: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    mitre: List[str] = field(default_factory=list)
    recommendation: str = ""
    confidence: str = "medium"  # low | medium | high

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    name: str
    title: str
    status: str = "pending"  # pending | running | completed | partial | failed | skipped | cancelled
    started_utc: Optional[str] = None
    finished_utc: Optional[str] = None
    duration_seconds: float = 0.0
    record_counts: Dict[str, int] = field(default_factory=dict)
    files_acquired: int = 0
    errors: int = 0
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
