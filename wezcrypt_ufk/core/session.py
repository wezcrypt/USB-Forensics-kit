"""Investigation session: unique ID, folder layout and session metadata."""

from __future__ import annotations

import getpass
import json
import os
import platform
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .. import __app_name__, __version__
from .paths import safe_name
from .timeutil import utc_now, utc_now_iso
from .winapi import is_admin, long_path

SESSION_FILE = "session.json"
SUBDIRS = ("evidence", "parsed", "analysis", "reports", "logs")


@dataclass
class Session:
    session_id: str
    case_id: str
    session_dir: str
    examiner: str = ""
    organization: str = ""
    notes: str = ""
    tool_name: str = __app_name__
    tool_version: str = __version__
    started_utc: str = ""
    finished_utc: Optional[str] = None
    status: str = "created"
    hostname: str = ""
    os_user: str = ""
    is_admin: bool = False
    platform: str = ""
    python_version: str = ""
    run_location: Dict[str, Any] = field(default_factory=dict)
    modules_requested: List[str] = field(default_factory=list)
    module_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    manifest_sha256: Optional[str] = None
    stats: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, output_root: str, case_id: str = "", examiner: str = "", organization: str = "",
               notes: str = "", case_prefix: str = "CASE") -> "Session":
        now = utc_now()
        session_id = str(uuid.uuid4())
        host = socket.gethostname()
        if not case_id:
            case_id = f"{case_prefix}-{now.strftime('%Y%m%d-%H%M%S')}"
        folder = f"{safe_name(case_id, 60)}_{safe_name(host, 40)}_{now.strftime('%Y%m%dT%H%M%SZ')}_{session_id[:8]}"
        session_dir = os.path.join(os.path.abspath(output_root), folder)
        for sub in SUBDIRS:
            os.makedirs(long_path(os.path.join(session_dir, sub)), exist_ok=True)
        try:
            user = getpass.getuser()
        except Exception:
            user = "unknown"
        session = cls(
            session_id=session_id, case_id=case_id, session_dir=session_dir, examiner=examiner,
            organization=organization, notes=notes, started_utc=utc_now_iso(), hostname=host, os_user=user,
            is_admin=is_admin(), platform=platform.platform(), python_version=platform.python_version(),
        )
        session.save()
        return session

    def path(self, *parts: str) -> str:
        return os.path.join(self.session_dir, *parts)

    def save(self) -> None:
        data = self.to_dict()
        tmp = self.path(SESSION_FILE + ".tmp")
        with open(long_path(tmp), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(long_path(tmp), long_path(self.path(SESSION_FILE)))

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    @classmethod
    def load(cls, session_dir: str) -> "Session":
        with open(long_path(os.path.join(session_dir, SESSION_FILE)), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        known["session_dir"] = os.path.abspath(session_dir)
        return cls(**known)


def list_sessions(output_root: str) -> List[Dict[str, Any]]:
    """Summaries of all sessions under an output root, newest first."""
    out = []
    if not os.path.isdir(output_root):
        return out
    for name in os.listdir(output_root):
        path = os.path.join(output_root, name)
        meta = os.path.join(path, SESSION_FILE)
        if os.path.isfile(meta):
            try:
                with open(meta, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                data["session_dir"] = path
                out.append(data)
            except (OSError, ValueError):
                continue
    out.sort(key=lambda d: d.get("started_utc") or "", reverse=True)
    return out
