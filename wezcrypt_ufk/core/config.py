"""Kit configuration stored next to the executable (portable)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Optional

from .paths import CONFIG_FILE_NAME, application_dir


@dataclass
class Config:
    output_dir: str = ""  # empty = <kit folder>/WezCrypt_Cases
    examiner: str = ""
    organization: str = ""
    case_prefix: str = "CASE"
    max_workers: int = 4
    eventlog_max_events: int = 20000  # per channel, newest first
    script_block_max_chars: int = 4000
    browser_max_rows: int = 100000  # per table per profile
    collect_browser_cache_index: bool = True
    fs_scan_paths: List[str] = field(default_factory=lambda: [
        "%USERPROFILE%\\Downloads",
        "%USERPROFILE%\\Desktop",
        "%TEMP%",
        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        "%PUBLIC%",
    ])
    fs_max_depth: int = 4
    fs_max_files: int = 20000
    fs_hash_max_mb: int = 512
    fs_copy_suspicious: bool = False
    fs_copy_max_mb: int = 50
    hash_process_executables: bool = True
    verify_signatures: bool = True
    use_vss_for_locked: bool = False
    acquire_registry_hives: bool = True
    html_timeline_limit: int = 25000
    ioc_file: str = ""
    failed_logon_threshold: int = 10
    failed_logon_window_minutes: int = 10

    @classmethod
    def path(cls, app_dir: Optional[str] = None) -> str:
        return os.path.join(app_dir or application_dir(), CONFIG_FILE_NAME)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        path = path or cls.path()
        cfg = cls()
        if not os.path.isfile(path):
            return cfg
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return cfg
        if isinstance(data, dict):
            cfg.update(data)
        return cfg

    def update(self, data: Dict[str, Any]) -> List[str]:
        """Apply values with type validation. Returns a list of rejected keys."""
        rejected = []
        defaults = Config()
        for f in fields(self):
            if f.name not in data:
                continue
            value = data[f.name]
            expected = type(getattr(defaults, f.name))
            if expected is int and isinstance(value, bool):
                rejected.append(f.name)
                continue
            if expected is int and isinstance(value, str) and value.strip().lstrip("-").isdigit():
                value = int(value)
            if expected is list and isinstance(value, str):
                value = [line.strip() for line in value.splitlines() if line.strip()]
            if not isinstance(value, expected):
                rejected.append(f.name)
                continue
            if expected is int and value < 0:
                rejected.append(f.name)
                continue
            setattr(self, f.name, value)
        self.max_workers = max(1, min(self.max_workers, 16))
        return rejected

    def save(self, path: Optional[str] = None) -> str:
        path = path or self.path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return path

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))
