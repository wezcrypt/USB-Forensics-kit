"""Portable path discovery: where the kit runs from and where evidence is written."""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from typing import Optional

from . import winapi

CASES_DIR_NAME = "WezCrypt_Cases"
LOGS_DIR_NAME = "WezCrypt_Logs"
CONFIG_FILE_NAME = "wezcrypt_config.json"


def application_dir() -> str:
    """Directory holding the executable (frozen build) or the project root (source run)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def bundled_resource(*parts: str) -> str:
    """Path to a resource bundled by PyInstaller (sys._MEIPASS) or in the source tree."""
    base = getattr(sys, "_MEIPASS", None)
    if base is None:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


@dataclass
class RunLocation:
    app_dir: str
    drive: str
    drive_type: str
    is_removable: bool
    system_drive: str
    same_as_system_drive: bool

    def warnings(self):
        out = []
        if not self.is_removable:
            out.append(
                f"The kit is running from a '{self.drive_type}' volume ({self.drive or self.app_dir}), not a "
                "removable USB drive. Some USB enclosures report as 'fixed'; verify the output location."
            )
        if self.same_as_system_drive:
            out.append(
                "Output is on the system drive of the examined host. Writing evidence there can overwrite "
                "unallocated space; prefer an external drive."
            )
        return out

    def to_dict(self):
        return {
            "app_dir": self.app_dir,
            "drive": self.drive,
            "drive_type": self.drive_type,
            "is_removable": self.is_removable,
            "system_drive": self.system_drive,
            "same_as_system_drive": self.same_as_system_drive,
        }


def detect_run_location(app_dir: Optional[str] = None) -> RunLocation:
    app_dir = os.path.abspath(app_dir or application_dir())
    drive = os.path.splitdrive(app_dir)[0]
    dtype = winapi.drive_type(app_dir)
    system_drive = os.environ.get("SystemDrive", "C:" if winapi.IS_WINDOWS else "")
    same = bool(drive) and bool(system_drive) and drive.upper() == system_drive.upper()
    return RunLocation(app_dir, drive, dtype, dtype == "removable", system_drive, same)


def default_output_root(app_dir: Optional[str] = None) -> str:
    return os.path.join(os.path.abspath(app_dir or application_dir()), CASES_DIR_NAME)


_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def safe_name(value: str, max_len: int = 80) -> str:
    """Make a string safe as a single Windows path component while keeping Unicode (Arabic) letters."""
    cleaned = _UNSAFE.sub("_", value or "").strip(" .")
    if cleaned.upper() in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(?i)(COM|LPT)\d", cleaned or ""):
        cleaned = "_" + cleaned
    return (cleaned or "_")[:max_len]


def unique_path(path: str) -> str:
    """Return path, or path with a numeric suffix if it already exists (evidence is never overwritten)."""
    if not os.path.exists(winapi.long_path(path)):
        return path
    root, ext = os.path.splitext(path)
    n = 1
    while os.path.exists(winapi.long_path(f"{root}_{n}{ext}")):
        n += 1
    return f"{root}_{n}{ext}"
