"""Recycle Bin $I metadata parser (Windows Vista+; version 1 and 2 formats)."""

from __future__ import annotations

import struct
from typing import Dict

from ..core.timeutil import filetime_to_iso


class RecycleBinError(Exception):
    pass


def parse_recycle_i(data: bytes) -> Dict:
    if len(data) < 24:
        raise RecycleBinError("$I file too small")
    version, size, deleted = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        path = data[24:24 + 520].decode("utf-16-le", "replace").split("\x00", 1)[0]
    elif version == 2:
        if len(data) < 28:
            raise RecycleBinError("truncated v2 $I file")
        length = struct.unpack_from("<I", data, 24)[0]
        path = data[28:28 + length * 2].decode("utf-16-le", "replace").split("\x00", 1)[0]
    else:
        raise RecycleBinError(f"unknown $I version {version}")
    return {"format_version": version, "original_size": size, "deleted_utc": filetime_to_iso(deleted),
            "original_path": path}
