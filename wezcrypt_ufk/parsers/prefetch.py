"""Windows Prefetch (.pf) parser - formats 17 (XP), 23 (Vista/7), 26 (8.x), 30/31 (10/11, MAM-compressed)."""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ..core.timeutil import filetime_to_iso
from ..core.winapi import decompress_xpress_huffman


class PrefetchError(Exception):
    pass


def decompress_if_needed(data: bytes, decompressor=None) -> bytes:
    if data[:3] == b"MAM":
        if len(data) < 8:
            raise PrefetchError("truncated MAM header")
        size = struct.unpack_from("<I", data, 4)[0]
        decompressor = decompressor or decompress_xpress_huffman
        try:
            return decompressor(data[8:], size)
        except OSError as exc:
            raise PrefetchError(f"cannot decompress MAM prefetch: {exc}") from exc
    return data


def parse_prefetch(data: bytes, max_files: int = 1024, decompressor=None) -> Dict:
    data = decompress_if_needed(data, decompressor)
    if len(data) < 0x98 or data[4:8] != b"SCCA":
        raise PrefetchError("not a prefetch file (missing SCCA signature)")
    version = struct.unpack_from("<I", data, 0)[0]
    exe = data[0x10:0x10 + 60].decode("utf-16-le", "replace").split("\x00", 1)[0]
    pf_hash = struct.unpack_from("<I", data, 0x4C)[0]
    metrics_off = struct.unpack_from("<I", data, 0x54)[0]
    strings_off, strings_size = struct.unpack_from("<II", data, 0x64)
    vol_off, vol_count, vol_size = struct.unpack_from("<III", data, 0x6C)

    if version == 17:
        times = [struct.unpack_from("<Q", data, 0x78)[0]]
        run_count = struct.unpack_from("<I", data, 0x90)[0]
        vol_entry = 40
    elif version == 23:
        times = [struct.unpack_from("<Q", data, 0x80)[0]]
        run_count = struct.unpack_from("<I", data, 0x98)[0]
        vol_entry = 104
    elif version in (26, 30, 31):
        times = list(struct.unpack_from("<8Q", data, 0x80))
        run_off = 0xC8 if version >= 30 and metrics_off == 0x128 else 0xD0
        run_count = struct.unpack_from("<I", data, run_off)[0]
        vol_entry = 104 if version == 26 else 96
    else:
        raise PrefetchError(f"unsupported prefetch version {version}")

    run_times = [t for t in (filetime_to_iso(x) for x in times) if t]

    files: List[str] = []
    if 0 < strings_off < len(data) and strings_size:
        blob = data[strings_off:strings_off + strings_size].decode("utf-16-le", "replace")
        files = [s for s in blob.split("\x00") if s]

    volumes: List[Dict] = []
    for i in range(min(vol_count, 64)):
        base = vol_off + i * vol_entry
        if base + 20 > len(data):
            break
        path_off, path_len = struct.unpack_from("<II", data, base)
        created = struct.unpack_from("<Q", data, base + 8)[0]
        serial = struct.unpack_from("<I", data, base + 16)[0]
        start = vol_off + path_off
        device = data[start:start + path_len * 2].decode("utf-16-le", "replace") if path_len else ""
        volumes.append({"device_path": device, "serial": f"{serial:08X}", "created": filetime_to_iso(created)})

    return {
        "format_version": version,
        "executable": exe,
        "prefetch_hash": f"{pf_hash:08X}",
        "run_count": run_count,
        "last_run": run_times[0] if run_times else None,
        "run_times": run_times,
        "volumes": volumes,
        "referenced_file_count": len(files),
        "referenced_files": files[:max_files],
        "referenced_files_truncated": len(files) > max_files,
        "executable_path": _guess_exe_path(exe, files),
    }


def _guess_exe_path(exe: str, files: List[str]) -> Optional[str]:
    if not exe:
        return None
    up = exe.upper()
    for f in files:
        if f.upper().endswith("\\" + up):
            return f
    return None
