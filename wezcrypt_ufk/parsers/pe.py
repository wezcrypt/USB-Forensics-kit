"""Minimal Portable Executable header parser for triage (no execution, no imports resolution)."""

from __future__ import annotations

import math
import struct
from typing import Dict, Optional

from ..core.timeutil import unix_to_iso
from ..core.winapi import long_path

MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "armnt", 0x200: "ia64"}
SUBSYSTEMS = {1: "native", 2: "windows_gui", 3: "windows_cui", 9: "windows_ce_gui", 10: "efi_application",
              11: "efi_boot_driver", 12: "efi_runtime_driver", 14: "xbox", 16: "windows_boot_application"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".efi", ".drv", ".msi"}
SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".lnk",
                     ".iso", ".img", ".vhd", ".vhdx", ".jar", ".reg"}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def parse_pe(path: str, max_read: int = 16 * 1024 * 1024) -> Optional[Dict]:
    """Return PE metadata or None if the file is not a PE image."""
    try:
        with open(long_path(path), "rb") as fh:
            head = fh.read(4096)
            if len(head) < 64 or head[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if e_lfanew > 0x10000:
                return None
            fh.seek(e_lfanew)
            hdr = fh.read(24 + 240)
            if hdr[:4] != b"PE\x00\x00":
                return None
            machine, nsec, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", hdr, 4)
            magic = struct.unpack_from("<H", hdr, 24)[0] if len(hdr) >= 26 else 0
            subsystem = struct.unpack_from("<H", hdr, 24 + 68)[0] if len(hdr) >= 24 + 70 else 0
            dll_chars = struct.unpack_from("<H", hdr, 24 + 70)[0] if len(hdr) >= 24 + 72 else 0
            fh.seek(e_lfanew + 24 + opt_size)
            sec_raw = fh.read(40 * min(nsec, 96))
            sections = []
            for i in range(len(sec_raw) // 40):
                name = sec_raw[i * 40:i * 40 + 8].split(b"\x00", 1)[0].decode("latin-1")
                vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", sec_raw, i * 40 + 8)
                chars = struct.unpack_from("<I", sec_raw, i * 40 + 36)[0]
                ent = None
                if 0 < rsize <= max_read:
                    fh.seek(rptr)
                    ent = round(entropy(fh.read(min(rsize, 4 * 1024 * 1024))), 3)
                sections.append({"name": name, "virtual_size": vsize, "raw_size": rsize, "entropy": ent,
                                 "executable": bool(chars & 0x20000000), "writable": bool(chars & 0x80000000)})
    except (OSError, struct.error):
        return None
    max_ent = max((s["entropy"] or 0 for s in sections), default=0)
    return {
        "machine": MACHINES.get(machine, hex(machine)),
        "pe_type": "PE32+" if magic == 0x20B else "PE32" if magic == 0x10B else hex(magic),
        "compile_time": unix_to_iso(timestamp) if timestamp else None,
        "compile_timestamp_raw": timestamp,
        "is_dll": bool(characteristics & 0x2000),
        "subsystem": SUBSYSTEMS.get(subsystem, subsystem),
        "aslr": bool(dll_chars & 0x40),
        "dep": bool(dll_chars & 0x100),
        "section_count": nsec,
        "sections": sections,
        "max_section_entropy": max_ent,
        "packed_suspected": max_ent >= 7.2 or any(s["name"].upper().startswith("UPX") for s in sections),
        "writable_executable_section": any(s["executable"] and s["writable"] for s in sections),
    }
