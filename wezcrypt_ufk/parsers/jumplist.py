"""Jump List parsing: OLE Compound File reader, AutomaticDestinations (LNK streams + DestList)
and CustomDestinations (concatenated LNK records)."""

from __future__ import annotations

import struct
from typing import Dict, List, Optional

from ..core.timeutil import filetime_to_iso
from .lnk import LNK_HEADER, LnkError, parse_lnk

CFB_SIG = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF

# Only AppIDs whose mapping is well established are labelled; others are reported as raw IDs.
APP_IDS = {
    "5d696d521de238c3": "Google Chrome",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)",
    "f01b4d95cf55d32a": "Windows Explorer",
    "5f7b5f1e01b83767": "Quick Access",
    "1b4dd67f29cb1962": "Windows Explorer Pinned and Recent",
}


class CFBError(Exception):
    pass


class CompoundFile:
    def __init__(self, data: bytes):
        if len(data) < 512 or data[:8] != CFB_SIG:
            raise CFBError("not an OLE compound file")
        self.data = data
        self.sector_size = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mini_size = 1 << struct.unpack_from("<H", data, 0x20)[0]
        num_fat = struct.unpack_from("<I", data, 0x2C)[0]
        self.first_dir = struct.unpack_from("<I", data, 0x30)[0]
        self.cutoff = struct.unpack_from("<I", data, 0x38)[0]
        self.first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
        first_difat = struct.unpack_from("<I", data, 0x44)[0]
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        sid = first_difat
        seen = set()
        per = self.sector_size // 4
        while sid not in (ENDOFCHAIN, FREESECT) and sid not in seen and len(seen) < 100000:
            seen.add(sid)
            entries = struct.unpack_from(f"<{per}I", data, self._offset(sid))
            difat.extend(entries[:-1])
            sid = entries[-1]
        self.fat: List[int] = []
        for fs in [d for d in difat if d not in (ENDOFCHAIN, FREESECT)][:num_fat]:
            self.fat.extend(struct.unpack_from(f"<{per}I", data, self._offset(fs)))
        self.entries = self._read_directory()
        root = self.entries[0] if self.entries else None
        self.mini_stream = self._read_chain(root["start"], root["size"]) if root and root["size"] else b""
        self.minifat: List[int] = []
        if self.first_minifat not in (ENDOFCHAIN, FREESECT):
            raw = self._read_chain(self.first_minifat, None)
            self.minifat = list(struct.unpack_from(f"<{len(raw) // 4}I", raw))

    def _offset(self, sid: int) -> int:
        off = (sid + 1) * self.sector_size
        if off + self.sector_size > len(self.data):
            raise CFBError(f"sector {sid} beyond end of file")
        return off

    def _read_chain(self, start: int, size: Optional[int]) -> bytes:
        out = bytearray()
        sid = start
        guard = 0
        while sid not in (ENDOFCHAIN, FREESECT) and guard <= len(self.fat):
            off = self._offset(sid)
            out += self.data[off:off + self.sector_size]
            if sid >= len(self.fat):
                break
            sid = self.fat[sid]
            guard += 1
        return bytes(out[:size]) if size is not None else bytes(out)

    def _read_mini(self, start: int, size: int) -> bytes:
        out = bytearray()
        sid = start
        guard = 0
        while sid not in (ENDOFCHAIN, FREESECT) and guard <= len(self.minifat):
            off = sid * self.mini_size
            out += self.mini_stream[off:off + self.mini_size]
            if sid >= len(self.minifat):
                break
            sid = self.minifat[sid]
            guard += 1
        return bytes(out[:size])

    def _read_directory(self) -> List[Dict]:
        raw = self._read_chain(self.first_dir, None)
        entries = []
        for i in range(len(raw) // 128):
            e = raw[i * 128:(i + 1) * 128]
            name_len = struct.unpack_from("<H", e, 64)[0]
            etype = e[66]
            name = e[:max(0, name_len - 2)].decode("utf-16-le", "replace")
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<Q", e, 120)[0]
            if self.sector_size == 512:
                size &= 0xFFFFFFFF
            entries.append({"name": name, "type": etype, "start": start, "size": size})
        return entries

    def streams(self) -> Dict[str, bytes]:
        out = {}
        for e in self.entries[1:]:
            if e["type"] != 2:
                continue
            if e["size"] < self.cutoff:
                out[e["name"]] = self._read_mini(e["start"], e["size"])
            else:
                out[e["name"]] = self._read_chain(e["start"], e["size"])
        return out


def parse_destlist(data: bytes) -> List[Dict]:
    if len(data) < 32:
        return []
    version, count = struct.unpack_from("<II", data, 0)
    entries = []
    pos = 32
    for _ in range(count):
        try:
            if version >= 3:
                if pos + 130 > len(data):
                    break
                host = data[pos + 0x48:pos + 0x58].split(b"\x00", 1)[0].decode("cp1252", "replace")
                entry_no = struct.unpack_from("<I", data, pos + 0x58)[0]
                modified = struct.unpack_from("<Q", data, pos + 0x60)[0]
                pin = struct.unpack_from("<i", data, pos + 0x68)[0]
                count_access = struct.unpack_from("<I", data, pos + 0x70)[0]
                plen = struct.unpack_from("<H", data, pos + 0x80)[0]
                path = data[pos + 0x82:pos + 0x82 + plen * 2].decode("utf-16-le", "replace")
                pos += 0x82 + plen * 2 + 4
            else:
                if pos + 114 > len(data):
                    break
                host = data[pos + 0x48:pos + 0x58].split(b"\x00", 1)[0].decode("cp1252", "replace")
                entry_no = struct.unpack_from("<Q", data, pos + 0x58)[0]
                modified = struct.unpack_from("<Q", data, pos + 0x64)[0]
                pin = struct.unpack_from("<i", data, pos + 0x6C)[0]
                count_access = None
                plen = struct.unpack_from("<H", data, pos + 0x70)[0]
                path = data[pos + 0x72:pos + 0x72 + plen * 2].decode("utf-16-le", "replace")
                pos += 0x72 + plen * 2
        except struct.error:
            break
        entries.append({
            "entry_number": entry_no,
            "stream": format(entry_no, "x"),
            "hostname": host,
            "last_used": filetime_to_iso(modified),
            "pinned": pin != -1,
            "access_count": count_access,
            "path": path,
        })
    return entries


def parse_automatic_destinations(data: bytes) -> List[Dict]:
    cf = CompoundFile(data)
    streams = cf.streams()
    dest = {e["stream"]: e for e in parse_destlist(streams.get("DestList", b""))}
    out = []
    for name, blob in streams.items():
        if name == "DestList":
            continue
        rec: Dict = {"stream": name}
        try:
            rec.update(parse_lnk(blob))
        except (LnkError, struct.error) as exc:
            rec["parse_error"] = str(exc)
        meta = dest.get(name.lower())
        if meta:
            rec.update({"destlist_path": meta["path"], "last_used": meta["last_used"], "pinned": meta["pinned"],
                        "access_count": meta["access_count"], "hostname": meta["hostname"]})
        out.append(rec)
    return out


def parse_custom_destinations(data: bytes) -> List[Dict]:
    out = []
    pos = data.find(LNK_HEADER)
    while pos >= 0:
        nxt = data.find(LNK_HEADER, pos + len(LNK_HEADER))
        chunk = data[pos:nxt if nxt > 0 else len(data)]
        try:
            out.append(parse_lnk(chunk))
        except (LnkError, struct.error):
            pass
        pos = nxt
    return out


def app_id_from_filename(name: str) -> Dict[str, Optional[str]]:
    app_id = name.split(".", 1)[0].lower()
    return {"app_id": app_id, "app_hint": APP_IDS.get(app_id)}
