"""Registry access abstraction.

Artifact parsers work against the small RegKey interface so the same code analyses:
  * offline hive files (REGF parser below) - used for hives acquired as evidence and for tests,
  * the live registry (winreg) - used when hives cannot be exported without admin rights,
  * in-memory keys (MemoryKey) - used by unit tests.

Limitation (documented): transaction logs (.LOG1/.LOG2) of dirty hives are not replayed.
"""

from __future__ import annotations

import mmap
import os
import struct
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

from ..core.timeutil import filetime_to_iso

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BE = 0, 1, 2, 3, 4, 5
REG_LINK, REG_MULTI_SZ, REG_QWORD = 6, 7, 11


@dataclass
class RegValue:
    name: str
    type: int
    data: Any


def decode_value(vtype: int, raw: bytes) -> Any:
    if vtype in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
        return _utf16z(raw)
    if vtype == REG_MULTI_SZ:
        text = raw.decode("utf-16-le", "replace")
        return [s for s in text.split("\x00") if s]
    if vtype == REG_DWORD and len(raw) >= 4:
        return struct.unpack_from("<I", raw)[0]
    if vtype == REG_DWORD_BE and len(raw) >= 4:
        return struct.unpack_from(">I", raw)[0]
    if vtype == REG_QWORD and len(raw) >= 8:
        return struct.unpack_from("<Q", raw)[0]
    return bytes(raw)


def _utf16z(raw: bytes) -> str:
    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", "replace")
    idx = text.find("\x00")
    return text if idx < 0 else text[:idx]


class RegKey:
    name: str = ""
    path: str = ""

    @property
    def last_write(self) -> Optional[str]:
        return None

    def subkeys(self) -> List["RegKey"]:
        raise NotImplementedError

    def values(self) -> List[RegValue]:
        raise NotImplementedError

    def subkey(self, path: str) -> Optional["RegKey"]:
        key: Optional[RegKey] = self
        for part in [p for p in path.replace("/", "\\").split("\\") if p]:
            if key is None:
                return None
            key = key._child(part)
        return key

    def _child(self, name: str) -> Optional["RegKey"]:
        low = name.lower()
        for sk in self.subkeys():
            if sk.name.lower() == low:
                return sk
        return None

    def value(self, name: str, default: Any = None) -> Any:
        low = name.lower()
        for v in self.values():
            if v.name.lower() == low:
                return v.data
        return default

    def walk(self, max_depth: int = 64) -> Iterator["RegKey"]:
        stack = [(self, 0)]
        while stack:
            key, depth = stack.pop()
            yield key
            if depth < max_depth:
                stack.extend((k, depth + 1) for k in reversed(key.subkeys()))


# --------------------------------------------------------------------------- in-memory


class MemoryKey(RegKey):
    def __init__(self, name: str, values: Optional[Dict[str, Any]] = None, last_write: Optional[str] = None,
                 path: str = ""):
        self.name = name
        self.path = path or name
        self._values: List[RegValue] = []
        for k, v in (values or {}).items():
            if isinstance(v, RegValue):
                self._values.append(v)
            elif isinstance(v, str):
                self._values.append(RegValue(k, REG_SZ, v))
            elif isinstance(v, int):
                self._values.append(RegValue(k, REG_DWORD if v <= 0xFFFFFFFF else REG_QWORD, v))
            elif isinstance(v, list):
                self._values.append(RegValue(k, REG_MULTI_SZ, v))
            else:
                self._values.append(RegValue(k, REG_BINARY, bytes(v)))
        self._last_write = last_write
        self._subkeys: List[MemoryKey] = []

    @property
    def last_write(self) -> Optional[str]:
        return self._last_write

    def add(self, name: str, values: Optional[Dict[str, Any]] = None, last_write: Optional[str] = None) -> "MemoryKey":
        child = MemoryKey(name, values, last_write, path=f"{self.path}\\{name}")
        self._subkeys.append(child)
        return child

    def subkeys(self) -> List[RegKey]:
        return list(self._subkeys)

    def values(self) -> List[RegValue]:
        return list(self._values)


# --------------------------------------------------------------------------- offline hive


class HiveError(Exception):
    pass


class Hive:
    """Read-only REGF hive parser (memory mapped)."""

    BASE = 4096

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "rb")
        size = os.fstat(self._fh.fileno()).st_size
        if size < self.BASE + 32:
            self._fh.close()
            raise HiveError("file too small to be a registry hive")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        if self._mm[0:4] != b"regf":
            self.close()
            raise HiveError("missing 'regf' signature")
        self.major, self.minor = struct.unpack_from("<II", self._mm, 0x14)
        self.root_offset = struct.unpack_from("<I", self._mm, 0x24)[0]
        self.last_written = filetime_to_iso(struct.unpack_from("<Q", self._mm, 0x0C)[0])
        seq1, seq2 = struct.unpack_from("<II", self._mm, 0x04)
        self.dirty = seq1 != seq2
        name = self._mm[0x30:0x30 + 64]
        self.embedded_name = _utf16z(bytes(name))

    def close(self) -> None:
        try:
            self._mm.close()
        except Exception:
            pass
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def cell(self, offset: int) -> bytes:
        pos = self.BASE + offset
        if offset == 0xFFFFFFFF or pos + 4 > len(self._mm):
            raise HiveError(f"cell offset out of range: 0x{offset:X}")
        size = struct.unpack_from("<i", self._mm, pos)[0]
        length = abs(size)
        if length < 4 or pos + length > len(self._mm):
            raise HiveError(f"invalid cell size at 0x{offset:X}")
        return self._mm[pos + 4: pos + length]

    def root(self) -> "HiveKey":
        return HiveKey(self, self.root_offset, "")


class HiveKey(RegKey):
    def __init__(self, hive: Hive, offset: int, parent_path: str):
        self.hive = hive
        self.offset = offset
        data = hive.cell(offset)
        if data[0:2] != b"nk":
            raise HiveError(f"expected nk cell at 0x{offset:X}")
        self._data = data
        flags = struct.unpack_from("<H", data, 2)[0]
        name_len = struct.unpack_from("<H", data, 72)[0]
        raw = data[76:76 + name_len]
        self.name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
        self.path = f"{parent_path}\\{self.name}" if parent_path else self.name
        self._ft = struct.unpack_from("<Q", data, 4)[0]
        self._n_sub = struct.unpack_from("<I", data, 20)[0]
        self._sub_off = struct.unpack_from("<I", data, 28)[0]
        self._n_val = struct.unpack_from("<I", data, 36)[0]
        self._val_off = struct.unpack_from("<I", data, 40)[0]

    @property
    def last_write(self) -> Optional[str]:
        return filetime_to_iso(self._ft)

    def _list_offsets(self, offset: int, depth: int = 0) -> List[int]:
        if depth > 4:
            return []
        data = self.hive.cell(offset)
        sig = data[0:2]
        count = struct.unpack_from("<H", data, 2)[0]
        if sig in (b"lf", b"lh"):
            return [struct.unpack_from("<I", data, 4 + i * 8)[0] for i in range(count)]
        if sig == b"li":
            return [struct.unpack_from("<I", data, 4 + i * 4)[0] for i in range(count)]
        if sig == b"ri":
            out: List[int] = []
            for i in range(count):
                out.extend(self._list_offsets(struct.unpack_from("<I", data, 4 + i * 4)[0], depth + 1))
            return out
        raise HiveError(f"unknown subkey list signature {sig!r}")

    def subkeys(self) -> List[RegKey]:
        if not self._n_sub or self._sub_off == 0xFFFFFFFF:
            return []
        out: List[RegKey] = []
        for off in self._list_offsets(self._sub_off):
            try:
                out.append(HiveKey(self.hive, off, self.path))
            except HiveError:
                continue
        return out

    def values(self) -> List[RegValue]:
        if not self._n_val or self._val_off == 0xFFFFFFFF:
            return []
        try:
            vlist = self.hive.cell(self._val_off)
        except HiveError:
            return []
        out = []
        for i in range(min(self._n_val, len(vlist) // 4)):
            off = struct.unpack_from("<I", vlist, i * 4)[0]
            try:
                out.append(self._read_value(off))
            except (HiveError, struct.error):
                continue
        return out

    def _read_value(self, offset: int) -> RegValue:
        vk = self.hive.cell(offset)
        if vk[0:2] != b"vk":
            raise HiveError("expected vk cell")
        name_len, size, data_off, vtype, flags = struct.unpack_from("<HIIIH", vk, 2)
        raw_name = vk[20:20 + name_len]
        name = raw_name.decode("latin-1") if flags & 1 else raw_name.decode("utf-16-le", "replace")
        if size & 0x80000000:
            length = size & 0x7FFFFFFF
            raw = struct.pack("<I", data_off)[:length]
        elif size == 0:
            raw = b""
        else:
            cell = self.hive.cell(data_off)
            if size > 16344 and cell[0:2] == b"db":
                count, seg_list = struct.unpack_from("<HI", cell, 2)
                segs = self.hive.cell(seg_list)
                chunks = []
                remaining = size
                for i in range(count):
                    seg = self.hive.cell(struct.unpack_from("<I", segs, i * 4)[0])
                    take = min(remaining, 16344, len(seg))
                    chunks.append(bytes(seg[:take]))
                    remaining -= take
                raw = b"".join(chunks)
            else:
                raw = bytes(cell[:size])
        return RegValue(name, vtype, decode_value(vtype, raw))


# --------------------------------------------------------------------------- live registry


class LiveKey(RegKey):
    """Wrapper over winreg (Windows only). Opened with KEY_READ and the 64-bit view."""

    def __init__(self, root, subpath: str, display_root: str):
        self._root = root
        self._subpath = subpath
        self.name = subpath.rsplit("\\", 1)[-1] if subpath else display_root
        self.path = f"{display_root}\\{subpath}" if subpath else display_root
        self._display_root = display_root
        self._cached_lw: Optional[str] = None
        self._lw_loaded = False

    def _open(self):
        import winreg

        return winreg.OpenKey(self._root, self._subpath, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)

    @property
    def last_write(self) -> Optional[str]:
        if not self._lw_loaded:
            import winreg

            self._lw_loaded = True
            try:
                with self._open() as k:
                    self._cached_lw = filetime_to_iso(winreg.QueryInfoKey(k)[2])
            except OSError:
                self._cached_lw = None
        return self._cached_lw

    def subkeys(self) -> List[RegKey]:
        import winreg

        out: List[RegKey] = []
        try:
            with self._open() as k:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(k, i)
                    except OSError:
                        break
                    out.append(LiveKey(self._root, f"{self._subpath}\\{name}" if self._subpath else name,
                                       self._display_root))
                    i += 1
        except OSError:
            pass
        return out

    def _child(self, name: str) -> Optional[RegKey]:
        child = LiveKey(self._root, f"{self._subpath}\\{name}" if self._subpath else name, self._display_root)
        try:
            child._open().Close()
        except OSError:
            return None
        return child

    def values(self) -> List[RegValue]:
        import winreg

        out: List[RegValue] = []
        try:
            with self._open() as k:
                i = 0
                while True:
                    try:
                        name, data, vtype = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    if isinstance(data, (bytes, bytearray)) or data is None:
                        data = decode_value(vtype, bytes(data or b""))
                    out.append(RegValue(name, vtype, data))
                    i += 1
        except OSError:
            pass
        return out


def live_root(name: str) -> Optional[RegKey]:
    """Return a LiveKey for 'HKLM\\...' / 'HKCU\\...' style paths, or None if absent/inaccessible."""
    try:
        import winreg
    except ImportError:
        return None
    roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER, "HKU": winreg.HKEY_USERS}
    head, _, rest = name.partition("\\")
    root = roots.get(head.upper())
    if root is None:
        return None
    key = LiveKey(root, rest, head.upper())
    try:
        key._open().Close()
    except OSError:
        return None
    return key


def current_control_set(system_root: RegKey) -> Optional[RegKey]:
    """Resolve CurrentControlSet in a SYSTEM hive (offline) or HKLM\\SYSTEM (live)."""
    direct = system_root.subkey("CurrentControlSet")
    if direct is not None:
        return direct
    current = system_root.subkey("Select")
    num = current.value("Current") if current is not None else None
    if isinstance(num, int):
        return system_root.subkey(f"ControlSet{num:03d}")
    return system_root.subkey("ControlSet001")
