"""Windows shell item (ITEMIDLIST entry) parser used by ShellBags, LNK and RecentDocs."""

from __future__ import annotations

import struct
import uuid
from typing import Dict, List

from ..core.timeutil import dos_datetime_to_str

KNOWN_GUIDS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "User Files",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel Items",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
    "4234d49b-0245-4df3-b780-3893943456e1": "Applications",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "1cf1260c-4dd0-4ebb-811f-33c572699fde": "Music",
    "a0953c92-50dc-43bf-be83-3742fed03c9c": "Videos",
    "a8cdff1c-4878-43be-b5fd-f8091c1c60d0": "Documents",
    "3add1653-eb32-4cb0-bbd7-dfa0abb5acca": "Pictures",
    "5399e694-6ce5-4d6c-8fce-1d8870fdcba0": "Control Panel Home",
    "f3364ba0-65b9-11ce-a9ba-00aa004ae837": "Shell File System Folder",
    "9343812e-1c37-4a49-a12e-4b2d810d956b": "Search Home",
}


def guid_from_bytes(data: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(data[:16])))


def _cstring(data: bytes, offset: int, unicode: bool = False) -> str:
    if unicode:
        end = offset
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[offset:end].decode("utf-16-le", "replace")
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("cp1252", "replace")


def parse_shell_item(item: bytes) -> Dict:
    """Parse a single shell item (including its 2-byte size prefix)."""
    result: Dict = {"type": "unknown", "name": ""}
    if len(item) < 3:
        return result
    cls = item[2]
    try:
        if cls == 0x1F and len(item) >= 20:
            guid = guid_from_bytes(item[4:20])
            result.update(type="root_folder", guid=guid, name=KNOWN_GUIDS.get(guid, "{" + guid + "}"))
        elif 0x20 <= cls <= 0x2F:
            name = _cstring(item, 3)
            if not name and len(item) >= 0x16:
                guid = guid_from_bytes(item[0x0E:0x1E]) if len(item) >= 0x1E else ""
                name = KNOWN_GUIDS.get(guid, "{" + guid + "}") if guid else ""
            result.update(type="volume", name=name)
        elif 0x30 <= cls <= 0x3F:
            result.update(_parse_file_entry(item, cls))
        elif 0x40 <= cls <= 0x4F:
            result.update(type="network", name=_cstring(item, 5))
        elif cls == 0x61:
            result.update(type="uri", name=_parse_uri(item))
        elif cls == 0x71:
            guid = guid_from_bytes(item[14:30]) if len(item) >= 30 else ""
            result.update(type="control_panel", guid=guid, name=KNOWN_GUIDS.get(guid, "{" + guid + "}"))
        elif cls == 0x74:
            result.update(_parse_delegate(item))
        else:
            result.update(type=f"class_0x{cls:02X}")
    except (struct.error, IndexError, ValueError):
        result["parse_error"] = True
    return result


def _parse_uri(item: bytes) -> str:
    """URI items carry a header of variable layout; locate the URI string by its scheme separator."""
    for encoding, marker in (("utf-16-le", ":\x00/\x00/\x00"), ("cp1252", "://")):
        raw = bytes(item)
        idx = raw.find(marker.encode("latin-1"))
        if idx < 0:
            continue
        step = 2 if encoding == "utf-16-le" else 1
        start = idx
        while start - step >= 3 and _printable(raw[start - step:start], encoding):
            start -= step
        text = _cstring(raw, start, encoding == "utf-16-le")
        if "://" in text:
            return text
    return ""


def _printable(chunk: bytes, encoding: str) -> bool:
    try:
        ch = chunk.decode(encoding)
    except UnicodeDecodeError:
        return False
    return len(ch) == 1 and (ch.isalnum() or ch in "+-.")


def _parse_delegate(item: bytes) -> Dict:
    """Delegate (0x74) items embed a regular file entry after the 'CFSF' signature."""
    idx = item.find(b"CFSF")
    if idx < 0 or idx + 4 + 14 > len(item):
        return {"type": "delegate"}
    inner = bytes(item[idx + 4:])
    cls = inner[2] if 0x30 <= inner[2] <= 0x3F else 0x31
    res = _parse_file_entry(inner, cls)
    res["delegate"] = True
    return res


def _parse_file_entry(item: bytes, cls: int) -> Dict:
    is_dir = bool(cls & 0x01)
    is_unicode = bool(cls & 0x04)
    file_size = struct.unpack_from("<I", item, 4)[0]
    mod_date, mod_time = struct.unpack_from("<HH", item, 8)
    attrs = struct.unpack_from("<H", item, 12)[0]
    short_name = _cstring(item, 14, is_unicode)
    res: Dict = {
        "type": "directory" if is_dir else "file",
        "short_name": short_name,
        "name": short_name,
        "size": file_size,
        "modified": dos_datetime_to_str(mod_date, mod_time),
        "attributes": attrs,
    }
    sig = item.find(b"\x04\x00\xef\xbe", 14)
    if sig >= 4:
        ext = sig - 4
        version = struct.unpack_from("<H", item, ext + 2)[0]
        c_date, c_time = struct.unpack_from("<HH", item, ext + 8)
        a_date, a_time = struct.unpack_from("<HH", item, ext + 12)
        res["created"] = dos_datetime_to_str(c_date, c_time)
        res["accessed"] = dos_datetime_to_str(a_date, a_time)
        if version >= 7 and ext + 28 <= len(item):
            ref = struct.unpack_from("<Q", item, ext + 20)[0]
            res["mft_entry"] = ref & 0xFFFFFFFFFFFF
            res["mft_sequence"] = ref >> 48
        if version >= 9:
            name_off = ext + 46
        elif version == 8:
            name_off = ext + 42
        elif version == 7:
            name_off = ext + 38
        else:
            name_off = ext + 20
        if name_off < len(item):
            long_name = _cstring(item, name_off, True)
            if long_name and all(ch.isprintable() for ch in long_name):
                res["long_name"] = long_name
                res["name"] = long_name
    return res


def parse_id_list(data: bytes) -> List[Dict]:
    """Parse a sequence of shell items terminated by a zero-size entry."""
    items: List[Dict] = []
    pos = 0
    while pos + 2 <= len(data):
        size = struct.unpack_from("<H", data, pos)[0]
        if size == 0 or pos + size > len(data):
            break
        items.append(parse_shell_item(data[pos:pos + size]))
        pos += size
    return items


def join_path(parent: str, name: str) -> str:
    if not parent:
        return name
    if not name:
        return parent
    if parent.endswith("\\"):
        return parent + name
    return parent + "\\" + name


def id_list_to_path(items: List[Dict]) -> str:
    path = ""
    for it in items:
        name = it.get("name") or ""
        if it.get("type") == "root_folder" and name == "My Computer":
            continue
        path = join_path(path, name)
    return path
