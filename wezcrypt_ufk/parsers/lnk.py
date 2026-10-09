"""Windows Shell Link (.lnk) parser following MS-SHLLINK."""

from __future__ import annotations

import struct
import uuid
from typing import Dict, Optional

from ..core.timeutil import filetime_to_iso
from .shellitems import id_list_to_path, parse_id_list

LNK_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}


class LnkError(Exception):
    pass


def _ansi(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    return data[off:end if end >= 0 else len(data)].decode("cp1252", "replace")


def _utf16(data: bytes, off: int) -> str:
    end = off
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[off:end].decode("utf-16-le", "replace")


def _droid_mac(raw: bytes) -> Optional[str]:
    try:
        u = uuid.UUID(bytes_le=bytes(raw))
    except ValueError:
        return None
    if u.version != 1:
        return None
    node = f"{u.node:012x}"
    return ":".join(node[i:i + 2] for i in range(0, 12, 2))


def parse_lnk(data: bytes) -> Dict:
    if len(data) < 0x4C or data[:20] != LNK_HEADER:
        raise LnkError("not a shell link (bad header)")
    flags, attrs = struct.unpack_from("<II", data, 0x14)
    ctime, atime, wtime = struct.unpack_from("<QQQ", data, 0x1C)
    size = struct.unpack_from("<I", data, 0x34)[0]
    unicode = bool(flags & 0x80)
    res: Dict = {
        "target_created": filetime_to_iso(ctime),
        "target_accessed": filetime_to_iso(atime),
        "target_modified": filetime_to_iso(wtime),
        "target_size": size,
        "target_attributes": attrs,
        "flags": flags,
    }
    pos = 0x4C
    if flags & 0x01:
        idl_size = struct.unpack_from("<H", data, pos)[0]
        items = parse_id_list(data[pos + 2:pos + 2 + idl_size])
        res["idlist_path"] = id_list_to_path(items)
        pos += 2 + idl_size
    if flags & 0x02 and pos + 28 <= len(data):
        li_size, li_hsize, li_flags, vol_off, lbp_off, cnr_off, cps_off = struct.unpack_from("<7I", data, pos)
        li = data[pos:pos + li_size]
        if li_flags & 0x1 and vol_off:
            vsize, dtype, serial, label_off = struct.unpack_from("<IIII", li, vol_off)
            if label_off == 0x14:
                label = _utf16(li, vol_off + struct.unpack_from("<I", li, vol_off + 16)[0])
            else:
                label = _ansi(li, vol_off + label_off)
            res["drive_type"] = DRIVE_TYPES.get(dtype, str(dtype))
            res["volume_serial"] = f"{serial:08X}"
            res["volume_label"] = label
            if li_hsize >= 0x24:
                lbpu = struct.unpack_from("<I", li, 28)[0]
                res["local_path"] = _utf16(li, lbpu) if lbpu else _ansi(li, lbp_off)
            else:
                res["local_path"] = _ansi(li, lbp_off)
        if li_flags & 0x2 and cnr_off:
            net_off = struct.unpack_from("<I", li, cnr_off + 8)[0]
            res["network_share"] = _ansi(li, cnr_off + net_off)
            suffix = _ansi(li, cps_off) if cps_off else ""
            if suffix:
                res["network_path"] = res["network_share"].rstrip("\\") + "\\" + suffix
        pos += li_size
    for flag, key in ((0x04, "name"), (0x08, "relative_path"), (0x10, "working_dir"),
                      (0x20, "arguments"), (0x40, "icon_location")):
        if flags & flag and pos + 2 <= len(data):
            count = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if unicode:
                res[key] = data[pos:pos + count * 2].decode("utf-16-le", "replace")
                pos += count * 2
            else:
                res[key] = data[pos:pos + count].decode("cp1252", "replace")
                pos += count
    # Extra data blocks
    while pos + 8 <= len(data):
        bsize, bsig = struct.unpack_from("<II", data, pos)
        if bsize < 8 or pos + bsize > len(data):
            break
        block = data[pos:pos + bsize]
        if bsig == 0xA0000003 and bsize >= 0x60:
            res["machine_id"] = _ansi(block, 16)[:16]
            res["droid_volume"] = str(uuid.UUID(bytes_le=bytes(block[32:48])))
            res["droid_file"] = str(uuid.UUID(bytes_le=bytes(block[48:64])))
            res["birth_droid_file"] = str(uuid.UUID(bytes_le=bytes(block[80:96])))
            res["droid_mac"] = _droid_mac(block[48:64])
        elif bsig == 0xA0000001 and bsize >= 0x314:
            env = _utf16(block, 8 + 260)
            res["env_target"] = env or _ansi(block, 8)
        pos += bsize
    local = res.get("local_path")
    if local and "?" in local and res.get("idlist_path"):
        local = None  # ANSI path lost non-codepage characters; the shell item list keeps the Unicode name
    res["target_path"] = (local or res.get("network_path") or res.get("env_target")
                          or res.get("idlist_path") or res.get("relative_path") or "")
    return res
