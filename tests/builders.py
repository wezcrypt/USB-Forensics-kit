"""Builders for SYNTHETIC forensic artifacts used by the tests (no real personal data)."""

from __future__ import annotations

import json
import os
import sqlite3
import struct
import uuid
from typing import Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------- time helpers

FILETIME_2024 = 133_485_408_000_000_000  # 2024-01-01T00:00:00Z


def filetime(year_offset_seconds: int = 0) -> int:
    return FILETIME_2024 + year_offset_seconds * 10_000_000


def webkit(seconds_after_2024: int = 0) -> int:
    return FILETIME_2024 // 10 + seconds_after_2024 * 1_000_000


# ----------------------------------------------------------------------------- registry hive (REGF)


class HiveBuilder:
    """Writes a minimal but valid REGF hive. Keys: (name, values, subkeys, last_write_filetime)."""

    def __init__(self):
        self.data = bytearray()

    def _alloc(self, payload: bytes) -> int:
        size = (len(payload) + 4 + 7) & ~7
        off = 0x20 + len(self.data)
        self.data += struct.pack("<i", -size) + payload + b"\x00" * (size - 4 - len(payload))
        return off

    def _value(self, name: str, vtype: int, raw: bytes) -> int:
        nm = name.encode("latin-1")
        if len(raw) <= 4:
            size = len(raw) | 0x80000000
            data_off = struct.unpack("<I", raw.ljust(4, b"\x00"))[0]
        elif len(raw) > 16344:
            segs = []
            for i in range(0, len(raw), 16344):
                segs.append(self._alloc(raw[i:i + 16344]))
            seg_list = self._alloc(b"".join(struct.pack("<I", s) for s in segs))
            data_off = self._alloc(b"db" + struct.pack("<HI", len(segs), seg_list))
            size = len(raw)
        else:
            data_off = self._alloc(raw)
            size = len(raw)
        return self._alloc(b"vk" + struct.pack("<HIIIHH", len(nm), size, data_off, vtype, 1, 0) + nm)

    def key(self, name: str, values: Optional[List[Tuple[str, int, bytes]]] = None,
            subkeys: Optional[List[int]] = None, last_write: int = FILETIME_2024, root: bool = False) -> int:
        values = values or []
        subkeys = subkeys or []
        sub_off = 0xFFFFFFFF
        if subkeys:
            sub_off = self._alloc(b"lf" + struct.pack("<H", len(subkeys)) + b"".join(struct.pack("<II", s, 0) for s in subkeys))
        val_off = 0xFFFFFFFF
        if values:
            offs = [self._value(n, t, d) for n, t, d in values]
            val_off = self._alloc(b"".join(struct.pack("<I", o) for o in offs))
        nm = name.encode("latin-1")
        flags = 0x20 | (0x0C if root else 0)
        body = (b"nk" + struct.pack("<HQIIIIIIIIIII", flags, last_write, 0, 0, len(subkeys), 0, sub_off, 0xFFFFFFFF,
                                    len(values), val_off, 0xFFFFFFFF, 0xFFFFFFFF, 0)
                + b"\x00" * 12 + struct.pack("<IHH", 0, len(nm), 0) + nm)
        return self._alloc(body)

    def build(self, root_offset: int, path: str, dirty: bool = False) -> str:
        hbin_size = ((0x20 + len(self.data) + 8 + 4095) // 4096) * 4096
        free = hbin_size - 0x20 - len(self.data)
        hbin = b"hbin" + struct.pack("<III", 0, hbin_size, 0) + b"\x00" * 16 + bytes(self.data)
        if free >= 8:
            hbin += struct.pack("<i", free) + b"\x00" * (free - 4)
        base = bytearray(4096)
        base[0:4] = b"regf"
        struct.pack_into("<II", base, 4, 1, 2 if dirty else 1)
        struct.pack_into("<Q", base, 0x0C, FILETIME_2024)
        struct.pack_into("<IIII", base, 0x14, 1, 5, 0, 1)
        struct.pack_into("<II", base, 0x24, root_offset, hbin_size)
        with open(path, "wb") as fh:
            fh.write(bytes(base) + hbin)
        return path


def sz(text: str) -> bytes:
    return (text + "\x00").encode("utf-16-le")


def dword(v: int) -> bytes:
    return struct.pack("<I", v)


# ----------------------------------------------------------------------------- shell items / LNK


def file_entry_item(name: str, is_dir: bool = True, version: int = 9, mft: int = 1234) -> bytes:
    short = name[:8].upper().encode("ascii", "replace") + b"\x00"
    if len(short) % 2:
        short += b"\x00"
    body = struct.pack("<BBIHHH", 0x31 if is_dir else 0x32, 0, 0, 0x5821, 0x6000, 0x10 if is_dir else 0x20) + short
    long_name = (name + "\x00").encode("utf-16-le")
    ext = struct.pack("<HHI", 0, version, 0xBEEF0004) + struct.pack("<HHHH", 0x5821, 0x6000, 0x5822, 0x6000) + b"\x2e\x00"
    if version >= 7:
        ext += b"\x00\x00" + struct.pack("<Q", mft | (3 << 48)) + b"\x00" * 8
    ext += struct.pack("<H", 0)  # long string size
    if version >= 9:
        ext += b"\x00" * 4
    if version >= 8:
        ext += b"\x00" * 4
    ext += long_name + struct.pack("<H", 0)
    ext = struct.pack("<H", len(ext)) + ext[2:]
    item = body + ext
    return struct.pack("<H", len(item) + 2) + item


def root_item(guid: str = "20d04fe0-3aea-1069-a2d8-08002b30309d") -> bytes:
    payload = b"\x1f\x50" + uuid.UUID(guid).bytes_le
    return struct.pack("<H", len(payload) + 2) + payload


def volume_item(letter: str = "C:\\") -> bytes:
    payload = b"\x2f" + letter.encode("ascii") + b"\x00" * (20 - len(letter))
    return struct.pack("<H", len(payload) + 2) + payload


def build_lnk(target: str, arguments: str = "", working_dir: str = "", drive_type: int = 3, serial: int = 0xA1B2C3D4,
              label: str = "OS", machine: str = "WS-TEST01", times: Tuple[int, int, int] = (filetime(), filetime(60), filetime(120))) -> bytes:
    flags = 0x01 | 0x02 | 0x80  # IDList, LinkInfo, Unicode
    if working_dir:
        flags |= 0x10
    if arguments:
        flags |= 0x20
    header = bytearray(0x4C)
    header[0:20] = bytes.fromhex("4c0000000114020000000000c000000000000046")
    struct.pack_into("<II", header, 0x14, flags, 0x20)
    struct.pack_into("<QQQ", header, 0x1C, *times)
    struct.pack_into("<I", header, 0x34, 4096)
    struct.pack_into("<I", header, 0x3C, 1)
    idl = root_item() + volume_item(target[:3]) + b"".join(file_entry_item(p, i < len(target[3:].split("\\")) - 1)
                                                          for i, p in enumerate(target[3:].split("\\"))) + b"\x00\x00"
    idlist = struct.pack("<H", len(idl)) + idl
    label_b = label.encode("ascii") + b"\x00"
    volid = struct.pack("<IIII", 0x10 + len(label_b), drive_type, serial, 0x10) + label_b
    path_b = target.encode("cp1252", "replace") + b"\x00"
    unicode_needed = path_b.decode("cp1252", "replace")[:-1] != target
    hdr_size = 0x24 if unicode_needed else 0x1C
    vol_off = hdr_size
    lbp_off = vol_off + len(volid)
    cps_off = lbp_off + len(path_b)
    li_body = volid + path_b + b"\x00"
    extra = b""
    if unicode_needed:
        lbpu_off = hdr_size + len(li_body)
        uni = (target + "\x00").encode("utf-16-le")
        cpsu_off = lbpu_off + len(uni)
        li_body += uni + b"\x00\x00"
        extra = struct.pack("<II", lbpu_off, cpsu_off)
    li = struct.pack("<7I", hdr_size + len(li_body), hdr_size, 1, vol_off, lbp_off, 0, cps_off) + extra + li_body
    strings = b""
    if working_dir:
        strings += struct.pack("<H", len(working_dir)) + working_dir.encode("utf-16-le")
    if arguments:
        strings += struct.pack("<H", len(arguments)) + arguments.encode("utf-16-le")
    droid_vol = uuid.uuid4()
    droid_file = uuid.uuid1(node=0x001122334455)
    tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine.encode("ascii").ljust(16, b"\x00")
    tracker += droid_vol.bytes_le + droid_file.bytes_le + droid_vol.bytes_le + droid_file.bytes_le
    return bytes(header) + idlist + li + strings + tracker + b"\x00\x00\x00\x00"


# ----------------------------------------------------------------------------- prefetch


def build_prefetch(exe: str, run_count: int, run_times: List[int], files: List[str], version: int = 30,
                   device: str = "\\VOLUME{01d9aaaa-1234}", serial: int = 0x1234ABCD) -> bytes:
    strings = b"".join((f + "\x00").encode("utf-16-le") for f in files)
    vol_entry = {17: 40, 23: 104, 26: 104, 30: 96}[version]
    header_len = 0x130 if version >= 26 else 0xA0
    strings_off = header_len
    vol_off = strings_off + len(strings)
    dev = device.encode("utf-16-le")
    vol = bytearray(vol_entry)
    struct.pack_into("<IIQI", vol, 0, vol_entry, len(device), filetime(-86400), serial)
    vol_blob = bytes(vol) + dev + b"\x00\x00"
    data = bytearray(vol_off + len(vol_blob))
    struct.pack_into("<I4sI", data, 0, version, b"SCCA", len(data))
    name = exe.encode("utf-16-le")[:58]
    data[0x10:0x10 + len(name)] = name
    struct.pack_into("<I", data, 0x4C, 0xDEADBEEF)
    struct.pack_into("<I", data, 0x54, 0x130)
    struct.pack_into("<II", data, 0x64, strings_off, len(strings))
    struct.pack_into("<III", data, 0x6C, vol_off, 1, len(vol_blob))
    if version == 17:
        struct.pack_into("<Q", data, 0x78, run_times[0])
        struct.pack_into("<I", data, 0x90, run_count)
    elif version == 23:
        struct.pack_into("<Q", data, 0x80, run_times[0])
        struct.pack_into("<I", data, 0x98, run_count)
    else:
        times = (run_times + [0] * 8)[:8]
        struct.pack_into("<8Q", data, 0x80, *times)
        struct.pack_into("<I", data, 0xD0, run_count)
    data[strings_off:strings_off + len(strings)] = strings
    data[vol_off:vol_off + len(vol_blob)] = vol_blob
    return bytes(data)


# ----------------------------------------------------------------------------- compound file / jump lists


def build_cfb(streams: Dict[str, bytes]) -> bytes:
    """Version-3 compound file. Streams < 4096 bytes go to the mini stream (as Windows does)."""
    SS, MS = 512, 64
    END, FREE, FATSECT = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    sectors: List[bytes] = []
    fat: List[int] = []

    def put_chain(blob: bytes) -> int:
        if not blob:
            return END
        start = len(sectors)
        n = (len(blob) + SS - 1) // SS
        for i in range(n):
            sectors.append(blob[i * SS:(i + 1) * SS].ljust(SS, b"\x00"))
            fat.append(start + i + 1 if i < n - 1 else END)
        return start

    mini = bytearray()
    minifat: List[int] = []
    entries = []
    for name, data in streams.items():
        if len(data) < 4096:
            start = len(mini) // MS
            n = max(1, (len(data) + MS - 1) // MS)
            mini += data.ljust(n * MS, b"\x00")
            minifat.extend([start + i + 1 if i < n - 1 else END for i in range(n)])
            entries.append((name, start, len(data)))
        else:
            entries.append((name, put_chain(data), len(data)))
    mini_start = put_chain(bytes(mini))
    mf_blob = b"".join(struct.pack("<I", x) for x in minifat)
    minifat_start = put_chain(mf_blob.ljust(((len(mf_blob) + SS - 1) // SS) * SS, b"\xff")) if minifat else END

    def dir_entry(name: str, etype: int, start: int, size: int, child: int = FREE, right: int = FREE) -> bytes:
        e = bytearray(128)
        nb = (name + "\x00").encode("utf-16-le")
        e[0:len(nb)] = nb
        struct.pack_into("<HBB", e, 64, len(nb), etype, 1)
        struct.pack_into("<III", e, 68, FREE, right, child)
        struct.pack_into("<IQ", e, 116, start, size)
        return bytes(e)

    dirs = dir_entry("Root Entry", 5, mini_start, len(mini), child=1 if entries else FREE)
    for i, (name, start, size) in enumerate(entries):
        dirs += dir_entry(name, 2, start, size, right=(i + 2) if i + 1 < len(entries) else FREE)
    dirs = dirs.ljust(((len(dirs) + SS - 1) // SS) * SS, b"\x00")
    dir_start = put_chain(dirs)
    n_fat = 1
    while (len(sectors) + n_fat) > n_fat * (SS // 4):
        n_fat += 1
    fat_ids = list(range(len(sectors), len(sectors) + n_fat))
    fat.extend([FATSECT] * n_fat)
    fat_blob = b"".join(struct.pack("<I", x) for x in fat).ljust(n_fat * SS, b"\xff")
    for i in range(n_fat):
        sectors.append(fat_blob[i * SS:(i + 1) * SS])
    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 0x28, 0, n_fat, dir_start, 0, 4096, minifat_start,
                     (len(mf_blob) + SS - 1) // SS if minifat else 0, END, 0)
    difat = fat_ids + [FREE] * (109 - len(fat_ids))
    struct.pack_into("<109I", header, 0x4C, *difat)
    return bytes(header) + b"".join(sectors)


def build_destlist_v4(entries: List[Tuple[int, str, int, int]]) -> bytes:
    """entries: (entry_number, path, last_used_filetime, access_count)."""
    out = bytearray(32)
    struct.pack_into("<II", out, 0, 4, len(entries))
    for num, path, ts, count in entries:
        e = bytearray(0x82)
        e[0x48:0x48 + 9] = b"WS-TEST01"
        struct.pack_into("<I", e, 0x58, num)
        struct.pack_into("<Q", e, 0x60, ts)
        struct.pack_into("<i", e, 0x68, -1)
        struct.pack_into("<I", e, 0x70, count)
        struct.pack_into("<H", e, 0x80, len(path))
        out += e + path.encode("utf-16-le") + b"\x00\x00\x00\x00"
    return bytes(out)


# ----------------------------------------------------------------------------- recycle bin


def build_recycle_i(path: str, size: int, deleted: int, version: int = 2) -> bytes:
    if version == 1:
        return struct.pack("<QQQ", 1, size, deleted) + path.encode("utf-16-le").ljust(520, b"\x00")
    p = (path + "\x00").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, deleted, len(p) // 2) + p


# ----------------------------------------------------------------------------- browsers


def build_chrome_profile(profile_dir: str) -> None:
    os.makedirs(profile_dir, exist_ok=True)
    con = sqlite3.connect(os.path.join(profile_dir, "History"))
    con.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,
                          last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER);
        CREATE TABLE downloads(id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT, target_path TEXT, start_time INTEGER,
                               received_bytes INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER,
                               interrupt_reason INTEGER, end_time INTEGER, opened INTEGER, last_access_time INTEGER,
                               referrer TEXT, tab_url TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT);
    """)
    con.execute("INSERT INTO urls VALUES(1,'https://example.org/','Example Domain',3,1,?,0)", (webkit(100),))
    con.execute("INSERT INTO urls VALUES(2,'https://downloads.example.net/tool.exe','tool',1,0,?,0)", (webkit(200),))
    con.execute("INSERT INTO urls VALUES(3,'https://ar.example.org/صفحة','صفحة عربية',1,0,?,0)", (webkit(300),))
    con.execute("INSERT INTO visits VALUES(1,1,?,0,1)", (webkit(100),))
    con.execute("INSERT INTO visits VALUES(2,2,?,1,0)", (webkit(200),))
    con.execute("INSERT INTO visits VALUES(3,3,?,0,0)", (webkit(300),))
    con.execute("INSERT INTO downloads VALUES(1,'g',?,?,?,1024,1024,1,1,0,?,0,0,'https://example.org/',"
                "'https://example.org/','application/octet-stream')",
                (r"C:\Users\analyst\Downloads\tool.exe", r"C:\Users\analyst\Downloads\tool.exe", webkit(210), webkit(215)))
    con.execute("INSERT INTO downloads_url_chains VALUES(1,0,'https://downloads.example.net/tool.exe')")
    con.commit()
    con.close()
    con = sqlite3.connect(os.path.join(profile_dir, "Cookies"))
    con.executescript("""CREATE TABLE cookies(creation_utc INTEGER, host_key TEXT, name TEXT, value TEXT, path TEXT,
        expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, last_access_utc INTEGER, has_expires INTEGER,
        is_persistent INTEGER, priority INTEGER, encrypted_value BLOB, samesite INTEGER);""")
    con.execute("INSERT INTO cookies VALUES(?, '.example.org', 'session', 'SECRET-VALUE-MUST-NOT-LEAK', '/', ?, 1, 1, ?, 1, 1, 1, X'DEADBEEF', 0)",
                (webkit(100), webkit(9_000_000), webkit(150)))
    con.commit()
    con.close()
    with open(os.path.join(profile_dir, "Bookmarks"), "w", encoding="utf-8") as fh:
        json.dump({"roots": {"bookmark_bar": {"type": "folder", "name": "Bookmarks bar", "children": [
            {"type": "url", "name": "Example", "url": "https://example.org/", "date_added": str(webkit(50))},
            {"type": "folder", "name": "مجلد", "children": [
                {"type": "url", "name": "عربي", "url": "https://ar.example.org/", "date_added": str(webkit(60))}]}]}}},
                  fh, ensure_ascii=False)
    with open(os.path.join(profile_dir, "Preferences"), "w", encoding="utf-8") as fh:
        json.dump({"extensions": {"settings": {"abcdefghijklmnopabcdefghijklmnop": {
            "install_time": str(webkit(40)), "from_webstore": True, "state": 1, "location": 1,
            "manifest": {"name": "Test Extension", "version": "1.2.3", "permissions": ["tabs", "storage"]}}}}}, fh)
    cache = os.path.join(profile_dir, "Cache", "Cache_Data")
    os.makedirs(cache, exist_ok=True)
    key = b"1/0/_dk_https://example.org https://example.org https://example.org/logo.png"
    with open(os.path.join(cache, "0123456789abcdef_0"), "wb") as fh:
        fh.write(struct.pack("<QIII", 0xFCFB6D1BA7725C30, 5, len(key), 0) + key + b"\x00" * 32)


def build_firefox_profile(appdata_roaming: str, name: str = "abcd1234.default-release") -> str:
    base = os.path.join(appdata_roaming, "Mozilla", "Firefox")
    prof = os.path.join(base, "Profiles", name)
    os.makedirs(prof, exist_ok=True)
    with open(os.path.join(base, "profiles.ini"), "w", encoding="utf-8") as fh:
        fh.write(f"[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/{name}\n")
    con = sqlite3.connect(os.path.join(prof, "places.sqlite"))
    con.executescript("""
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER);
        CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
        CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT,
                                   dateAdded INTEGER, lastModified INTEGER);
        CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT,
                               dateAdded INTEGER, lastModified INTEGER);
    """)
    us = 1_704_067_200_000_000  # 2024-01-01 in PRTime
    con.execute("INSERT INTO moz_places VALUES(1,'https://example.com/page','Example page',2,?)", (us,))
    con.execute("INSERT INTO moz_places VALUES(2,'https://files.example.com/setup.msi','setup',1,?)", (us + 5_000_000,))
    con.execute("INSERT INTO moz_historyvisits VALUES(1,0,1,?,1)", (us,))
    con.execute("INSERT INTO moz_historyvisits VALUES(2,0,2,?,7)", (us + 5_000_000,))
    con.execute("INSERT INTO moz_bookmarks VALUES(1,2,NULL,0,'toolbar',?,?)", (us, us))
    con.execute("INSERT INTO moz_bookmarks VALUES(2,1,1,1,'Example bookmark',?,?)", (us, us))
    con.execute("INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI')")
    con.execute("INSERT INTO moz_anno_attributes VALUES(2,'downloads/metaData')")
    con.execute("INSERT INTO moz_annos VALUES(1,2,1,'file:///C:/Users/analyst/Downloads/setup.msi',?,?)", (us + 5_000_000, us))
    con.execute("INSERT INTO moz_annos VALUES(2,2,2,?,?,?)", (json.dumps({"state": 1, "endTime": 1704067206000, "fileSize": 2048}),
                                                             us + 5_000_000, us))
    con.commit()
    con.close()
    con = sqlite3.connect(os.path.join(prof, "cookies.sqlite"))
    con.executescript("""CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY, name TEXT, value TEXT, host TEXT, path TEXT,
        expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER);""")
    con.execute("INSERT INTO moz_cookies VALUES(1,'sid','SECRET-VALUE-MUST-NOT-LEAK','.example.com','/',1893456000,?,?,1,1)", (us, us))
    con.commit()
    con.close()
    with open(os.path.join(prof, "extensions.json"), "w", encoding="utf-8") as fh:
        json.dump({"addons": [{"id": "addon@example.com", "version": "2.0", "type": "extension", "active": True,
                               "installDate": 1704067200000, "location": "app-profile",
                               "defaultLocale": {"name": "Example Addon", "description": "synthetic"}},
                              {"id": "builtin@mozilla.org", "location": "app-builtin", "defaultLocale": {"name": "x"}}]}, fh)
    return prof


# ----------------------------------------------------------------------------- event XML

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def event_xml(event_id: int, time: str, data: Dict[str, str], channel: str = "Security",
              provider: str = "Microsoft-Windows-Security-Auditing", record: int = 1) -> str:
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{event_id}</EventID><Level>0</Level>'
            f'<TimeCreated SystemTime="{time}"/><EventRecordID>{record}</EventRecordID><Channel>{channel}</Channel>'
            f'<Computer>WS-TEST01</Computer><Security UserID="S-1-5-18"/></System><EventData>{fields}</EventData></Event>')
