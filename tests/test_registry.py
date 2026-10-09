"""Offline REGF parser and registry artifact parsers (synthetic hives)."""

import codecs
import struct

import pytest

from builders import HiveBuilder, dword, file_entry_item, filetime, root_item, sz, volume_item
from wezcrypt_ufk.parsers import winreg_artifacts as wra
from wezcrypt_ufk.parsers.registry import (REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD, REG_SZ, Hive, HiveError,
                                           MemoryKey, RegValue)


def test_hive_values_subkeys_and_bigdata(tmp_path):
    b = HiveBuilder()
    big = bytes(range(256)) * 100  # 25,600 bytes -> 'db' big-data record
    child = b.key("Child", [("Name", REG_SZ, sz("قيمة عربية")), ("Count", REG_DWORD, dword(7)),
                            ("Q", REG_QWORD, struct.pack("<Q", 2 ** 40)), ("Multi", REG_MULTI_SZ, sz("a") + sz("b") + b"\x00\x00"),
                            ("Big", REG_BINARY, big), ("Small", REG_BINARY, b"\x01\x02")], last_write=filetime(3600))
    root = b.key("ROOT", [("RootVal", REG_SZ, sz("x"))], [child], root=True)
    path = b.build(root, str(tmp_path / "TEST.hive"))
    with Hive(path) as hive:
        r = hive.root()
        assert r.name == "ROOT" and r.value("rootval") == "x"
        c = r.subkey("child")
        assert c.value("Name") == "قيمة عربية"
        assert c.value("Count") == 7 and c.value("Q") == 2 ** 40
        assert c.value("Multi") == ["a", "b"]
        assert c.value("Big") == big and c.value("Small") == b"\x01\x02"
        assert c.last_write == "2024-01-01T01:00:00.000000Z"
        assert not hive.dirty


def test_hive_rejects_non_hive_and_flags_dirty(tmp_path):
    bad = tmp_path / "bad.hive"
    bad.write_bytes(b"\x00" * 8192)
    with pytest.raises(HiveError):
        Hive(str(bad))
    b = HiveBuilder()
    path = b.build(b.key("R", root=True), str(tmp_path / "dirty.hive"), dirty=True)
    with Hive(path) as hive:
        assert hive.dirty


def test_userassist_rot13_and_counts():
    root = MemoryKey("NTUSER")
    ua = root.add("Software").add("Microsoft").add("Windows").add("CurrentVersion").add("Explorer").add("UserAssist")
    count = ua.add("{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}").add("Count")
    data = bytearray(72)
    struct.pack_into("<IIII", data, 0, 0, 5, 3, 60000)
    struct.pack_into("<Q", data, 60, filetime(7200))
    name = codecs.encode("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", "rot_13")
    count._values.append(RegValue(name, REG_BINARY, bytes(data)))
    recs = wra.parse_userassist(root, "analyst")
    assert recs[0]["path"] == "C:\\Windows\\System32\\cmd.exe"
    assert recs[0]["run_count"] == 5 and recs[0]["last_executed"] == "2024-01-01T02:00:00.000000Z"


def test_shellbags_paths(tmp_path):
    b = HiveBuilder()
    leaf = b.key("0", [("NodeSlot", REG_DWORD, dword(4))], last_write=filetime(500))
    vol = b.key("0", [("0", REG_BINARY, file_entry_item("تقارير")), ("NodeSlot", REG_DWORD, dword(3)),
                      ("MRUListEx", REG_BINARY, struct.pack("<ii", 0, -1))], [leaf], last_write=filetime(400))
    comp = b.key("0", [("0", REG_BINARY, volume_item("E:\\")), ("MRUListEx", REG_BINARY, struct.pack("<ii", 0, -1))],
                 [vol], last_write=filetime(300))
    bag = b.key("BagMRU", [("0", REG_BINARY, root_item()), ("MRUListEx", REG_BINARY, struct.pack("<ii", 0, -1))], [comp], root=True)
    path = b.build(bag, str(tmp_path / "usrclass.hive"))
    with Hive(path) as hive:
        recs = wra.parse_shellbags(hive.root(), "UsrClass", "analyst")
    paths = [r["path"] for r in recs]
    assert "E:\\تقارير" in paths
    target = next(r for r in recs if r["path"] == "E:\\تقارير")
    assert target["mft_entry"] == 1234 and target["key_last_write"] == "2024-01-01T00:08:20.000000Z"


def _shim_blob(entries):
    body = b""
    for path, ts in entries:
        p = path.encode("utf-16-le")
        inner = struct.pack("<H", len(p)) + p + struct.pack("<QI", ts, 0)
        body += b"10ts" + struct.pack("<II", 0, len(inner)) + inner
    return struct.pack("<I", 0x34) + b"\x00" * (0x34 - 4) + body


def test_shimcache_from_system_hive(tmp_path):
    b = HiveBuilder()
    acc = b.key("AppCompatCache", [("AppCompatCache", REG_BINARY, _shim_blob([
        ("C:\\Users\\analyst\\Downloads\\tool.exe", filetime(10)), ("C:\\Windows\\notepad.exe", filetime(20))]))])
    sm = b.key("Session Manager", subkeys=[acc])
    ctrl = b.key("Control", subkeys=[sm])
    cs = b.key("ControlSet001", subkeys=[ctrl])
    sel = b.key("Select", [("Current", REG_DWORD, dword(1))])
    root = b.key("SYSTEM", subkeys=[cs, sel], root=True)
    path = b.build(root, str(tmp_path / "SYSTEM.hive"))
    with Hive(path) as hive:
        recs = wra.shimcache_from_system(hive.root())
    assert [r["path"] for r in recs] == ["C:\\Users\\analyst\\Downloads\\tool.exe", "C:\\Windows\\notepad.exe"]
    assert recs[0]["position"] == 0 and recs[0]["last_modified"] == "2024-01-01T00:00:10.000000Z"


def test_usb_devices_and_properties():
    system = MemoryKey("SYSTEM")
    system.add("Select", {"Current": 1})
    ccs = system.add("ControlSet001")
    dev = ccs.add("Enum").add("USBSTOR").add("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00").add("4C530001230101112233&0",
                                                                                          {"FriendlyName": "SanDisk Cruzer USB Device"})
    props = dev.add("Properties").add("{83da6326-97a6-4088-9453-a1923f573b29}")
    props.add("0064", {"": RegValue("", 0xFFFF0010, struct.pack("<Q", filetime(0)))})
    props.add("0066", {"": RegValue("", 0xFFFF0010, struct.pack("<Q", filetime(3600)))})
    props.add("0067", {"": RegValue("", 0xFFFF0010, struct.pack("<Q", filetime(7200)))})
    ccs.subkey("Enum").add("USB").add("VID_0781&PID_5567").add("4C530001230101112233", {"Service": "USBSTOR"})
    system.add("MountedDevices", {"\\DosDevices\\E:": RegValue("\\DosDevices\\E:", REG_BINARY,
                                  "_??_USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer#4C530001230101112233&0#{53f56307}".encode("utf-16-le"))})
    software = MemoryKey("SOFTWARE")
    software.add("Microsoft").add("Windows Portable Devices").add("Devices").add(
        "SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_SANDISK#4C530001230101112233&0#", {"FriendlyName": "EVIDENCE_USB"})
    recs = wra.parse_usb_devices(system, software)
    stor = next(r for r in recs if r["source"] == "USBSTOR")
    assert stor["vendor"] == "SanDisk" and stor["serial"] == "4C530001230101112233" and stor["serial_is_unique"]
    assert stor["first_install"] == "2024-01-01T00:00:00.000000Z" and stor["last_removal"] == "2024-01-01T02:00:00.000000Z"
    assert stor["drive_letters"] == ["E:"] and stor["volume_label"] == "EVIDENCE_USB"
    usb = next(r for r in recs if r["source"] == "USB")
    assert usb["vid"] == "0781" and usb["pid"] == "5567"


def test_run_keys_installed_apps_services():
    sw = MemoryKey("SOFTWARE")
    run = sw.add("Microsoft").add("Windows").add("CurrentVersion").add("Run", {"Updater": "C:\\Users\\a\\AppData\\Roaming\\u.exe"})
    assert run is not None
    sw.subkey("Microsoft\\Windows\\CurrentVersion").add("Uninstall").add("App1", {
        "DisplayName": "Example App", "DisplayVersion": "1.0", "Publisher": "Example Corp", "InstallDate": "20240115"})
    wl = sw.subkey("Microsoft").add("Windows NT").add("CurrentVersion").add("Winlogon", {"Shell": "explorer.exe, evil.exe",
                                                                                        "Userinit": "C:\\Windows\\system32\\userinit.exe,"})
    assert wl is not None
    entries = wra.parse_run_keys(sw, None)
    names = {e["name"]: e for e in entries}
    assert names["Updater"]["command"].endswith("u.exe")
    assert names["Shell"]["non_default"] is True and names["Userinit"]["non_default"] is False
    apps = wra.parse_installed_apps(sw, None)
    assert apps[0]["install_date"] == "2024-01-15" and apps[0]["publisher"] == "Example Corp"
    system = MemoryKey("SYSTEM")
    svc = system.add("ControlSet001").add("Services").add("EvilSvc", {"ImagePath": "C:\\Users\\Public\\svc.exe", "Start": 2, "Type": 16})
    svc.add("Parameters", {"ServiceDll": "C:\\x.dll"})
    s = wra.parse_services(system)[0]
    assert s["start_type"] == "automatic" and s["service_type"] == "own_process" and s["service_dll"] == "C:\\x.dll"


def test_amcache_inventory(tmp_path):
    b = HiveBuilder()
    f1 = b.key("0000abcd", [("LowerCaseLongPath", REG_SZ, sz("c:\\users\\a\\downloads\\tool.exe")), ("Name", REG_SZ, sz("tool.exe")),
                            ("FileId", REG_SZ, sz("0000" + "a" * 40)), ("Size", REG_SZ, sz("0x400")),
                            ("Publisher", REG_SZ, sz("unknown"))], last_write=filetime(99))
    inv = b.key("InventoryApplicationFile", subkeys=[f1])
    app = b.key("app1", [("Name", REG_SZ, sz("Example App")), ("Version", REG_SZ, sz("2.0"))])
    inva = b.key("InventoryApplication", subkeys=[app])
    rootk = b.key("Root", subkeys=[inv, inva])
    top = b.key("{root}", subkeys=[rootk], root=True)
    path = b.build(top, str(tmp_path / "Amcache.hve"))
    with Hive(path) as hive:
        data = wra.parse_amcache(hive.root())
    f = data["files"][0]
    assert f["sha1"] == "a" * 40 and f["size"] == 1024 and f["key_last_write"] == "2024-01-01T00:01:39.000000Z"
    assert data["applications"][0]["name"] == "Example App"


def test_recentdocs_and_runmru():
    nt = MemoryKey("NTUSER")
    exp = nt.add("Software").add("Microsoft").add("Windows").add("CurrentVersion").add("Explorer")
    rd = exp.add("RecentDocs", {"MRUListEx": RegValue("MRUListEx", REG_BINARY, struct.pack("<iii", 1, 0, -1))},
                 last_write="2024-02-01T00:00:00.000000Z")
    rd._values.append(RegValue("0", REG_BINARY, "old.docx\x00".encode("utf-16-le") + b"\x00" * 4))
    rd._values.append(RegValue("1", REG_BINARY, "تقرير.pdf\x00".encode("utf-16-le") + b"\x00" * 4))
    exp.add("RunMRU", {"a": "cmd\\1", "b": "powershell -enc AAAA\\1", "MRUList": "ba"}, last_write="2024-02-02T00:00:00.000000Z")
    docs = wra.parse_recentdocs(nt, "u")
    newest = next(d for d in docs if d["mru_position"] == 0)
    assert newest["name"] == "تقرير.pdf" and newest["opened_utc"] == "2024-02-01T00:00:00.000000Z"
    mru = wra.parse_run_mru(nt, "u")
    assert {m["value"] for m in mru} == {"cmd", "powershell -enc AAAA"}
    assert next(m for m in mru if m["mru_position"] == 0)["value"] == "powershell -enc AAAA"
