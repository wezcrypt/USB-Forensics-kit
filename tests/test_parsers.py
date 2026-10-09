"""File-format parsers: LNK, Prefetch, Jump Lists, Recycle Bin, Windows event XML, setupapi, tasks, PE."""

import struct

import pytest

from builders import (build_cfb, build_destlist_v4, build_lnk, build_prefetch, build_recycle_i, event_xml, filetime)
from wezcrypt_ufk.parsers.evtx_xml import iter_events, iter_events_file
from wezcrypt_ufk.parsers.jumplist import (CFBError, CompoundFile, app_id_from_filename, parse_automatic_destinations,
                                           parse_custom_destinations)
from wezcrypt_ufk.parsers.lnk import LnkError, parse_lnk
from wezcrypt_ufk.parsers.pe import entropy, parse_pe
from wezcrypt_ufk.parsers.prefetch import PrefetchError, parse_prefetch
from wezcrypt_ufk.parsers.recyclebin import RecycleBinError, parse_recycle_i
from wezcrypt_ufk.parsers.setupapi import parse_setupapi
from wezcrypt_ufk.parsers.tasks import parse_task_xml, split_schtasks_xml


def test_lnk_full_structure():
    data = build_lnk("C:\\Users\\analyst\\Documents\\تقرير.docx", arguments="/safe", working_dir="C:\\Users\\analyst",
                     drive_type=2, label="USBDISK")
    rec = parse_lnk(data)
    assert rec["local_path"].startswith("C:\\Users\\analyst\\Documents\\")
    assert rec["drive_type"] == "removable" and rec["volume_serial"] == "A1B2C3D4" and rec["volume_label"] == "USBDISK"
    assert rec["arguments"] == "/safe" and rec["working_dir"] == "C:\\Users\\analyst"
    assert rec["target_created"] == "2024-01-01T00:00:00.000000Z" and rec["target_modified"] == "2024-01-01T00:02:00.000000Z"
    assert rec["machine_id"] == "WS-TEST01" and rec["droid_mac"] == "00:11:22:33:44:55"
    assert rec["idlist_path"].endswith("تقرير.docx")


def test_lnk_rejects_garbage():
    with pytest.raises(LnkError):
        parse_lnk(b"MZ" + b"\x00" * 200)


@pytest.mark.parametrize("version", [17, 23, 26, 30])
def test_prefetch_versions(version):
    times = [filetime(3600 * i) for i in range(3, 0, -1)]
    data = build_prefetch("MALWARE.EXE", 12, times, ["\\VOLUME{01}\\WINDOWS\\SYSTEM32\\NTDLL.DLL",
                                                      "\\VOLUME{01}\\USERS\\A\\DOWNLOADS\\MALWARE.EXE"], version=version)
    rec = parse_prefetch(data)
    assert rec["executable"] == "MALWARE.EXE" and rec["run_count"] == 12 and rec["format_version"] == version
    assert rec["last_run"] == "2024-01-01T03:00:00.000000Z"
    assert len(rec["run_times"]) == (3 if version >= 26 else 1)
    assert rec["executable_path"].endswith("\\DOWNLOADS\\MALWARE.EXE")
    assert rec["volumes"][0]["serial"] == "1234ABCD" and rec["volumes"][0]["device_path"] == "\\VOLUME{01d9aaaa-1234}"


def test_prefetch_mam_compressed_uses_system_decompressor():
    raw = build_prefetch("CALC.EXE", 1, [filetime()], ["X"])
    mam = b"MAM\x04" + struct.pack("<I", len(raw)) + b"compressed-payload"
    seen = {}

    def fake(payload, size):
        seen["args"] = (payload, size)
        return raw

    assert parse_prefetch(mam, decompressor=fake)["executable"] == "CALC.EXE"
    assert seen["args"] == (b"compressed-payload", len(raw))

    def failing(payload, size):
        raise OSError("ntdll unavailable")

    with pytest.raises(PrefetchError):
        parse_prefetch(mam, decompressor=failing)


def test_jumplist_automatic_destinations_with_destlist():
    lnk1 = build_lnk("C:\\Users\\a\\Desktop\\plan.xlsx")
    lnk2 = build_lnk("E:\\secret\\export.zip", drive_type=2)
    big = build_lnk("C:\\big.bin") + b"\x00" * 5000  # forces a regular (non-mini) stream
    dest = build_destlist_v4([(1, "C:\\Users\\a\\Desktop\\plan.xlsx", filetime(100), 4),
                              (2, "E:\\secret\\export.zip", filetime(200), 1)])
    data = build_cfb({"1": lnk1, "2": lnk2, "3": big, "DestList": dest})
    cf = CompoundFile(data)
    assert set(cf.streams()) == {"1", "2", "3", "DestList"}
    entries = {e["stream"]: e for e in parse_automatic_destinations(data)}
    assert entries["2"]["drive_type"] == "removable" and entries["2"]["last_used"] == "2024-01-01T00:03:20.000000Z"
    assert entries["1"]["access_count"] == 4 and entries["1"]["hostname"] == "WS-TEST01"
    assert entries["3"]["local_path"] == "C:\\big.bin"
    with pytest.raises(CFBError):
        CompoundFile(b"not a compound file" * 40)


def test_jumplist_custom_destinations_and_appid():
    blob = b"\xab\xfb\xbf\xba" + build_lnk("C:\\a.txt") + b"\x00" * 10 + build_lnk("C:\\b.txt") + b"\xab\xfb\xbf\xba"
    recs = parse_custom_destinations(blob)
    assert [r["local_path"] for r in recs] == ["C:\\a.txt", "C:\\b.txt"]
    assert app_id_from_filename("5d696d521de238c3.customDestinations-ms")["app_hint"] == "Google Chrome"
    assert app_id_from_filename("ffffffffffffffff.automaticDestinations-ms")["app_hint"] is None


@pytest.mark.parametrize("version", [1, 2])
def test_recycle_bin_i_files(version):
    rec = parse_recycle_i(build_recycle_i("C:\\Users\\a\\Documents\\مستند.docx", 4096, filetime(42), version))
    assert rec["original_path"] == "C:\\Users\\a\\Documents\\مستند.docx" and rec["original_size"] == 4096
    assert rec["deleted_utc"] == "2024-01-01T00:00:42.000000Z"
    with pytest.raises(RecycleBinError):
        parse_recycle_i(b"\x09" + b"\x00" * 40)


def test_event_xml_streaming_parser_and_fractional_time(tmp_path):
    xml = event_xml(4625, "2024-03-01T10:00:00.1234567Z", {"TargetUserName": "admin", "IpAddress": "203.0.113.5",
                                                            "LogonType": "3", "SubStatus": "0xc000006a"})
    xml += event_xml(4104, "2024-03-01T10:05:00.000Z", {"ScriptBlockText": "x" * 50}, "Microsoft-Windows-PowerShell/Operational",
                     "Microsoft-Windows-PowerShell", 2)
    chunks = [xml[i:i + 37] for i in range(0, len(xml), 37)]  # split mid-tag to test incremental parsing
    events = list(iter_events(chunks, max_field_chars=20))
    assert events[0]["event_id"] == 4625 and events[0]["time_created"] == "2024-03-01T10:00:00.123456Z"
    assert events[0]["data"]["IpAddress"] == "203.0.113.5" and events[0]["user_sid"] == "S-1-5-18"
    assert events[1]["data"]["ScriptBlockText"].startswith("x" * 20 + "...[truncated 30")
    path = tmp_path / "events.xml"
    path.write_text(xml, encoding="utf-16")
    assert [e["event_id"] for e in iter_events_file(str(path))] == [4625, 4104]


def test_setupapi_parser():
    lines = [
        ">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C5300012301&0]",
        ">>>  Section start 2024/01/05 09:15:30.123",
        ">>>  [Device Install (Hardware initiated) - PCI\\VEN_8086]",
        ">>>  Section start 2024/01/05 09:16:00.000",
    ]
    recs = parse_setupapi(lines)
    assert len(recs) == 1 and recs[0]["serial"] == "4C5300012301" and recs[0]["first_install_local"] == "2024-01-05T09:15:30.123"


TASK = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>2024-02-03T04:05:06</Date><Author>WS\\attacker</Author><URI>\\Updater</URI></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>C:\\Users\\Public\\upd.exe</Command><Arguments>-silent</Arguments></Exec></Actions>
</Task>"""


def test_task_xml_parser():
    t = parse_task_xml(TASK)
    assert t["name"] == "\\Updater" and t["hidden"] and t["run_level"] == "HighestAvailable"
    assert t["command_line"] == "C:\\Users\\Public\\upd.exe -silent" and t["triggers"][0]["type"] == "LogonTrigger"
    assert t["registration_date"] == "2024-02-03T04:05:06.000000Z"
    combined = "<Tasks><!-- \\Updater -->\n" + TASK.split("?>", 1)[1] + "</Tasks>"
    assert split_schtasks_xml(combined)[0][0] == "\\Updater"


def _minimal_pe(path, high_entropy=False):
    import os

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 64)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 1700000000, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<HH", opt, 68, 3, 0x0140)
    raw = os.urandom(2048) if high_entropy else b"\x90" * 2048
    sec = b".text\x00\x00\x00" + struct.pack("<IIII", 2048, 0x1000, 2048, 64 + 4 + 20 + 240 + 40) + b"\x00" * 12 + struct.pack("<I", 0x60000020)
    with open(path, "wb") as fh:
        fh.write(bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec + raw)


def test_pe_parser(tmp_path):
    p = tmp_path / "a.exe"
    _minimal_pe(p)
    info = parse_pe(str(p))
    assert info["machine"] == "x64" and info["subsystem"] == "windows_cui" and info["aslr"] and info["dep"]
    assert info["compile_time"] == "2023-11-14T22:13:20.000000Z" and not info["packed_suspected"]
    _minimal_pe(tmp_path / "b.exe", high_entropy=True)
    assert parse_pe(str(tmp_path / "b.exe"))["packed_suspected"]
    (tmp_path / "c.txt").write_text("hello")
    assert parse_pe(str(tmp_path / "c.txt")) is None
    assert entropy(b"") == 0 and round(entropy(bytes(range(256))), 3) == 8.0
