"""End-to-end collection: orchestrator, collectors on synthetic data, failure isolation, cancellation,
locked files and missing privileges."""

import json
import os
import threading

from builders import build_cfb, build_chrome_profile, build_destlist_v4, build_lnk, build_prefetch, build_recycle_i, filetime
from wezcrypt_ufk.analysis.data import SessionData
from wezcrypt_ufk.collectors import windows_activity
from wezcrypt_ufk.collectors.base import Collector, register
from wezcrypt_ufk.collectors.filesystem import RecycleBinCollector, parse_zone_identifier, suspicious_indicators
from wezcrypt_ufk.collectors.windows_activity import LnkFilesCollector, PrefetchCollector
from wezcrypt_ufk.core import acquire
from wezcrypt_ufk.core.acquire import AcquisitionError
from wezcrypt_ufk.core.integrity import verify_manifest
from wezcrypt_ufk.core.orchestrator import Orchestrator


@register
class _FailingCollector(Collector):
    name = "test_failing"
    title = "Test failing module"
    category = "Test"
    windows_only = False
    default_enabled = False

    def run(self, ctx):
        ctx.write_records("before_failure", [{"ok": True}])
        raise RuntimeError("simulated parser crash")


@register
class _SlowCollector(Collector):
    name = "test_slow"
    title = "Test slow module"
    category = "Test"
    windows_only = False
    default_enabled = False
    started = threading.Event()

    def run(self, ctx):
        _SlowCollector.started.set()
        for _ in range(500):
            ctx.check_cancel()
            ctx.cancel_event.wait(0.01)


def _populate_profile(home):
    build_chrome_profile(str(home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"))
    recent = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
    (recent / "AutomaticDestinations").mkdir(parents=True)
    (recent / "CustomDestinations").mkdir(parents=True)
    (recent / "تقرير.docx.lnk").write_bytes(build_lnk("E:\\تقارير\\تقرير.docx", drive_type=2, label="USB"))
    (recent / "AutomaticDestinations" / "5f7b5f1e01b83767.automaticDestinations-ms").write_bytes(
        build_cfb({"1": build_lnk("C:\\Users\\a\\Desktop\\plan.xlsx"), "DestList": build_destlist_v4([(1, "C:\\plan.xlsx", filetime(9), 2)])}))
    (recent / "CustomDestinations" / "5d696d521de238c3.customDestinations-ms").write_bytes(build_lnk("C:\\x.pdf"))
    dl = home / "Downloads"
    (dl / "invoice.pdf.exe").write_bytes(b"MZ" + b"\x00" * 200)
    (dl / "صورة.jpg").write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)
    (dl / "notes.txt").write_text("synthetic", encoding="utf-8")


def test_full_orchestrated_collection(fake_home, tmp_path, config):
    _populate_profile(fake_home)
    config.fs_scan_paths = [str(fake_home / "Downloads")]
    out = tmp_path / "USB" / "WezCrypt_Cases"
    events = []
    orch = Orchestrator(config, ["system_info", "processes", "network", "browser_chrome", "lnk_files", "jump_lists",
                                 "filesystem", "test_failing", "prefetch"],
                        case_id="E2E", examiner="Tester", notes="authorised test", output_root=str(out),
                        status_cb=lambda e, d: events.append(e), report_formats=["html", "json", "csv"])
    session = orch.run()
    assert session.status == "completed"
    res = session.module_results
    assert res["test_failing"]["status"] == "failed" and "simulated parser crash" in res["test_failing"]["message"]
    assert res["browser_chrome"]["status"] in ("completed", "partial") and res["browser_chrome"]["files_acquired"] >= 3
    if not os.name == "nt":
        assert res["prefetch"]["status"] == "skipped"
    assert "module_finished" in events and "session_finished" in events
    data = SessionData(session.session_dir)
    lnk = data.all("lnk_files", "lnk_files")
    assert lnk[0]["drive_type"] == "removable" and lnk[0]["target_path"] == "E:\\تقارير\\تقرير.docx"
    jl = data.all("jump_lists", "jump_lists")
    assert {j["jumplist_type"] for j in jl} == {"AutomaticDestinations", "CustomDestinations"}
    files = {os.path.basename(f["path"]): f for f in data.all("filesystem", "files")}
    assert "صورة.jpg" in files and "double_extension" in files["invoice.pdf.exe"]["indicators"]
    import hashlib

    assert files["notes.txt"]["sha256"] == hashlib.sha256("synthetic".encode()).hexdigest()
    assert data.all("test_failing", "before_failure") == [{"ok": True}]
    # integrity & custody
    assert session.stats["post_collection_verification"]["passed"]
    assert verify_manifest(session.session_dir).passed
    custody = [json.loads(l)["action"] for l in open(os.path.join(session.session_dir, "chain_of_custody.jsonl"), encoding="utf-8")]
    assert custody[0] == "session_created" and "evidence_manifest_created" in custody and custody[-1] == "session_closed"
    errors = json.load(open(os.path.join(session.session_dir, "logs", "errors.json"), encoding="utf-8"))
    assert any(e["module"] == "test_failing" for e in errors)
    report = open(os.path.join(session.session_dir, "reports", "report.html"), encoding="utf-8").read()
    assert "E2E" in report and "authorised test" in report
    # tampering after collection is detected
    hist = next(p for p in (os.path.join(r, f) for r, _, fs in os.walk(os.path.join(session.session_dir, "evidence")) for f in fs)
                if p.endswith("History"))
    with open(hist, "ab") as fh:
        fh.write(b"x")
    assert not verify_manifest(session.session_dir).passed


def test_cancellation_is_safe(tmp_path, config):
    orch = Orchestrator(config, ["test_slow"], output_root=str(tmp_path / "out"), report_formats=[])
    _SlowCollector.started.clear()
    t = threading.Thread(target=lambda: setattr(orch, "_session", orch.run()))
    t.start()
    assert _SlowCollector.started.wait(10)
    orch.cancel()
    t.join(20)
    assert not t.is_alive()
    session = orch._session
    assert session.status == "cancelled" and session.module_results["test_slow"]["status"] == "cancelled"
    assert os.path.isfile(os.path.join(session.session_dir, "manifest.json"))  # what was collected is still hashed


def test_locked_file_recorded_and_module_continues(make_ctx, tmp_path, monkeypatch, fake_home):
    (fake_home / "Desktop" / "a.lnk").write_bytes(build_lnk("C:\\a.txt"))
    (fake_home / "Desktop" / "b.lnk").write_bytes(build_lnk("C:\\b.txt"))
    real = acquire._open_source

    def flaky(path):
        if path.endswith("a.lnk"):
            raise AcquisitionError("The process cannot access the file because it is being used by another process", "locked", path)
        return real(path)

    monkeypatch.setattr(acquire, "_open_source", flaky)
    ctx = make_ctx("lnk_files")
    LnkFilesCollector().run(ctx)
    ctx.close()
    errs = [e for e in make_ctx.shared.errors if e.kind == "locked"]
    assert len(errs) == 1 and errs[0].path.endswith("a.lnk")
    recs = SessionData(ctx.session.session_dir).all("lnk_files", "lnk_files")
    assert [r["lnk_file"] for r in recs] == ["b.lnk"]


def test_prefetch_collector_with_and_without_admin(make_ctx, tmp_path, monkeypatch):
    windows = tmp_path / "Windows"
    pf = windows / "Prefetch"
    pf.mkdir(parents=True)
    monkeypatch.setenv("SystemRoot", str(windows))
    monkeypatch.setattr(windows_activity, "is_admin", lambda: False)
    ctx = make_ctx("prefetch")
    PrefetchCollector().run(ctx)
    assert any(e.kind == "requires_admin" for e in make_ctx.shared.errors)
    (pf / "TOOL.EXE-1A2B3C4D.pf").write_bytes(build_prefetch("TOOL.EXE", 3, [filetime(60)], ["\\VOLUME{1}\\TEMP\\TOOL.EXE"]))
    (pf / "BROKEN.EXE-00000000.pf").write_bytes(b"garbage" * 30)
    monkeypatch.setattr(windows_activity, "is_admin", lambda: True)
    ctx2 = make_ctx("prefetch")
    PrefetchCollector().run(ctx2)
    ctx2.close()
    recs = SessionData(ctx2.session.session_dir).all("prefetch", "prefetch")
    assert len(recs) == 1 and recs[0]["run_count"] == 3 and len(recs[0]["file_sha256"]) == 64
    assert any("BROKEN" in (e.path or "") for e in make_ctx.shared.errors)
    assert ctx2.files_acquired == 2  # both files preserved as evidence even if one cannot be parsed


def test_recycle_bin_collector(make_ctx, tmp_path, monkeypatch):
    import psutil

    drive = tmp_path / "C"
    rb = drive / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
    rb.mkdir(parents=True)
    (rb / "$IABC123.docx").write_bytes(build_recycle_i("C:\\Users\\a\\سري.docx", 999, filetime(5)))
    (rb / "$RABC123.docx").write_bytes(b"x" * 999)

    class P:
        mountpoint, opts = str(drive), "rw,fixed"

    monkeypatch.setattr(psutil, "disk_partitions", lambda all=False: [P()])
    ctx = make_ctx("recycle_bin")
    RecycleBinCollector().run(ctx)
    ctx.close()
    rec = SessionData(ctx.session.session_dir).all("recycle_bin", "recycle_bin")[0]
    assert rec["original_path"] == "C:\\Users\\a\\سري.docx" and rec["r_file_present"] and rec["r_file_size"] == 999


def test_suspicious_indicator_logic():
    rec = {"pe": {"packed_suspected": True}, "signature": {"status": "NotSigned"}, "zone_identifier": {"zone_id": 3},
           "alternate_streams": [{"name": "Zone.Identifier", "size": 26}, {"name": "hidden_payload", "size": 4000}]}
    ind = suspicious_indicators("C:\\Users\\a\\Downloads\\cv.docx\u202eexe.scr", rec)
    assert {"rtlo_character_in_name", "unsigned_executable", "high_entropy_or_packed", "downloaded_from_internet",
            "non_standard_alternate_data_stream"} <= set(ind)
    assert suspicious_indicators("C:\\Docs\\notes.txt", {"alternate_streams": []}) == []
    z = parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.org/a.exe\r\n")
    assert z == {"zone_id": 3, "referrer_url": None, "host_url": "https://example.org/a.exe"}


def test_event_log_collector_with_simulated_wevtutil(make_ctx, monkeypatch):
    """Drives the EVTX module end to end with a stand-in for wevtutil (export + XPath query)."""
    from builders import event_xml
    from wezcrypt_ufk.core import commands

    calls = []

    def fake_run(args, timeout=120, encoding=None, stdout_path=None):
        calls.append(args)
        if args[1] == "epl":
            if args[2] == "Microsoft-Windows-Sysmon/Operational":
                return commands.CommandResult(args, 15007, "", "channel not found")
            if args[2] == "Security":
                return commands.CommandResult(args, 5, "", "Access is denied.")
            with open(args[3], "wb") as fh:
                fh.write(b"ElfFile\x00" + b"\x00" * 100)
            return commands.CommandResult(args, 0, "", "")
        query = args[-1]
        xml = ""
        if "System" in args[2] and "EventID=7045" in query:
            xml = event_xml(7045, "2024-05-01T08:00:00.000Z", {"ServiceName": "svc", "ImagePath": "C:\\Windows\\Temp\\s.exe"},
                            "System", "Service Control Manager")
        with open(stdout_path, "w", encoding="utf-8") as fh:
            fh.write(xml)
        return commands.CommandResult(args, 0, "", "")

    monkeypatch.setattr(commands, "run", fake_run)
    monkeypatch.setattr(windows_activity, "is_admin", lambda: False)
    ctx = make_ctx("event_logs")
    windows_activity.EventLogsCollector().run(ctx)
    ctx.close()
    assert all(len(a[-1].split(" or ")) <= windows_activity.QUERY_BATCH for a in calls if a[1] == "qe")
    rec = SessionData(ctx.session.session_dir).all("event_logs", "events_system")
    assert len(rec) == 1 and rec[0]["event_type"] == "service_installed" and "s.exe" in rec[0]["description"]
    kinds = {e.path: e.kind for e in make_ctx.shared.errors}
    assert kinds["Security"] == "requires_admin" and "Microsoft-Windows-Sysmon/Operational" not in kinds
    assert ctx.files_acquired == len(windows_activity.CHANNELS) - 2
