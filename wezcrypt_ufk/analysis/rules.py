"""Detection rules. Each rule reads parsed artifacts and returns evidence-backed findings.

Principles: a finding cites the records it is based on; severity reflects the strength of the indicator;
wording says "suspicious"/"review" unless the evidence itself is conclusive (e.g. an AV detection).
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict
from datetime import timedelta
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ..core.config import Config
from ..core.models import Finding
from ..core.timeutil import parse_iso
from .data import SessionData

MAX_EVIDENCE = 25

USER_WRITABLE = re.compile(r"(\\users\\[^\\]+\\(downloads|desktop|documents|appdata\\local\\temp|appdata\\roaming|appdata\\local)\\"
                           r"|\\windows\\temp\\|\\users\\public\\|\\programdata\\[^\\]+\.(exe|dll|ps1|bat|vbs)|\\\$recycle\.bin\\|\\perflogs\\)",
                           re.I)

SUSPICIOUS_CMD: List[Tuple[str, str, str, str]] = [
    # (id, regex, severity, label)
    ("ps_encoded", r"(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "high",
     "PowerShell with encoded command"),
    ("ps_download_exec", r"(downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|start-bitstransfer).*(iex|invoke-expression|\|\s*iex)"
     r"|(iex|invoke-expression)\s*\(?\s*\(?\s*new-object\s+net\.webclient", "high", "PowerShell download-and-execute"),
    ("ps_hidden", r"(powershell|pwsh)(\.exe)?\b.*-(w|wi|win|windowstyle)\s+(h|hidden)\b.*-(nop|noprofile|ep|executionpolicy)", "medium",
     "Hidden PowerShell window with policy/profile bypass"),
    ("certutil_download", r"certutil(\.exe)?\b.*(-urlcache|-verifyctl|-decode\b|-decodehex)", "high", "certutil used to download/decode"),
    ("mshta_remote", r"mshta(\.exe)?\b.*(https?:|javascript:|vbscript:)", "high", "mshta executing remote/inline script"),
    ("rundll32_script", r"rundll32(\.exe)?\b.*(javascript:|vbscript:|mshtml,runhtmlapplication)", "high", "rundll32 script execution"),
    ("regsvr32_squiblydoo", r"regsvr32(\.exe)?\b.*/i:\s*https?:.*scrobj", "high", "regsvr32 remote scriptlet (Squiblydoo)"),
    ("bitsadmin_transfer", r"bitsadmin(\.exe)?\b.*/(transfer|addfile)\b", "medium", "bitsadmin file transfer"),
    ("wmic_process_create", r"wmic(\.exe)?\b.*process\s+call\s+create", "medium", "WMIC remote/indirect process creation"),
    ("shadow_delete", r"(vssadmin(\.exe)?\b.*delete\s+shadows|wmic(\.exe)?\b.*shadowcopy\s+delete|wbadmin(\.exe)?\b.*delete\s+catalog"
     r"|bcdedit(\.exe)?\b.*recoveryenabled\s+no)", "critical", "Backup / shadow copy destruction (ransomware precursor)"),
    ("user_add", r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S*\s*/add\b", "high", "Local user account created via net.exe"),
    ("admin_group_add", r"\bnet1?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add\b", "high", "Account added to Administrators via net.exe"),
    ("credential_tool", r"(mimikatz|sekurlsa::|lsadump::|invoke-mimikatz|procdump(64)?(\.exe)?\b.*\blsass|comsvcs(\.dll)?,\s*minidump)",
     "critical", "Credential dumping tool or technique"),
    ("defender_tamper", r"set-mppreference\b.*-(disablerealtimemonitoring|disableioavprotection|exclusionpath|exclusionprocess)", "high",
     "Microsoft Defender settings tampering"),
    ("log_clear_cmd", r"(wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog\b)", "high", "Event log clearing command"),
]

SYSTEM_BINARIES = {
    "svchost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "lsass.exe": ["\\windows\\system32\\"],
    "csrss.exe": ["\\windows\\system32\\"],
    "services.exe": ["\\windows\\system32\\"],
    "winlogon.exe": ["\\windows\\system32\\"],
    "smss.exe": ["\\windows\\system32\\"],
    "wininit.exe": ["\\windows\\system32\\"],
    "spoolsv.exe": ["\\windows\\system32\\"],
    "taskhostw.exe": ["\\windows\\system32\\"],
    "explorer.exe": ["\\windows\\"],
    "lsm.exe": ["\\windows\\system32\\"],
    "dllhost.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
    "conhost.exe": ["\\windows\\system32\\"],
    "rundll32.exe": ["\\windows\\system32\\", "\\windows\\syswow64\\"],
}
EXPECTED_PARENTS = {"lsass.exe": {"wininit.exe"}, "services.exe": {"wininit.exe"}, "svchost.exe": {"services.exe", "msmpeng.exe"},
                    "wininit.exe": {"smss.exe", None}, "taskhostw.exe": {"svchost.exe"}}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 12345, 5555, 9001, 1080}
EXEC_EXT = (".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".msi", ".jar", ".iso", ".img", ".lnk", ".com", ".pif")


def _ev(source: str, **fields) -> Dict:
    return {"source": source, **{k: v for k, v in fields.items() if v not in (None, "", [], {})}}


def _span(times: Iterable[Optional[str]]) -> Tuple[Optional[str], Optional[str]]:
    ts = sorted(t for t in times if t)
    return (ts[0], ts[-1]) if ts else (None, None)


def is_user_writable(path: Optional[str]) -> bool:
    return bool(path) and bool(USER_WRITABLE.search(path.replace("/", "\\")))


def is_public_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


class RuleContext:
    def __init__(self, data: SessionData, config: Config, iocs: Optional[Dict[str, set]] = None):
        self.data = data
        self.config = config
        self.iocs = iocs or {}
        self._cache: Dict[Tuple[str, str], List[Dict]] = {}

    def get(self, module: str, artifact: str) -> List[Dict]:
        key = (module, artifact)
        if key not in self._cache:
            self._cache[key] = self.data.all(module, artifact)
        return self._cache[key]

    def events(self, channel_key: str, ids: Iterable[int]) -> List[Dict]:
        idset = set(ids)
        return [r for r in self.get("event_logs", f"events_{channel_key}") if r.get("event_id") in idset]

    def browser(self, artifact: str) -> List[Dict]:
        out = []
        for m in self.data.modules():
            if m.startswith("browser_"):
                out.extend(self.get(m, artifact))
        return out


Rule = Callable[[RuleContext], List[Finding]]
RULES: List[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


# ----------------------------------------------------------------------------- event log rules


@rule
def log_cleared(rc: RuleContext) -> List[Finding]:
    evs = rc.events("security", [1102]) + rc.events("system", [104])
    if not evs:
        return []
    first, last = _span(e.get("time_created") for e in evs)
    return [Finding(
        "LOG-001", "Event log cleared", "high", "Defense Evasion",
        f"{len(evs)} event log clearing event(s) recorded. Log clearing removes evidence and is a common anti-forensic step; "
        "confirm whether it was authorised maintenance.",
        [_ev(f"EventLog {e.get('channel')} ID {e.get('event_id')}", time=e.get("time_created"), record_id=e.get("record_id"),
             detail=e.get("description")) for e in evs[:MAX_EVIDENCE]],
        first, last, ["T1070.001"], "Identify the account that cleared the log and correlate with logons at that time; "
        "recover older events from backups/SIEM.", "high")]


@rule
def failed_logons(rc: RuleContext) -> List[Finding]:
    fails = rc.events("security", [4625])
    if not fails:
        return []
    out: List[Finding] = []
    groups: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    for e in fails:
        d = e.get("data") or {}
        groups[(d.get("TargetUserName") or "?", d.get("IpAddress") or "-")].append(e)
    successes = rc.events("security", [4624])
    window = timedelta(minutes=rc.config.failed_logon_window_minutes)
    threshold = rc.config.failed_logon_threshold
    for (user, ip), evs in groups.items():
        times = sorted(t for t in (parse_iso(e.get("time_created")) for e in evs) if t)
        burst = 0
        j = 0
        for i in range(len(times)):
            while times[i] - times[j] > window:
                j += 1
            burst = max(burst, i - j + 1)
        if burst < threshold:
            continue
        later_success = [s for s in successes
                         if (s.get("data") or {}).get("TargetUserName", "").lower() == user.lower()
                         and ((s.get("data") or {}).get("IpAddress") or "-") == ip
                         and s.get("time_created") and times and s["time_created"] >= evs[-1].get("time_created", "")]
        sev = "high" if later_success else "medium"
        desc = (f"{len(evs)} failed logons for '{user}' from {ip} (peak {burst} within "
                f"{rc.config.failed_logon_window_minutes} min) - consistent with password guessing.")
        if later_success:
            desc += f" A successful logon for the same account from the same source followed ({later_success[0].get('time_created')})."
        first, last = _span(e.get("time_created") for e in evs)
        out.append(Finding("AUTH-001", f"Repeated failed logons: {user} from {ip}", sev, "Credential Access", desc,
                           [_ev("Security 4625", time=e.get("time_created"), record_id=e.get("record_id"), detail=e.get("description"))
                            for e in evs[:MAX_EVIDENCE]] +
                           [_ev("Security 4624", time=s.get("time_created"), record_id=s.get("record_id"), detail=s.get("description"))
                            for s in later_success[:5]],
                           first, last, ["T1110"], "Verify whether the source is legitimate; review account lockout policy and "
                           "subsequent activity of the account.", "high" if later_success else "medium"))
    total = len(fails)
    first, last = _span(e.get("time_created") for e in fails)
    out.append(Finding("AUTH-000", "Failed logon summary", "info", "Credential Access",
                       f"{total} failed logon events across {len(groups)} account/source pairs.",
                       [_ev("Security 4625", account=u, source_ip=ip, count=len(v)) for (u, ip), v in
                        sorted(groups.items(), key=lambda kv: -len(kv[1]))[:MAX_EVIDENCE]],
                       first, last, ["T1110"], "", "high"))
    return out


@rule
def remote_logons(rc: RuleContext) -> List[Finding]:
    evs = [e for e in rc.events("security", [4624]) if (e.get("data") or {}).get("LogonType") == "10"]
    evs += rc.events("rdp_rcm", [1149])
    evs += rc.events("rdp_lsm", [21, 25])
    if not evs:
        return []
    public = [e for e in evs if is_public_ip((e.get("data") or {}).get("IpAddress") or (e.get("data") or {}).get("Address")
                                             or (e.get("data") or {}).get("Param3"))]
    first, last = _span(e.get("time_created") for e in evs)
    sev = "medium" if public else "info"
    return [Finding("AUTH-002", "Remote Desktop logons", sev, "Lateral Movement",
                    f"{len(evs)} RDP logon/authentication events; {len(public)} from public IP addresses.",
                    [_ev(f"{e.get('channel')} {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description"))
                     for e in (public or evs)[:MAX_EVIDENCE]], first, last, ["T1021.001"],
                    "Confirm RDP sessions are expected; restrict RDP exposure (VPN/NLA/MFA)." if public else "", "high")]


@rule
def account_changes(rc: RuleContext) -> List[Finding]:
    out = []
    created = rc.events("security", [4720])
    if created:
        first, last = _span(e.get("time_created") for e in created)
        out.append(Finding("ACCT-001", "User account(s) created", "medium", "Persistence",
                           f"{len(created)} local/domain account creation event(s).",
                           [_ev("Security 4720", time=e.get("time_created"), detail=e.get("description")) for e in created[:MAX_EVIDENCE]],
                           first, last, ["T1136.001"], "Validate each new account against change records; disable unknown accounts.", "high"))
    added = [e for e in rc.events("security", [4732, 4728, 4756])
             if ((e.get("data") or {}).get("TargetUserName", "").lower() in ("administrators", "domain admins", "enterprise admins")
                 or (e.get("data") or {}).get("TargetSid") == "S-1-5-32-544")]
    if added:
        first, last = _span(e.get("time_created") for e in added)
        out.append(Finding("ACCT-002", "Member added to privileged group", "high", "Privilege Escalation",
                           f"{len(added)} addition(s) to Administrators/Domain Admins.",
                           [_ev(f"Security {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in added[:MAX_EVIDENCE]],
                           first, last, ["T1098"], "Confirm the change was authorised; review the actor account's activity.", "high"))
    return out


@rule
def service_installs(rc: RuleContext) -> List[Finding]:
    evs = rc.events("system", [7045]) + rc.events("security", [4697])
    if not evs:
        return []
    suspicious, normal = [], []
    for e in evs:
        d = e.get("data") or {}
        path = d.get("ImagePath") or d.get("ServiceFileName") or ""
        if is_user_writable(path) or _match_cmd(path) or re.search(r"(cmd(\.exe)?\s+/c|%comspec%|\\\\[^\\]+\\(admin|c)\$)", path, re.I):
            suspicious.append(e)
        else:
            normal.append(e)
    out = []
    if suspicious:
        first, last = _span(e.get("time_created") for e in suspicious)
        out.append(Finding("PERS-001", "Suspicious service installation", "high", "Persistence",
                           f"{len(suspicious)} service(s) installed with a binary in a user-writable location, a command shell "
                           "or an admin share path (pattern used by PsExec-style lateral movement and malware).",
                           [_ev(f"EventLog {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in suspicious[:MAX_EVIDENCE]],
                           first, last, ["T1543.003", "T1569.002"], "Acquire the service binary, check its hash/signature and "
                           "identify the installing account.", "medium"))
    if normal:
        first, last = _span(e.get("time_created") for e in normal)
        out.append(Finding("PERS-000", "Service installations", "info", "Persistence",
                           f"{len(normal)} service installation event(s) with binaries in standard locations.",
                           [_ev(f"EventLog {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in normal[:MAX_EVIDENCE]],
                           first, last, ["T1543.003"], "", "high"))
    return out


@rule
def defender_events(rc: RuleContext) -> List[Finding]:
    out = []
    det = rc.events("defender", [1006, 1116, 1117, 1007, 1008, 1118, 1119])
    if det:
        first, last = _span(e.get("time_created") for e in det)
        out.append(Finding("AV-001", "Microsoft Defender malware detections", "high", "Execution",
                           f"{len(det)} Defender detection/remediation event(s).",
                           [_ev(f"Defender {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in det[:MAX_EVIDENCE]],
                           first, last, [], "Review each detected path; check whether remediation succeeded (1117) or failed (1118/1119).", "high"))
    off = rc.events("defender", [5001, 5010, 5012])
    if off:
        first, last = _span(e.get("time_created") for e in off)
        out.append(Finding("AV-002", "Microsoft Defender protection disabled", "medium", "Defense Evasion",
                           f"{len(off)} event(s) show real-time protection or scanning being disabled.",
                           [_ev(f"Defender {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in off[:MAX_EVIDENCE]],
                           first, last, ["T1562.001"], "Determine who disabled protection and whether it was policy-driven.", "high"))
    return out


# ----------------------------------------------------------------------------- command lines


def _match_cmd(text: str) -> List[Tuple[str, str, str]]:
    hits = []
    for rid, pattern, sev, label in SUSPICIOUS_CMD:
        if re.search(pattern, text or "", re.I | re.S):
            hits.append((rid, sev, label))
    return hits


@rule
def suspicious_command_lines(rc: RuleContext) -> List[Finding]:
    sources: List[Tuple[str, Optional[str], str]] = []
    for p in rc.get("processes", "processes"):
        if p.get("cmdline"):
            sources.append((f"Running process PID {p.get('pid')} ({p.get('name')})", p.get("create_time"), p["cmdline"]))
    for e in rc.events("security", [4688]):
        sources.append(("Security 4688", e.get("time_created"), (e.get("data") or {}).get("CommandLine", "")))
    for e in rc.events("sysmon", [1]):
        sources.append(("Sysmon 1", e.get("time_created"), (e.get("data") or {}).get("CommandLine", "")))
    for e in rc.events("powershell", [4104]):
        sources.append(("PowerShell 4104 script block", e.get("time_created"), (e.get("data") or {}).get("ScriptBlockText", "")))
    for t in rc.get("scheduled_tasks", "scheduled_tasks"):
        sources.append((f"Scheduled task {t.get('name')}", t.get("registration_date"), t.get("command_line") or ""))
    for s in rc.get("startup_programs", "startup_entries"):
        sources.append((f"Startup {s.get('location')}\\{s.get('name')}", s.get("key_last_write"), str(s.get("command") or "")))
    for s in rc.get("services", "services"):
        sources.append((f"Service {s.get('name')}", s.get("key_last_write"), str(s.get("image_path") or "")))
    by_rule: Dict[str, List[Dict]] = defaultdict(list)
    meta: Dict[str, Tuple[str, str]] = {}
    for src, ts, text in sources:
        for rid, sev, label in _match_cmd(text):
            by_rule[rid].append(_ev(src, time=ts, command=text[:600]))
            meta[rid] = (sev, label)
    out = []
    for rid, evs in by_rule.items():
        sev, label = meta[rid]
        first, last = _span(e.get("time") for e in evs)
        out.append(Finding(f"CMD-{rid}", label, sev, "Execution",
                           f"{len(evs)} command line(s)/script(s) match the pattern '{label}'. Legitimate admin tools can "
                           "match; review the full command and its parent.",
                           evs[:MAX_EVIDENCE], first, last, ["T1059"], "Review the full command line, parent process and user; "
                           "decode encoded payloads offline.", "medium" if sev in ("medium",) else "high"))
    return out


# ----------------------------------------------------------------------------- processes & network


@rule
def process_anomalies(rc: RuleContext) -> List[Finding]:
    procs = rc.get("processes", "processes")
    if not procs:
        return []
    conns = rc.get("network", "connections")
    remote_by_pid: Dict[int, List[Dict]] = defaultdict(list)
    for c in conns:
        if c.get("remote_address") and c.get("pid") is not None:
            remote_by_pid[c["pid"]].append(c)
    out = []
    masq, writable = [], []
    for p in procs:
        name = (p.get("name") or "").lower()
        exe = (p.get("exe") or "")
        lexe = exe.lower()
        if name in SYSTEM_BINARIES and exe and not any(d in lexe for d in SYSTEM_BINARIES[name]):
            masq.append(_ev(f"PID {p.get('pid')}", name=p.get("name"), path=exe, parent=p.get("parent_name"),
                            started=p.get("create_time"), signer=p.get("signer")))
        parent = (p.get("parent_name") or "").lower() or None
        if name in EXPECTED_PARENTS and p.get("parent_name") is not None and parent not in EXPECTED_PARENTS[name]:
            masq.append(_ev(f"PID {p.get('pid')}", name=p.get("name"), path=exe, unexpected_parent=p.get("parent_name"),
                            started=p.get("create_time")))
        if exe and is_user_writable(exe):
            signed = p.get("signature_status") == "Valid"
            remote = remote_by_pid.get(p.get("pid"), [])
            writable.append((p, signed, remote))
    if masq:
        first, last = _span(e.get("started") for e in masq)
        out.append(Finding("PROC-001", "System process name in unexpected location or with unexpected parent", "high",
                           "Defense Evasion", f"{len(masq)} process(es) use a Windows system binary name but run from a "
                           "non-standard path or under an unexpected parent (process masquerading indicator).",
                           masq[:MAX_EVIDENCE], first, last, ["T1036.005"], "Hash and acquire the binary; compare with the "
                           "genuine system file.", "medium"))
    unsigned_net = [(p, r) for p, s, r in writable if not s and r]
    others = [(p, s) for p, s, r in writable if not (not s and r)]
    if unsigned_net:
        out.append(Finding("PROC-002", "Unsigned process from user-writable path with network connections", "high",
                           "Command and Control",
                           f"{len(unsigned_net)} process(es) running from user-writable folders, without a valid signature, "
                           "hold network connections to remote hosts.",
                           [_ev(f"PID {p.get('pid')}", name=p.get("name"), path=p.get("exe"), sha256=p.get("exe_sha256"),
                                signature=p.get("signature_status"), remotes=[f"{c['remote_address']}:{c['remote_port']}" for c in r][:10])
                            for p, r in unsigned_net[:MAX_EVIDENCE]],
                           *_span(p.get("create_time") for p, _ in unsigned_net), ["T1071"],
                           "Isolate the host if confirmed; look up the hash and remote addresses in threat intelligence.", "medium"))
    if others:
        out.append(Finding("PROC-003", "Processes running from user-writable locations", "low", "Execution",
                           f"{len(others)} process(es) run from Downloads/Temp/AppData/Public. Many legitimate apps "
                           "(updaters, per-user installs) do this; review unknown ones.",
                           [_ev(f"PID {p.get('pid')}", name=p.get("name"), path=p.get("exe"), signature=p.get("signature_status"),
                                signer=p.get("signer")) for p, _ in others[:MAX_EVIDENCE]],
                           *_span(p.get("create_time") for p, _ in others), ["T1204"], "", "medium"))
    return out


@rule
def network_anomalies(rc: RuleContext) -> List[Finding]:
    conns = rc.get("network", "connections")
    out = []
    odd = [c for c in conns if (c.get("remote_port") in SUSPICIOUS_PORTS and is_public_ip(c.get("remote_address")))
           or (c.get("state") == "LISTEN" and c.get("local_port") in SUSPICIOUS_PORTS)]
    if odd:
        out.append(Finding("NET-001", "Connections on ports commonly used by remote-access tools", "medium",
                           "Command and Control", f"{len(odd)} connection(s)/listener(s) on ports such as 4444/1337/31337. "
                           "Port numbers alone are weak evidence; verify the owning process.",
                           [_ev("connection", process=c.get("process"), path=c.get("process_path"),
                                local=f"{c.get('local_address')}:{c.get('local_port')}",
                                remote=f"{c.get('remote_address')}:{c.get('remote_port')}", state=c.get("state")) for c in odd[:MAX_EVIDENCE]],
                           None, None, ["T1571"], "Identify the owning process and its legitimacy.", "low"))
    listen_writable = [c for c in rc.get("network", "listening_ports") if is_user_writable(c.get("process_path"))]
    if listen_writable:
        out.append(Finding("NET-002", "Listening port owned by process in user-writable path", "medium", "Command and Control",
                           f"{len(listen_writable)} listening socket(s) owned by programs in user-writable folders.",
                           [_ev("listener", process=c.get("process"), path=c.get("process_path"),
                                local=f"{c.get('local_address')}:{c.get('local_port')}", protocol=c.get("protocol"))
                            for c in listen_writable[:MAX_EVIDENCE]], None, None, ["T1571"],
                           "Confirm the application is expected to accept inbound connections.", "medium"))
    return out


# ----------------------------------------------------------------------------- persistence


@rule
def startup_persistence(rc: RuleContext) -> List[Finding]:
    entries = rc.get("startup_programs", "startup_entries")
    out = []
    strong = [e for e in entries if e.get("non_default")]
    weak = [e for e in entries if not e.get("non_default") and (is_user_writable(str(e.get("command"))) or _match_cmd(str(e.get("command"))))]
    if strong:
        out.append(Finding("PERS-002", "Non-default Winlogon / AppInit / IFEO debugger entries", "high", "Persistence",
                           f"{len(strong)} high-impact autostart entries differ from Windows defaults.",
                           [_ev(e.get("location"), name=e.get("name"), command=e.get("command"), modified=e.get("key_last_write"))
                            for e in strong[:MAX_EVIDENCE]], *_span(e.get("key_last_write") for e in strong),
                           ["T1547.004", "T1546.012", "T1546.010"], "Verify against a known-good baseline; acquire referenced binaries.", "high"))
    if weak:
        out.append(Finding("PERS-003", "Autostart entries launching from user-writable paths or with suspicious commands",
                           "medium", "Persistence", f"{len(weak)} Run-key/Startup-folder entries reference user-writable "
                           "locations or suspicious command patterns.",
                           [_ev(e.get("location"), name=e.get("name"), command=e.get("command"), user=e.get("user"),
                                enabled=e.get("enabled"), modified=e.get("key_last_write") or e.get("file_created")) for e in weak[:MAX_EVIDENCE]],
                           *_span(e.get("key_last_write") or e.get("file_created") for e in weak), ["T1547.001"],
                           "Check each binary's signature/hash; remove unauthorised entries after evidence is preserved.", "medium"))
    tasks = [t for t in rc.get("scheduled_tasks", "scheduled_tasks")
             if any(is_user_writable(a.get("command")) for a in t.get("actions") or [])
             or (t.get("hidden") and not str(t.get("name", "")).lower().startswith("\\microsoft\\"))]
    if tasks:
        out.append(Finding("PERS-004", "Scheduled tasks executing from user-writable paths or hidden", "medium", "Persistence",
                           f"{len(tasks)} scheduled task(s) run binaries from user-writable folders or are hidden outside the "
                           "Microsoft task tree.",
                           [_ev(f"Task {t.get('name')}", command=t.get("command_line"), author=t.get("author"),
                                registered=t.get("registration_date"), run_as=t.get("run_as"), hidden=t.get("hidden"))
                            for t in tasks[:MAX_EVIDENCE]], *_span(t.get("registration_date") for t in tasks), ["T1053.005"],
                           "Review task XML in evidence; confirm author and purpose.", "medium"))
    created = rc.events("security", [4698]) + rc.events("taskscheduler", [106])
    if created:
        out.append(Finding("PERS-005", "Scheduled task registrations recorded", "info", "Persistence",
                           f"{len(created)} task registration event(s) in event logs.",
                           [_ev(f"EventLog {e.get('event_id')}", time=e.get("time_created"), detail=e.get("description")) for e in created[:MAX_EVIDENCE]],
                           *_span(e.get("time_created") for e in created), ["T1053.005"], "", "high"))
    return out


# ----------------------------------------------------------------------------- execution artifacts


@rule
def execution_from_unusual_locations(rc: RuleContext) -> List[Finding]:
    hits = []
    for p in rc.get("prefetch", "prefetch"):
        path = p.get("executable_path") or ""
        if is_user_writable(path):
            hits.append(_ev("Prefetch", program=p.get("executable"), path=path, last_run=p.get("last_run"), run_count=p.get("run_count")))
    for u in rc.get("userassist", "userassist"):
        if is_user_writable(u.get("path")):
            hits.append(_ev("UserAssist", user=u.get("user"), path=u.get("path"), last_run=u.get("last_executed"), run_count=u.get("run_count")))
    for a in rc.get("amcache", "amcache_files"):
        if is_user_writable(a.get("path")) and not a.get("is_os_component"):
            hits.append(_ev("Amcache", path=a.get("path"), sha1=a.get("sha1"), publisher=a.get("publisher"), first_seen=a.get("key_last_write")))
    if not hits:
        return []
    return [Finding("EXEC-001", "Programs executed from user-writable locations", "low", "Execution",
                    f"{len(hits)} execution artifact(s) reference programs in Downloads/Temp/AppData/Public. Review for "
                    "unknown or unexpected tools.",
                    hits[:MAX_EVIDENCE * 2], *_span(h.get("last_run") or h.get("first_seen") for h in hits), ["T1204.002"],
                    "Hash-check the listed programs (Amcache SHA-1) against threat intelligence.", "medium")]


@rule
def removable_media_activity(rc: RuleContext) -> List[Finding]:
    devs = [d for d in rc.get("usb_history", "usb_devices") if d.get("source") == "USBSTOR"]
    lnk = [l for l in rc.get("lnk_files", "lnk_files") if l.get("drive_type") == "removable"]
    jl = [j for j in rc.get("jump_lists", "jump_lists") if j.get("drive_type") == "removable"]
    out = []
    if devs:
        out.append(Finding("USB-001", "USB storage devices connected", "info", "Exfiltration/Initial Access",
                           f"{len(devs)} USB mass-storage device(s) recorded in the registry.",
                           [_ev("USBSTOR", device=d.get("friendly_name") or f"{d.get('vendor')} {d.get('product')}", serial=d.get("serial"),
                                first_install=d.get("first_install"), last_connected=d.get("last_arrival"),
                                last_removed=d.get("last_removal"), drive_letters=d.get("drive_letters"), label=d.get("volume_label"))
                            for d in devs[:MAX_EVIDENCE * 2]],
                           *_span([d.get("first_install") for d in devs] + [d.get("last_arrival") for d in devs]),
                           ["T1091", "T1052.001"], "Correlate device serials with authorised media and with file-access artifacts.", "high"))
    files = lnk + jl
    if files:
        out.append(Finding("USB-002", "Files opened from removable media", "low", "Exfiltration/Initial Access",
                           f"{len(files)} LNK/Jump List entries point to files on removable volumes.",
                           [_ev("LNK/JumpList", user=f.get("user"), target=f.get("target_path"), volume_serial=f.get("volume_serial"),
                                volume_label=f.get("volume_label"), opened=f.get("lnk_modified") or f.get("last_used"))
                            for f in files[:MAX_EVIDENCE]], *_span(f.get("lnk_modified") or f.get("last_used") for f in files),
                           ["T1052.001"], "Match volume serials to USB devices; review whether data left the system.", "high"))
    return out


@rule
def browser_downloads(rc: RuleContext) -> List[Finding]:
    downloads = rc.browser("downloads")
    exe_dl = [d for d in downloads if str(d.get("target_path") or "").lower().endswith(EXEC_EXT)]
    dangerous = [d for d in downloads if d.get("danger_type") not in (None, "not_dangerous", "user_validated", "allowlisted_by_policy", 0)]
    out = []
    if dangerous:
        out.append(Finding("WEB-001", "Browser flagged downloads as dangerous", "medium", "Initial Access",
                           f"{len(dangerous)} download(s) carried a browser danger verdict.",
                           [_ev(d.get("browser"), user=d.get("user"), file=d.get("target_path"), url=d.get("source_url"),
                                verdict=d.get("danger_type"), time=d.get("start_time")) for d in dangerous[:MAX_EVIDENCE]],
                           *_span(d.get("start_time") for d in dangerous), ["T1189", "T1204.002"], "Check whether the file "
                           "still exists and was executed.", "high"))
    if exe_dl:
        executed_names = set()
        for p in rc.get("prefetch", "prefetch"):
            executed_names.add((p.get("executable") or "").lower())
        for u in rc.get("userassist", "userassist"):
            executed_names.add(os.path.basename(str(u.get("path") or "").replace("\\", "/")).lower())
        for a in rc.get("amcache", "amcache_files"):
            executed_names.add((a.get("name") or os.path.basename(str(a.get("path") or "").replace("\\", "/"))).lower())
        ran = [d for d in exe_dl
               if os.path.basename(str(d.get("target_path")).replace("\\", "/")).lower()[:29] in {n[:29] for n in executed_names if n}]
        if ran:
            out.append(Finding("WEB-002", "Downloaded executable was later executed", "medium", "Execution",
                               f"{len(ran)} file(s) downloaded by a browser have matching execution artifacts "
                               "(Prefetch/UserAssist/Amcache, matched by file name).",
                               [_ev(d.get("browser"), user=d.get("user"), file=d.get("target_path"), url=d.get("source_url"),
                                    downloaded=d.get("start_time")) for d in ran[:MAX_EVIDENCE]],
                               *_span(d.get("start_time") for d in ran), ["T1204.002"],
                               "Hash the executable and verify its origin; name matching can collide.", "medium"))
        out.append(Finding("WEB-000", "Executable or script files downloaded", "info", "Initial Access",
                           f"{len(exe_dl)} downloads with executable/script/disk-image extensions.",
                           [_ev(d.get("browser"), user=d.get("user"), file=d.get("target_path"), url=d.get("source_url"),
                                time=d.get("start_time")) for d in exe_dl[:MAX_EVIDENCE]],
                           *_span(d.get("start_time") for d in exe_dl), [], "", "high"))
    return out


@rule
def suspicious_files(rc: RuleContext) -> List[Finding]:
    files = [f for f in rc.get("filesystem", "files") if f.get("indicators")]
    if not files:
        return []
    out = []
    severe_ind = {"signature_hash_mismatch", "rtlo_character_in_name", "double_extension", "hidden_system_executable"}
    severe = [f for f in files if severe_ind & set(f["indicators"])]
    medium = [f for f in files if f not in severe and {"downloaded_from_internet", "pe_with_non_executable_extension",
                                                        "non_standard_alternate_data_stream"} & set(f["indicators"])
              and ("unsigned_executable" in f["indicators"] or "pe_with_non_executable_extension" in f["indicators"]
                   or "non_standard_alternate_data_stream" in f["indicators"])]
    low = [f for f in files if f not in severe and f not in medium]

    def ev(f):
        return _ev("File", path=f.get("path"), sha256=f.get("sha256"), indicators=f.get("indicators"),
                   created=f.get("created"), signature=(f.get("signature") or {}).get("status"),
                   origin=(f.get("zone_identifier") or {}).get("host_url"))

    if severe:
        out.append(Finding("FILE-001", "Files with deceptive names or tampered signatures", "high", "Defense Evasion",
                           f"{len(severe)} file(s) show double extensions, right-to-left override characters, hidden "
                           "system executables or Authenticode hash mismatches.", [ev(f) for f in severe[:MAX_EVIDENCE]],
                           *_span(f.get("created") for f in severe), ["T1036.007", "T1036.002"],
                           "Preserve and analyse the files in a sandbox; determine how they arrived.", "high"))
    if medium:
        out.append(Finding("FILE-002", "Unsigned executables from the Internet / disguised PE files", "medium", "Execution",
                           f"{len(medium)} file(s) are unsigned executables with an Internet zone mark, PE files with "
                           "non-executable extensions, or carry non-standard alternate data streams.",
                           [ev(f) for f in medium[:MAX_EVIDENCE]], *_span(f.get("created") for f in medium),
                           ["T1204.002", "T1564.004"], "Hash-check and review the files' origin URLs.", "medium"))
    if low:
        out.append(Finding("FILE-003", "Files with weak suspicious indicators", "low", "Execution",
                           f"{len(low)} file(s) have weak indicators (executable in user-writable location, packing, "
                           "unsigned). Common for legitimate software; review unknown items.",
                           [ev(f) for f in low[:MAX_EVIDENCE]], *_span(f.get("created") for f in low), [], "", "low"))
    return out


@rule
def ioc_matches(rc: RuleContext) -> List[Finding]:
    if not rc.iocs:
        return []
    hashes = rc.iocs.get("hashes", set())
    ips = rc.iocs.get("ips", set())
    domains = rc.iocs.get("domains", set())
    hits = []
    for f in rc.get("filesystem", "files"):
        if f.get("sha256") and f["sha256"].lower() in hashes:
            hits.append(_ev("File", path=f.get("path"), sha256=f["sha256"]))
    for p in rc.get("processes", "processes"):
        if p.get("exe_sha256") and p["exe_sha256"].lower() in hashes:
            hits.append(_ev("Process", pid=p.get("pid"), path=p.get("exe"), sha256=p["exe_sha256"]))
    for a in rc.get("amcache", "amcache_files"):
        if a.get("sha1") and a["sha1"].lower() in hashes:
            hits.append(_ev("Amcache", path=a.get("path"), sha1=a["sha1"]))
    for c in rc.get("network", "connections"):
        if c.get("remote_address") in ips:
            hits.append(_ev("Connection", process=c.get("process"), remote=c.get("remote_address")))
    for d in rc.get("network", "dns_cache"):
        name = str(d.get("Entry") or d.get("Name") or "").lower().rstrip(".")
        if name and any(name == dom or name.endswith("." + dom) for dom in domains):
            hits.append(_ev("DNS cache", entry=name, data=d.get("Data")))
    for v in rc.browser("history"):
        host = _host(v.get("url"))
        if host and any(host == dom or host.endswith("." + dom) for dom in domains):
            hits.append(_ev(v.get("browser"), url=v.get("url"), time=v.get("visit_time"), user=v.get("user")))
    for d in rc.browser("downloads"):
        host = _host(d.get("source_url"))
        if host and any(host == dom or host.endswith("." + dom) for dom in domains):
            hits.append(_ev(f"{d.get('browser')} download", url=d.get("source_url"), file=d.get("target_path"),
                            time=d.get("start_time"), user=d.get("user")))
    if not hits:
        return []
    return [Finding("IOC-001", "Matches against supplied indicators of compromise", "critical", "Threat Intelligence",
                    f"{len(hits)} artifact(s) match the examiner-supplied IOC list.", hits[:MAX_EVIDENCE * 2], None, None, [],
                    "Treat as confirmed compromise indicators; escalate per incident response plan.", "high")]


def _host(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else None


def load_ioc_file(path: str) -> Dict[str, set]:
    """IOC file: one value per line (SHA-256/SHA-1/MD5 hashes, IPv4/IPv6 addresses, domains). '#' starts a comment."""
    out = {"hashes": set(), "ips": set(), "domains": set()}
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8-sig") as fh:
        for line in fh:
            value = line.split("#", 1)[0].strip().lower()
            if not value:
                continue
            if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", value):
                out["hashes"].add(value)
                continue
            try:
                ipaddress.ip_address(value)
                out["ips"].add(value)
                continue
            except ValueError:
                pass
            if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", value):
                out["domains"].add(value)
    return out
