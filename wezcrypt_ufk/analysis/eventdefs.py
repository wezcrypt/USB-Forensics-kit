"""Event log channels collected and human-readable descriptions for forensic event IDs."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

# channel -> (short key, event IDs of forensic interest, requires admin)
CHANNELS: List[Tuple[str, str, List[int], bool]] = [
    ("Security", "security",
     [1102, 4616, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4722,
      4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756, 4767, 4771, 4776, 4778, 4779, 4798, 4799, 5140, 6416],
     True),
    ("System", "system", [104, 1074, 6005, 6006, 6008, 6013, 7034, 7040, 7045, 1, 20001, 20003, 24576, 24577], False),
    ("Application", "application", [1000, 1001, 1002, 1033, 1034, 11707, 11708, 11724], False),
    ("Windows PowerShell", "powershell_classic", [400, 403, 600, 800], False),
    ("Microsoft-Windows-PowerShell/Operational", "powershell", [4103, 4104, 40961, 40962], False),
    ("Microsoft-Windows-TaskScheduler/Operational", "taskscheduler", [106, 140, 141, 200, 201], False),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "rdp_lsm", [21, 22, 23, 24, 25], False),
    ("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "rdp_rcm", [1149], False),
    ("Microsoft-Windows-Windows Defender/Operational", "defender", [1006, 1007, 1008, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012], False),
    ("Microsoft-Windows-DriverFrameworks-UserMode/Operational", "driverframeworks", [2003, 2004, 2100, 2101, 2102], False),
    ("Microsoft-Windows-Kernel-PnP/Configuration", "kernel_pnp", [400, 410, 420, 430], False),
    ("Microsoft-Windows-Partition/Diagnostic", "partition", [1006], False),
    ("Microsoft-Windows-WLAN-AutoConfig/Operational", "wlan", [8001, 8002, 8003], False),
    ("Microsoft-Windows-Bits-Client/Operational", "bits", [3, 59, 60], False),
    ("Microsoft-Windows-Sysmon/Operational", "sysmon", [1, 3, 6, 7, 8, 10, 11, 12, 13, 22, 23, 25], True),
]

LOGON_TYPES = {"2": "interactive", "3": "network", "4": "batch", "5": "service", "7": "unlock",
               "8": "network_cleartext", "9": "new_credentials", "10": "remote_interactive(RDP)",
               "11": "cached_interactive", "12": "cached_remote_interactive", "13": "cached_unlock"}

FAILURE_STATUS = {
    "0xc000006a": "bad password", "0xc0000064": "unknown user", "0xc0000234": "account locked",
    "0xc0000072": "account disabled", "0xc000006f": "outside logon hours", "0xc0000070": "workstation restriction",
    "0xc0000193": "account expired", "0xc0000071": "password expired", "0xc0000133": "clock skew",
    "0xc000015b": "logon type not granted", "0xc0000224": "password must change",
}


def _d(rec: Dict, key: str) -> str:
    return str((rec.get("data") or {}).get(key) or "").strip()


def _user(rec: Dict, prefix: str = "Target") -> str:
    dom, user = _d(rec, f"{prefix}DomainName"), _d(rec, f"{prefix}UserName")
    return f"{dom}\\{user}" if dom and dom != "-" else (user or "?")


Describer = Callable[[Dict], str]

DESCRIPTIONS: Dict[Tuple[str, int], Tuple[str, Describer]] = {
    ("security", 4624): ("logon_success", lambda r: f"Logon ({LOGON_TYPES.get(_d(r, 'LogonType'), _d(r, 'LogonType'))}) "
                         f"{_user(r)} from {_d(r, 'IpAddress') or '-'} via {_d(r, 'LogonProcessName') or '-'}"),
    ("security", 4625): ("logon_failure", lambda r: f"FAILED logon ({LOGON_TYPES.get(_d(r, 'LogonType'), _d(r, 'LogonType'))}) "
                         f"{_user(r)} from {_d(r, 'IpAddress') or '-'} - "
                         f"{FAILURE_STATUS.get(_d(r, 'SubStatus').lower(), FAILURE_STATUS.get(_d(r, 'Status').lower(), _d(r, 'SubStatus')))}"),
    ("security", 4634): ("logoff", lambda r: f"Logoff {_user(r)} (type {_d(r, 'LogonType')})"),
    ("security", 4647): ("logoff", lambda r: f"User initiated logoff {_user(r)}"),
    ("security", 4648): ("explicit_credentials", lambda r: f"Explicit credential logon by {_user(r, 'Subject')} as {_user(r)} "
                         f"to {_d(r, 'TargetServerName')} ({_d(r, 'ProcessName')})"),
    ("security", 4672): ("special_privileges", lambda r: f"Special privileges assigned to {_user(r, 'Subject')}"),
    ("security", 4688): ("process_creation", lambda r: f"Process created {_d(r, 'NewProcessName')} by {_user(r, 'Subject')} "
                         f"cmd: {_d(r, 'CommandLine')[:300]}"),
    ("security", 4697): ("service_installed", lambda r: f"Service installed {_d(r, 'ServiceName')}: {_d(r, 'ServiceFileName')}"),
    ("security", 4698): ("task_created", lambda r: f"Scheduled task created {_d(r, 'TaskName')} by {_user(r, 'Subject')}"),
    ("security", 4699): ("task_deleted", lambda r: f"Scheduled task deleted {_d(r, 'TaskName')}"),
    ("security", 4700): ("task_enabled", lambda r: f"Scheduled task enabled {_d(r, 'TaskName')}"),
    ("security", 4701): ("task_disabled", lambda r: f"Scheduled task disabled {_d(r, 'TaskName')}"),
    ("security", 4702): ("task_updated", lambda r: f"Scheduled task updated {_d(r, 'TaskName')}"),
    ("security", 4719): ("audit_policy_changed", lambda r: f"System audit policy changed by {_user(r, 'Subject')}"),
    ("security", 4720): ("account_created", lambda r: f"User account created {_user(r)} by {_user(r, 'Subject')}"),
    ("security", 4722): ("account_enabled", lambda r: f"User account enabled {_user(r)}"),
    ("security", 4723): ("password_change", lambda r: f"Password change attempt for {_user(r)}"),
    ("security", 4724): ("password_reset", lambda r: f"Password reset of {_user(r)} by {_user(r, 'Subject')}"),
    ("security", 4725): ("account_disabled", lambda r: f"User account disabled {_user(r)}"),
    ("security", 4726): ("account_deleted", lambda r: f"User account deleted {_user(r)} by {_user(r, 'Subject')}"),
    ("security", 4728): ("group_member_added", lambda r: f"Member {_d(r, 'MemberName') or _d(r, 'MemberSid')} added to global group {_d(r, 'TargetUserName')}"),
    ("security", 4732): ("group_member_added", lambda r: f"Member {_d(r, 'MemberName') or _d(r, 'MemberSid')} added to local group {_d(r, 'TargetUserName')}"),
    ("security", 4756): ("group_member_added", lambda r: f"Member {_d(r, 'MemberName') or _d(r, 'MemberSid')} added to universal group {_d(r, 'TargetUserName')}"),
    ("security", 4738): ("account_changed", lambda r: f"User account changed {_user(r)}"),
    ("security", 4740): ("account_lockout", lambda r: f"Account locked out {_d(r, 'TargetUserName')} (caller {_d(r, 'TargetDomainName')})"),
    ("security", 4767): ("account_unlocked", lambda r: f"Account unlocked {_user(r)}"),
    ("security", 4771): ("kerberos_preauth_failed", lambda r: f"Kerberos pre-auth failed {_d(r, 'TargetUserName')} from {_d(r, 'IpAddress')}"),
    ("security", 4776): ("ntlm_validation", lambda r: f"NTLM credential validation {_d(r, 'TargetUserName')} from {_d(r, 'Workstation')} status {_d(r, 'Status')}"),
    ("security", 4778): ("session_reconnected", lambda r: f"Session reconnected {_d(r, 'AccountName')} from {_d(r, 'ClientAddress')}"),
    ("security", 4779): ("session_disconnected", lambda r: f"Session disconnected {_d(r, 'AccountName')} from {_d(r, 'ClientAddress')}"),
    ("security", 4798): ("group_enumeration", lambda r: f"Local group membership of {_user(r)} enumerated by {_d(r, 'CallerProcessName')}"),
    ("security", 4799): ("group_enumeration", lambda r: f"Local group {_d(r, 'TargetUserName')} enumerated by {_d(r, 'CallerProcessName')}"),
    ("security", 5140): ("share_access", lambda r: f"Network share {_d(r, 'ShareName')} accessed by {_user(r, 'Subject')} from {_d(r, 'IpAddress')}"),
    ("security", 6416): ("device_recognized", lambda r: f"External device recognized: {_d(r, 'DeviceDescription')} ({_d(r, 'DeviceId')})"),
    ("security", 1102): ("log_cleared", lambda r: f"Security audit log CLEARED by {_d(r, 'SubjectUserName') or _d(r, 'SubjectDomainName')}"),
    ("security", 4616): ("time_changed", lambda r: f"System time changed from {_d(r, 'PreviousTime')} to {_d(r, 'NewTime')} by {_d(r, 'ProcessName')}"),
    ("system", 104): ("log_cleared", lambda r: f"Event log cleared: {_d(r, 'Channel')} by {_d(r, 'SubjectUserName')}"),
    ("system", 1074): ("shutdown_initiated", lambda r: f"Shutdown/restart initiated by {_d(r, 'param7') or _d(r, 'param1')}: {_d(r, 'param5') or _d(r, 'param3')}"),
    ("system", 6005): ("eventlog_started", lambda r: "Event Log service started (system boot)"),
    ("system", 6006): ("eventlog_stopped", lambda r: "Event Log service stopped (clean shutdown)"),
    ("system", 6008): ("unexpected_shutdown", lambda r: "Previous system shutdown was unexpected"),
    ("system", 6013): ("uptime", lambda r: f"System uptime {_d(r, 'Data4') or _d(r, 'Data0')} s"),
    ("system", 7034): ("service_crashed", lambda r: f"Service terminated unexpectedly: {_d(r, 'param1')}"),
    ("system", 7040): ("service_start_type_changed", lambda r: f"Service start type changed: {_d(r, 'param1')} {_d(r, 'param2')} -> {_d(r, 'param3')}"),
    ("system", 7045): ("service_installed", lambda r: f"Service installed {_d(r, 'ServiceName')}: {_d(r, 'ImagePath')} ({_d(r, 'StartType')}, {_d(r, 'AccountName')})"),
    ("system", 1): ("time_changed", lambda r: f"System time changed {_d(r, 'OldTime')} -> {_d(r, 'NewTime')}" if _d(r, "NewTime") else "Kernel-General event 1"),
    ("system", 20001): ("driver_installed", lambda r: f"Device driver install: {_d(r, 'DeviceInstanceID') or _d(r, 'Data1')}"),
    ("system", 20003): ("driver_service_added", lambda r: f"Driver service added: {_d(r, 'DeviceInstanceID') or _d(r, 'Data1')}"),
    ("system", 24576): ("driver_installed", lambda r: "Driver installed successfully"),
    ("system", 24577): ("driver_install_failed", lambda r: "Driver installation failed"),
    ("application", 1000): ("app_crash", lambda r: f"Application crash: {_d(r, 'Data0')} module {_d(r, 'Data3')}"),
    ("application", 1001): ("error_report", lambda r: f"Windows Error Reporting: {_d(r, 'Data0')} {_d(r, 'Data5')}"),
    ("application", 1002): ("app_hang", lambda r: f"Application hang: {_d(r, 'Data0')}"),
    ("application", 1033): ("msi_install", lambda r: f"MSI product installed: {_d(r, 'Data0')} {_d(r, 'Data1')}"),
    ("application", 1034): ("msi_uninstall", lambda r: f"MSI product removed: {_d(r, 'Data0')} {_d(r, 'Data1')}"),
    ("application", 11707): ("msi_install", lambda r: f"MSI installation completed: {_d(r, 'Data0')}"),
    ("application", 11708): ("msi_install_failed", lambda r: f"MSI installation failed: {_d(r, 'Data0')}"),
    ("application", 11724): ("msi_uninstall", lambda r: f"MSI removal completed: {_d(r, 'Data0')}"),
    ("powershell_classic", 400): ("powershell_engine_start", lambda r: f"PowerShell engine started: {_hostapp(r)}"),
    ("powershell_classic", 403): ("powershell_engine_stop", lambda r: f"PowerShell engine stopped: {_hostapp(r)}"),
    ("powershell_classic", 600): ("powershell_provider", lambda r: f"PowerShell provider started: {_hostapp(r)}"),
    ("powershell_classic", 800): ("powershell_pipeline", lambda r: f"PowerShell pipeline executed: {_hostapp(r)}"),
    ("powershell", 4103): ("powershell_module", lambda r: f"PowerShell module logging: {_d(r, 'Payload')[:300]}"),
    ("powershell", 4104): ("powershell_scriptblock", lambda r: f"PowerShell script block: {_d(r, 'ScriptBlockText')[:300]}"),
    ("powershell", 40961): ("powershell_console_start", lambda r: "PowerShell console starting"),
    ("powershell", 40962): ("powershell_console_ready", lambda r: "PowerShell console ready"),
    ("taskscheduler", 106): ("task_registered", lambda r: f"Task registered {_d(r, 'TaskName')} by {_d(r, 'UserContext')}"),
    ("taskscheduler", 140): ("task_updated", lambda r: f"Task updated {_d(r, 'TaskName')} by {_d(r, 'UserName')}"),
    ("taskscheduler", 141): ("task_deleted", lambda r: f"Task deleted {_d(r, 'TaskName')} by {_d(r, 'UserName')}"),
    ("taskscheduler", 200): ("task_action_started", lambda r: f"Task action started {_d(r, 'TaskName')}: {_d(r, 'ActionName')}"),
    ("taskscheduler", 201): ("task_action_completed", lambda r: f"Task action completed {_d(r, 'TaskName')}: {_d(r, 'ActionName')}"),
    ("rdp_lsm", 21): ("rdp_logon", lambda r: f"RDP session logon {_d(r, 'User')} from {_d(r, 'Address')}"),
    ("rdp_lsm", 22): ("rdp_shell_start", lambda r: f"RDP shell start {_d(r, 'User')} from {_d(r, 'Address')}"),
    ("rdp_lsm", 23): ("rdp_logoff", lambda r: f"RDP session logoff {_d(r, 'User')}"),
    ("rdp_lsm", 24): ("rdp_disconnect", lambda r: f"RDP session disconnected {_d(r, 'User')} from {_d(r, 'Address')}"),
    ("rdp_lsm", 25): ("rdp_reconnect", lambda r: f"RDP session reconnected {_d(r, 'User')} from {_d(r, 'Address')}"),
    ("rdp_rcm", 1149): ("rdp_auth", lambda r: f"RDP network authentication {_d(r, 'Param2')}\\{_d(r, 'Param1')} from {_d(r, 'Param3')}"),
    ("defender", 1006): ("malware_detected", lambda r: f"Defender detected malware: {_d(r, 'Threat Name')} {_d(r, 'Path')}"),
    ("defender", 1007): ("malware_action", lambda r: f"Defender action taken: {_d(r, 'Threat Name')} {_d(r, 'Action Name')}"),
    ("defender", 1008): ("malware_action_failed", lambda r: f"Defender action FAILED: {_d(r, 'Threat Name')}"),
    ("defender", 1116): ("malware_detected", lambda r: f"Defender detected: {_d(r, 'Threat Name')} ({_d(r, 'Severity Name')}) {_d(r, 'Path')}"),
    ("defender", 1117): ("malware_action", lambda r: f"Defender remediation: {_d(r, 'Threat Name')} {_d(r, 'Action Name')}"),
    ("defender", 1118): ("malware_action_failed", lambda r: f"Defender remediation failed: {_d(r, 'Threat Name')}"),
    ("defender", 1119): ("malware_action_failed", lambda r: f"Defender remediation critical failure: {_d(r, 'Threat Name')}"),
    ("defender", 5001): ("defender_disabled", lambda r: "Defender real-time protection DISABLED"),
    ("defender", 5007): ("defender_config_changed", lambda r: f"Defender configuration changed: {_d(r, 'New Value')[:200]}"),
    ("defender", 5010): ("defender_disabled", lambda r: "Defender antispyware scanning disabled"),
    ("defender", 5012): ("defender_disabled", lambda r: "Defender antivirus scanning disabled"),
    ("driverframeworks", 2003): ("usb_connected", lambda r: f"Device load (UMDF) {_d(r, 'InstanceId') or _d(r, 'lifetime')}"),
    ("driverframeworks", 2004): ("usb_connected", lambda r: f"Device driver load (UMDF) {_d(r, 'InstanceId')}"),
    ("driverframeworks", 2100): ("usb_removed", lambda r: f"Device removal (UMDF) {_d(r, 'InstanceId')}"),
    ("driverframeworks", 2101): ("usb_removed", lambda r: f"Device removal (UMDF) {_d(r, 'InstanceId')}"),
    ("driverframeworks", 2102): ("usb_removed", lambda r: f"Device removal (UMDF) {_d(r, 'InstanceId')}"),
    ("kernel_pnp", 400): ("device_configured", lambda r: f"Device configured {_d(r, 'DeviceInstanceId')}"),
    ("kernel_pnp", 410): ("device_started", lambda r: f"Device started {_d(r, 'DeviceInstanceId')}"),
    ("kernel_pnp", 420): ("device_deleted", lambda r: f"Device deleted {_d(r, 'DeviceInstanceId')}"),
    ("kernel_pnp", 430): ("device_install_pending", lambda r: f"Device requires further installation {_d(r, 'DeviceInstanceId')}"),
    ("partition", 1006): ("usb_storage_event", lambda r: f"Storage device {_d(r, 'Manufacturer')} {_d(r, 'Model')} serial {_d(r, 'SerialNumber')} (capacity {_d(r, 'Capacity')})"),
    ("wlan", 8001): ("wifi_connected", lambda r: f"Connected to Wi-Fi {_d(r, 'SSID')} ({_d(r, 'AuthenticationAlgorithm')})"),
    ("wlan", 8002): ("wifi_failed", lambda r: f"Wi-Fi connection failed {_d(r, 'SSID')}"),
    ("wlan", 8003): ("wifi_disconnected", lambda r: f"Disconnected from Wi-Fi {_d(r, 'SSID')}"),
    ("bits", 3): ("bits_job", lambda r: f"BITS job created {_d(r, 'jobTitle')} by {_d(r, 'jobOwner')}"),
    ("bits", 59): ("bits_transfer", lambda r: f"BITS transfer started {_d(r, 'url')}"),
    ("bits", 60): ("bits_transfer", lambda r: f"BITS transfer stopped {_d(r, 'url')} status {_d(r, 'hr')}"),
    ("sysmon", 1): ("process_creation", lambda r: f"[Sysmon] Process {_d(r, 'Image')} cmd: {_d(r, 'CommandLine')[:300]} parent {_d(r, 'ParentImage')}"),
    ("sysmon", 3): ("network_connection", lambda r: f"[Sysmon] {_d(r, 'Image')} -> {_d(r, 'DestinationIp')}:{_d(r, 'DestinationPort')} ({_d(r, 'DestinationHostname')})"),
    ("sysmon", 6): ("driver_loaded", lambda r: f"[Sysmon] Driver loaded {_d(r, 'ImageLoaded')} signed={_d(r, 'Signed')}"),
    ("sysmon", 7): ("image_loaded", lambda r: f"[Sysmon] Image loaded {_d(r, 'ImageLoaded')} by {_d(r, 'Image')}"),
    ("sysmon", 8): ("remote_thread", lambda r: f"[Sysmon] CreateRemoteThread {_d(r, 'SourceImage')} -> {_d(r, 'TargetImage')}"),
    ("sysmon", 10): ("process_access", lambda r: f"[Sysmon] Process access {_d(r, 'SourceImage')} -> {_d(r, 'TargetImage')} ({_d(r, 'GrantedAccess')})"),
    ("sysmon", 11): ("file_created", lambda r: f"[Sysmon] File created {_d(r, 'TargetFilename')} by {_d(r, 'Image')}"),
    ("sysmon", 12): ("registry_event", lambda r: f"[Sysmon] Registry {_d(r, 'EventType')} {_d(r, 'TargetObject')}"),
    ("sysmon", 13): ("registry_event", lambda r: f"[Sysmon] Registry value set {_d(r, 'TargetObject')} = {_d(r, 'Details')[:200]}"),
    ("sysmon", 22): ("dns_query", lambda r: f"[Sysmon] DNS query {_d(r, 'QueryName')} by {_d(r, 'Image')}"),
    ("sysmon", 23): ("file_deleted", lambda r: f"[Sysmon] File deleted {_d(r, 'TargetFilename')} by {_d(r, 'Image')}"),
    ("sysmon", 25): ("process_tampering", lambda r: f"[Sysmon] Process tampering {_d(r, 'Image')} ({_d(r, 'Type')})"),
}


def _hostapp(rec: Dict) -> str:
    text = _d(rec, "Data2") or _d(rec, "Data1")
    for line in text.splitlines():
        if "HostApplication=" in line:
            return line.split("=", 1)[1][:300]
    return text[:200]


def describe(channel_key: str, rec: Dict) -> Tuple[str, str]:
    eid = rec.get("event_id")
    entry: Optional[Tuple[str, Describer]] = DESCRIPTIONS.get((channel_key, eid))
    if entry is None:
        return "event", f"{rec.get('provider')} event {eid}"
    try:
        return entry[0], entry[1](rec)
    except Exception:
        return entry[0], f"{rec.get('provider')} event {eid}"
