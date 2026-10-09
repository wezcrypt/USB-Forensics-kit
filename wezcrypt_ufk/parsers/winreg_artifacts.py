"""Registry artifact parsers. Each function takes RegKey roots and returns plain dict records."""

from __future__ import annotations

import codecs
import re
import struct
from typing import Dict, List, Optional

from ..core.timeutil import filetime_to_iso
from .registry import RegKey, current_control_set
from .shellitems import join_path, parse_id_list, parse_shell_item

# ----------------------------------------------------------------------------- UserAssist

USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "executable",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "shortcut",
}

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "C:\\Windows\\System32",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "C:\\Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "C:\\Program Files (x86)",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "C:\\Windows",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "C:\\Windows\\SysWOW64",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "%APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned",
    "{374DE290-123F-4565-9164-39C4925E467B}": "%USERPROFILE%\\Downloads",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "%USERPROFILE%\\Desktop",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "%USERPROFILE%\\Documents",
}


def expand_known_folder(path: str) -> str:
    for guid, real in KNOWN_FOLDERS.items():
        if path.upper().startswith(guid):
            return real + path[len(guid):]
    return path


def parse_userassist(ntuser_root: RegKey, user: str = "") -> List[Dict]:
    base = ntuser_root.subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    out: List[Dict] = []
    if base is None:
        return out
    for guid_key in base.subkeys():
        count = guid_key.subkey("Count")
        if count is None:
            continue
        kind = USERASSIST_GUIDS.get(guid_key.name.upper(), "other")
        for val in count.values():
            name = codecs.decode(val.name, "rot_13")
            data = val.data if isinstance(val.data, (bytes, bytearray)) else b""
            rec = {
                "user": user,
                "guid": guid_key.name,
                "entry_type": kind,
                "name": name,
                "path": expand_known_folder(name),
                "run_count": None,
                "focus_count": None,
                "focus_time_ms": None,
                "last_executed": None,
            }
            if len(data) >= 68:
                rec["run_count"], rec["focus_count"], rec["focus_time_ms"] = struct.unpack_from("<III", data, 4)
                rec["last_executed"] = filetime_to_iso(struct.unpack_from("<Q", data, 60)[0])
            elif len(data) >= 16:  # Windows XP layout
                rec["run_count"] = max(0, struct.unpack_from("<I", data, 4)[0] - 5)
                rec["last_executed"] = filetime_to_iso(struct.unpack_from("<Q", data, 8)[0])
            if name.startswith("UEME_") and not rec["run_count"] and not rec["last_executed"]:
                continue  # session counters, not executions
            out.append(rec)
    return out


# ----------------------------------------------------------------------------- ShellBags


def _mru_order(key: RegKey) -> List[int]:
    raw = key.value("MRUListEx")
    if not isinstance(raw, (bytes, bytearray)):
        return []
    order = []
    for i in range(0, len(raw) - 3, 4):
        n = struct.unpack_from("<i", raw, i)[0]
        if n < 0:
            break
        order.append(n)
    return order


def parse_shellbags(root: RegKey, hive_label: str, user: str = "", max_depth: int = 40) -> List[Dict]:
    """Walk a BagMRU tree (root = the BagMRU key)."""
    out: List[Dict] = []

    def walk(key: RegKey, parent_path: str, depth: int) -> None:
        if depth > max_depth:
            return
        order = _mru_order(key)
        children = {sk.name: sk for sk in key.subkeys()}
        for val in key.values():
            if not val.name.isdigit() or not isinstance(val.data, (bytes, bytearray)):
                continue
            item = parse_shell_item(bytes(val.data))
            name = item.get("name") or f"<{item.get('type')}>"
            if item.get("type") == "root_folder" and item.get("name") == "My Computer":
                path = parent_path or "My Computer"
            else:
                path = join_path(parent_path if parent_path != "My Computer" else "", name)
            child = children.get(val.name)
            slot = child.value("NodeSlot") if child is not None else None
            idx = int(val.name)
            out.append({
                "user": user,
                "hive": hive_label,
                "path": path,
                "item_type": item.get("type"),
                "mru_position": order.index(idx) if idx in order else None,
                "node_slot": slot,
                "bag_key": child.path if child is not None else key.path,
                "key_last_write": child.last_write if child is not None else None,
                "created": item.get("created"),
                "modified": item.get("modified"),
                "accessed": item.get("accessed"),
                "mft_entry": item.get("mft_entry"),
            })
            if child is not None:
                walk(child, path, depth + 1)

    walk(root, "", 0)
    return out


# ----------------------------------------------------------------------------- Shimcache


def parse_appcompatcache(data: bytes) -> List[Dict]:
    """Windows 10/11 AppCompatCache ('10ts' entries). Order 0 is the most recently inserted entry."""
    out: List[Dict] = []
    if len(data) < 0x34:
        return out
    header = struct.unpack_from("<I", data, 0)[0]
    pos = header if header in (0x30, 0x34) else data.find(b"10ts")
    if pos < 0:
        return out
    position = 0
    while pos + 12 <= len(data) and data[pos:pos + 4] == b"10ts":
        entry_size = struct.unpack_from("<I", data, pos + 8)[0]
        body = pos + 12
        if body + entry_size > len(data):
            break
        path_len = struct.unpack_from("<H", data, body)[0]
        path = data[body + 2: body + 2 + path_len].decode("utf-16-le", "replace")
        off = body + 2 + path_len
        modified = struct.unpack_from("<Q", data, off)[0] if off + 8 <= len(data) else 0
        data_size = struct.unpack_from("<I", data, off + 8)[0] if off + 12 <= len(data) else 0
        out.append({
            "position": position,
            "path": path,
            "last_modified": filetime_to_iso(modified),
            "data_size": data_size,
        })
        position += 1
        pos = body + entry_size
    return out


def shimcache_from_system(system_root: RegKey) -> List[Dict]:
    ccs = current_control_set(system_root)
    if ccs is None:
        return []
    key = ccs.subkey("Control\\Session Manager\\AppCompatCache")
    data = key.value("AppCompatCache") if key is not None else None
    if not isinstance(data, (bytes, bytearray)):
        return []
    return parse_appcompatcache(bytes(data))


# ----------------------------------------------------------------------------- USB devices

DEVPROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
DEVPROP_TIMES = {"0064": "first_install", "0065": "install_date", "0066": "last_arrival", "0067": "last_removal"}


def _devprop_times(dev: RegKey) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {}
    props = dev.subkey(f"Properties\\{DEVPROP_GUID}")
    if props is None:
        return out
    for code, label in DEVPROP_TIMES.items():
        k = props.subkey(code)
        if k is None:
            continue
        for v in k.values():
            raw = v.data
            if isinstance(raw, int):
                out[label] = filetime_to_iso(raw)
            elif isinstance(raw, (bytes, bytearray)) and len(raw) >= 8:
                out[label] = filetime_to_iso(struct.unpack_from("<Q", raw)[0])
    return out


_USBSTOR_RE = re.compile(r"Disk&Ven_(?P<vendor>[^&]*)&Prod_(?P<product>[^&]*)(?:&Rev_(?P<rev>.*))?", re.I)


def parse_usb_devices(system_root: RegKey, software_root: Optional[RegKey] = None) -> List[Dict]:
    out: List[Dict] = []
    ccs = current_control_set(system_root)
    if ccs is None:
        return out
    labels: Dict[str, str] = {}
    if software_root is not None:
        wpd = software_root.subkey("Microsoft\\Windows Portable Devices\\Devices")
        for dev in (wpd.subkeys() if wpd is not None else []):
            fname = dev.value("FriendlyName")
            if fname:
                labels[dev.name.upper()] = fname
    letters = _mounted_device_letters(system_root)
    usbstor = ccs.subkey("Enum\\USBSTOR")
    for dev_class in (usbstor.subkeys() if usbstor is not None else []):
        m = _USBSTOR_RE.match(dev_class.name)
        for inst in dev_class.subkeys():
            serial = inst.name
            unique = not (len(serial) > 1 and serial[1] == "&")
            clean = serial[:-2] if serial.endswith("&0") else serial
            label = next((v for k, v in labels.items() if clean.upper() in k), None)
            rec = {
                "source": "USBSTOR",
                "device_class": dev_class.name,
                "vendor": m.group("vendor") if m else None,
                "product": m.group("product") if m else None,
                "revision": m.group("rev") if m else None,
                "serial": clean,
                "serial_is_unique": unique,
                "friendly_name": inst.value("FriendlyName"),
                "container_id": inst.value("ContainerID"),
                "volume_label": label,
                "drive_letters": [d for d, ident in letters.items() if clean.upper() in ident.upper()],
                "key_last_write": inst.last_write,
            }
            rec.update(_devprop_times(inst))
            out.append(rec)
    usb = ccs.subkey("Enum\\USB")
    for vidpid in (usb.subkeys() if usb is not None else []):
        if not vidpid.name.upper().startswith("VID_"):
            continue
        mv = re.match(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", vidpid.name, re.I)
        for inst in vidpid.subkeys():
            rec = {
                "source": "USB",
                "device_class": vidpid.name,
                "vid": mv.group(1) if mv else None,
                "pid": mv.group(2) if mv else None,
                "serial": inst.name,
                "serial_is_unique": "&" not in inst.name,
                "friendly_name": inst.value("FriendlyName") or inst.value("DeviceDesc"),
                "service": inst.value("Service"),
                "container_id": inst.value("ContainerID"),
                "key_last_write": inst.last_write,
            }
            rec.update(_devprop_times(inst))
            out.append(rec)
    return out


def _mounted_device_letters(system_root: RegKey) -> Dict[str, str]:
    md = system_root.subkey("MountedDevices")
    out: Dict[str, str] = {}
    if md is None:
        return out
    for v in md.values():
        if not v.name.upper().startswith("\\DOSDEVICES\\"):
            continue
        raw = v.data if isinstance(v.data, (bytes, bytearray)) else b""
        try:
            text = bytes(raw).decode("utf-16-le", "ignore")
        except Exception:
            continue
        if "USBSTOR" in text.upper() or "#" in text:
            out[v.name.split("\\")[-1]] = text
    return out


def parse_mountpoints2(ntuser_root: RegKey, user: str = "") -> List[Dict]:
    key = ntuser_root.subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
    return [{"user": user, "mount_point": sk.name, "key_last_write": sk.last_write}
            for sk in (key.subkeys() if key is not None else [])]


# ----------------------------------------------------------------------------- persistence / startup

RUN_PATHS = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
]


def _startup_approved(root: RegKey, prefix: str) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for sub in ("Run", "Run32", "StartupFolder"):
        key = root.subkey(prefix + "Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\" + sub)
        for v in (key.values() if key is not None else []):
            raw = v.data if isinstance(v.data, (bytes, bytearray)) else b""
            if len(raw) >= 1:
                enabled = raw[0] in (0x02, 0x06)
                disabled_at = filetime_to_iso(struct.unpack_from("<Q", raw, 4)[0]) if len(raw) >= 12 and not enabled else None
                out[v.name.lower()] = {"enabled": enabled, "disabled_utc": disabled_at}
    return out


def parse_run_keys(software_root: Optional[RegKey], ntuser_root: Optional[RegKey], user: str = "") -> List[Dict]:
    """Run/RunOnce entries. software_root = HKLM\\SOFTWARE; ntuser_root = HKCU (its Software key is resolved)."""
    out: List[Dict] = []
    sources = []
    if software_root is not None:
        sources.append(("HKLM\\SOFTWARE", software_root, "", None))
    if ntuser_root is not None:
        sw = ntuser_root.subkey("Software")
        if sw is not None:
            sources.append((f"HKCU({user})\\Software" if user else "HKCU\\Software", sw, "", user))
    for label, root, prefix, owner in sources:
        approved = _startup_approved(root, prefix)
        for rel in RUN_PATHS:
            key = root.subkey(rel)
            if key is None:
                continue
            for v in key.values():
                if not v.name and not v.data:
                    continue
                state = approved.get(v.name.lower(), {})
                out.append({
                    "location": f"{label}\\{rel}",
                    "name": v.name or "(Default)",
                    "command": v.data if isinstance(v.data, str) else str(v.data),
                    "user": owner,
                    "key_last_write": key.last_write,
                    "enabled": state.get("enabled", True),
                    "disabled_utc": state.get("disabled_utc"),
                })
    if software_root is not None:
        wl = software_root.subkey("Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        if wl is not None:
            for name, normal in (("Shell", "explorer.exe"), ("Userinit", "C:\\Windows\\system32\\userinit.exe,")):
                val = wl.value(name)
                if isinstance(val, str):
                    out.append({
                        "location": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                        "name": name, "command": val, "user": None, "key_last_write": wl.last_write,
                        "enabled": True, "non_default": val.strip().lower().rstrip(",") != normal.lower().rstrip(","),
                    })
        win = software_root.subkey("Microsoft\\Windows NT\\CurrentVersion\\Windows")
        if win is not None:
            dlls = win.value("AppInit_DLLs")
            if isinstance(dlls, str) and dlls.strip():
                out.append({
                    "location": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                    "name": "AppInit_DLLs", "command": dlls, "user": None, "key_last_write": win.last_write,
                    "enabled": bool(win.value("LoadAppInit_DLLs")), "non_default": True,
                })
        ifeo = software_root.subkey("Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
        for sk in (ifeo.subkeys() if ifeo is not None else []):
            dbg = sk.value("Debugger")
            if isinstance(dbg, str) and dbg.strip():
                out.append({
                    "location": f"HKLM\\SOFTWARE\\...\\Image File Execution Options\\{sk.name}",
                    "name": "Debugger", "command": dbg, "user": None, "key_last_write": sk.last_write,
                    "enabled": True, "non_default": True,
                })
    return out


# ----------------------------------------------------------------------------- installed applications

UNINSTALL_PATHS = [
    "Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]


def parse_installed_apps(software_root: Optional[RegKey], ntuser_root: Optional[RegKey], user: str = "") -> List[Dict]:
    out: List[Dict] = []
    roots = []
    if software_root is not None:
        roots.append(("machine", software_root))
    if ntuser_root is not None and ntuser_root.subkey("Software") is not None:
        roots.append((f"user:{user}" if user else "user", ntuser_root.subkey("Software")))
    for scope, root in roots:
        for rel in UNINSTALL_PATHS:
            key = root.subkey(rel)
            for app in (key.subkeys() if key is not None else []):
                name = app.value("DisplayName")
                if not name:
                    continue
                install_date = app.value("InstallDate")
                iso_date = None
                if isinstance(install_date, str) and re.fullmatch(r"\d{8}", install_date):
                    iso_date = f"{install_date[:4]}-{install_date[4:6]}-{install_date[6:]}"
                out.append({
                    "scope": scope,
                    "name": name,
                    "version": app.value("DisplayVersion"),
                    "publisher": app.value("Publisher"),
                    "install_date": iso_date,
                    "install_location": app.value("InstallLocation"),
                    "install_source": app.value("InstallSource"),
                    "uninstall_string": app.value("UninstallString"),
                    "system_component": bool(app.value("SystemComponent")),
                    "registry_key": app.path,
                    "key_last_write": app.last_write,
                    "wow64": "WOW6432Node" in rel,
                })
    return out


# ----------------------------------------------------------------------------- services

SERVICE_START = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
SERVICE_TYPES = {1: "kernel_driver", 2: "fs_driver", 0x10: "own_process", 0x20: "share_process",
                 0x50: "user_own_process", 0x60: "user_share_process", 0x110: "own_process_interactive",
                 0x120: "share_process_interactive"}


def parse_services(system_root: RegKey) -> List[Dict]:
    out: List[Dict] = []
    ccs = current_control_set(system_root)
    services = ccs.subkey("Services") if ccs is not None else None
    for svc in (services.subkeys() if services is not None else []):
        image = svc.value("ImagePath")
        stype = svc.value("Type")
        if image is None and stype is None:
            continue
        params = svc.subkey("Parameters")
        out.append({
            "name": svc.name,
            "display_name": svc.value("DisplayName"),
            "image_path": image,
            "service_dll": params.value("ServiceDll") if params is not None else None,
            "start_type": SERVICE_START.get(svc.value("Start"), svc.value("Start")),
            "service_type": SERVICE_TYPES.get(stype, stype),
            "account": svc.value("ObjectName"),
            "description": svc.value("Description"),
            "key_last_write": svc.last_write,
        })
    return out


# ----------------------------------------------------------------------------- MRU lists


def parse_recentdocs(ntuser_root: RegKey, user: str = "") -> List[Dict]:
    base = ntuser_root.subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    out: List[Dict] = []
    if base is None:
        return out
    for key, ext in [(base, "*")] + [(sk, sk.name) for sk in base.subkeys()]:
        order = _mru_order(key)
        for v in key.values():
            if not v.name.isdigit() or not isinstance(v.data, (bytes, bytearray)):
                continue
            raw = bytes(v.data)
            end = 0
            while end + 1 < len(raw) and raw[end:end + 2] != b"\x00\x00":
                end += 2
            name = raw[:end].decode("utf-16-le", "replace")
            pos = order.index(int(v.name)) if int(v.name) in order else None
            out.append({
                "user": user, "extension": ext, "name": name, "mru_position": pos,
                # The key's last-write time is the time the most recent (position 0) entry was opened.
                "opened_utc": key.last_write if pos == 0 else None,
                "key_last_write": key.last_write,
            })
    return out


def parse_run_mru(ntuser_root: RegKey, user: str = "") -> List[Dict]:
    out: List[Dict] = []
    key = ntuser_root.subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if key is not None:
        order = key.value("MRUList") or ""
        for v in key.values():
            if len(v.name) == 1 and isinstance(v.data, str):
                pos = order.find(v.name)
                out.append({"user": user, "source": "RunMRU", "value": v.data[:-2] if v.data.endswith("\\1") else v.data,
                            "mru_position": pos if pos >= 0 else None,
                            "used_utc": key.last_write if pos == 0 else None})
    key = ntuser_root.subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
    if key is not None:
        for v in key.values():
            if isinstance(v.data, str):
                out.append({"user": user, "source": "TypedPaths", "value": v.data,
                            "mru_position": int(v.name[3:]) - 1 if v.name[3:].isdigit() else None,
                            "used_utc": key.last_write if v.name.lower() == "url1" else None})
    return out


# ----------------------------------------------------------------------------- Amcache


def parse_amcache(root: RegKey) -> Dict[str, List[Dict]]:
    files: List[Dict] = []
    apps: List[Dict] = []
    inv = root.subkey("Root\\InventoryApplicationFile")
    for k in (inv.subkeys() if inv is not None else []):
        file_id = k.value("FileId") or ""
        sha1 = file_id[4:] if isinstance(file_id, str) and file_id.startswith("0000") and len(file_id) == 44 else None
        size = k.value("Size")
        files.append({
            "path": k.value("LowerCaseLongPath"),
            "name": k.value("Name"),
            "sha1": sha1,
            "publisher": k.value("Publisher"),
            "product_name": k.value("ProductName"),
            "version": k.value("Version"),
            "size": _to_int(size),
            "link_date": k.value("LinkDate"),
            "binary_type": k.value("BinaryType"),
            "is_os_component": bool(k.value("IsOsComponent")),
            "program_id": k.value("ProgramId"),
            "key_last_write": k.last_write,
        })
    legacy = root.subkey("Root\\File")
    for vol in (legacy.subkeys() if legacy is not None else []):
        for k in vol.subkeys():
            sha1 = k.value("101")
            files.append({
                "path": k.value("15"),
                "name": None,
                "sha1": sha1[4:] if isinstance(sha1, str) and sha1.startswith("0000") else sha1,
                "publisher": k.value("1"),
                "product_name": k.value("0"),
                "version": k.value("d"),
                "size": k.value("6"),
                "key_last_write": k.last_write,
                "format": "legacy",
            })
    inv_app = root.subkey("Root\\InventoryApplication")
    for k in (inv_app.subkeys() if inv_app is not None else []):
        apps.append({
            "name": k.value("Name"),
            "version": k.value("Version"),
            "publisher": k.value("Publisher"),
            "install_date": k.value("InstallDate"),
            "source": k.value("Source"),
            "root_dir": k.value("RootDirPath"),
            "uninstall_string": k.value("UninstallString"),
            "key_last_write": k.last_write,
        })
    return {"files": files, "applications": apps}


def _to_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return value
    return value


# ----------------------------------------------------------------------------- system details


def parse_system_details(system_root: Optional[RegKey], software_root: Optional[RegKey]) -> Dict:
    info: Dict = {}
    if software_root is not None:
        cv = software_root.subkey("Microsoft\\Windows NT\\CurrentVersion")
        if cv is not None:
            for name in ("ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild", "UBR", "EditionID",
                         "RegisteredOwner", "RegisteredOrganization", "InstallationType"):
                info[name] = cv.value(name)
            install = cv.value("InstallDate")
            if isinstance(install, int):
                from ..core.timeutil import unix_to_iso

                info["InstallDate"] = unix_to_iso(install)
        profiles = software_root.subkey("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        info["profiles"] = [
            {"sid": p.name, "profile_path": p.value("ProfileImagePath"), "key_last_write": p.last_write}
            for p in (profiles.subkeys() if profiles is not None else [])
        ]
    if system_root is not None:
        ccs = current_control_set(system_root)
        if ccs is not None:
            cn = ccs.subkey("Control\\ComputerName\\ComputerName")
            info["ComputerName"] = cn.value("ComputerName") if cn is not None else None
            tz = ccs.subkey("Control\\TimeZoneInformation")
            if tz is not None:
                info["TimeZoneKeyName"] = tz.value("TimeZoneKeyName")
                bias = tz.value("ActiveTimeBias")
                if isinstance(bias, int):
                    info["ActiveTimeBiasMinutes"] = bias - (1 << 32) if bias & 0x80000000 else bias
            win = ccs.subkey("Control\\Windows")
            sd = win.value("ShutdownTime") if win is not None else None
            if isinstance(sd, (bytes, bytearray)) and len(sd) >= 8:
                info["LastShutdownTime"] = filetime_to_iso(struct.unpack_from("<Q", sd)[0])
    return info


def id_list_path(data: bytes) -> str:
    from .shellitems import id_list_to_path

    return id_list_to_path(parse_id_list(data))
