"""System-state collectors: system info, registry hives, processes, services, startup, applications, tasks."""

from __future__ import annotations

import os
import platform
import socket
import time
from typing import Dict, List, Optional

from ..core.context import CollectionContext
from ..core.hashing import try_sha256_file
from ..core.paths import detect_run_location
from ..core.timeutil import unix_to_iso, utc_now_iso
from ..core.winapi import IS_WINDOWS, is_admin
from ..parsers import winreg_artifacts as wra
from ..parsers.lnk import LnkError, parse_lnk
from ..parsers.tasks import parse_task_xml, split_schtasks_xml
from .base import Collector, register
from .common import RegistryProvider, accessible_profiles
from .signing import lookup, verify_signatures


def _psutil():
    try:
        import psutil

        return psutil
    except ImportError:  # pragma: no cover
        return None


@register
class SystemInfoCollector(Collector):
    name = "system_info"
    title = "System Information"
    category = "System"
    description = "Host identity, OS build, time zone, boot time, logged-on users, disks and clock reference."
    requires_admin = "no"
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        ps = _psutil()
        info: Dict = {
            "collected_utc": utc_now_iso(),
            "local_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "utc_offset_seconds": -time.altzone if time.daylight and time.localtime().tm_isdst else -time.timezone,
            "tzname": list(time.tzname),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "examiner_is_admin": is_admin(),
            "kit_run_location": detect_run_location().to_dict(),
            "environment": {k: os.environ.get(k) for k in ("USERNAME", "USERDOMAIN", "COMPUTERNAME",
                                                           "PROCESSOR_ARCHITECTURE", "SystemRoot", "SystemDrive")},
        }
        if ps is not None:
            boot = ps.boot_time()
            info["boot_time_utc"] = unix_to_iso(boot)
            info["cpu_count_logical"] = ps.cpu_count()
            info["memory_total_bytes"] = ps.virtual_memory().total
            info["logged_on_users"] = [{"name": u.name, "terminal": u.terminal, "host": u.host,
                                        "started_utc": unix_to_iso(u.started)} for u in ps.users()]
            disks = []
            for part in ps.disk_partitions(all=False):
                entry = {"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype, "opts": part.opts}
                try:
                    usage = ps.disk_usage(part.mountpoint)
                    entry.update(total=usage.total, used=usage.used, free=usage.free)
                except OSError:
                    pass
                disks.append(entry)
            info["disks"] = disks
            ctx.add_event(info["boot_time_utc"], "System", "system_boot", "System booted (current uptime start)",
                          "system_info")
        if IS_WINDOWS:  # pragma: no cover
            prov = RegistryProvider.for_session(ctx)
            details = wra.parse_system_details(prov.machine("SYSTEM"), prov.machine("SOFTWARE"))
            info["registry"] = details
            if details.get("InstallDate"):
                ctx.add_event(details["InstallDate"], "Registry", "os_installed",
                              f"Windows installed ({details.get('ProductName')} {details.get('DisplayVersion') or ''})",
                              "system_info")
            if details.get("LastShutdownTime"):
                ctx.add_event(details["LastShutdownTime"], "Registry", "shutdown", "Last recorded shutdown", "system_info")
            for prof in details.get("profiles") or []:
                if prof.get("key_last_write"):
                    ctx.add_event(prof["key_last_write"], "Registry", "profile_key_updated",
                                  f"User profile key last written {prof.get('sid')} ({prof.get('profile_path')})", "system_info")
        ctx.write_records("system_info", [info])


@register
class RegistryHivesCollector(Collector):
    name = "registry"
    title = "Windows Registry Hives"
    category = "Windows"
    description = ("Exports SYSTEM, SOFTWARE and per-user NTUSER/UsrClass hives (reg save) as hashed evidence. "
                   "SAM/SECURITY are never exported. Falls back to read-only live registry access.")
    requires_admin = "partial"
    admin_note = "Exporting HKLM hives and other users' hives requires Administrator; without it the live registry is read."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        recs = []
        for name in ("SYSTEM", "SOFTWARE"):
            root = prov.machine(name)
            recs.append({"hive": name, "available": root is not None, "source": prov.source_notes.get(name)})
        for prof, nt, uc, source in prov.users():
            recs.append({"hive": f"NTUSER ({prof.username})", "available": nt is not None, "source": source,
                         "sid": prof.sid})
            recs.append({"hive": f"UsrClass ({prof.username})", "available": uc is not None, "source": source,
                         "sid": prof.sid})
        ctx.write_records("hive_sources", recs)


@register
class ProcessesCollector(Collector):
    name = "processes"
    title = "Running Processes"
    category = "Windows"
    description = "Live process list with parent, command line, owner, executable SHA-256 and Authenticode status."
    requires_admin = "partial"
    admin_note = "Command lines/paths of other users' and system processes require Administrator."
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        ps = _psutil()
        if ps is None:  # pragma: no cover
            ctx.error("psutil not available", "error")
            return
        procs: List[Dict] = []
        denied = 0
        names: Dict[int, str] = {}
        for p in ps.process_iter():
            ctx.check_cancel()
            rec: Dict = {"pid": p.pid}
            try:
                with p.oneshot():
                    rec["name"] = p.name()
                    rec["ppid"] = p.ppid()
                    rec["create_time"] = unix_to_iso(p.create_time())
                    rec["status"] = p.status()
                    for attr in ("exe", "cmdline", "username", "cwd", "num_threads"):
                        try:
                            val = getattr(p, attr)()
                            rec[attr] = " ".join(val) if attr == "cmdline" and isinstance(val, list) else val
                        except (ps.AccessDenied, ps.ZombieProcess, OSError):
                            rec[attr] = None
                            if attr in ("exe", "cmdline"):
                                rec["access_limited"] = True
                    try:
                        rec["memory_rss"] = p.memory_info().rss
                    except (ps.AccessDenied, OSError):
                        rec["memory_rss"] = None
            except ps.NoSuchProcess:
                continue
            except ps.AccessDenied:
                denied += 1
                rec["access_limited"] = True
            names[p.pid] = rec.get("name") or ""
            procs.append(rec)
        for rec in procs:
            rec["parent_name"] = names.get(rec.get("ppid"))
        if ctx.config.hash_process_executables:
            cache: Dict[str, Optional[str]] = {}
            for rec in procs:
                exe = rec.get("exe")
                if exe:
                    if exe not in cache:
                        cache[exe] = try_sha256_file(exe, ctx.config.fs_hash_max_mb * 1024 * 1024)
                    rec["exe_sha256"] = cache[exe]
        sigs = verify_signatures(ctx, [r.get("exe") for r in procs], "process executables")
        for rec in procs:
            sig = lookup(sigs, rec.get("exe"))
            if sig:
                rec["signature_status"] = sig["status"]
                rec["signer"] = sig["signer"]
        if denied or any(r.get("access_limited") for r in procs):
            limited = sum(1 for r in procs if r.get("access_limited"))
            ctx.error(f"{limited} processes returned limited details (access denied)",
                      "requires_admin" if not is_admin() else "access_denied")
        for rec in procs:
            ctx.add_event(rec.get("create_time"), "Process", "process_start",
                          f"Process started {rec.get('name')} (PID {rec['pid']}, parent {rec.get('parent_name')})",
                          "processes", path=rec.get("exe"), cmdline=(rec.get("cmdline") or "")[:500])
        ctx.write_records("processes", procs)


@register
class ServicesCollector(Collector):
    name = "services"
    title = "Windows Services"
    category = "Windows"
    description = "Service configuration from the SYSTEM hive merged with live status (Service Control Manager)."
    requires_admin = "no"

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        system = prov.machine("SYSTEM")
        services = wra.parse_services(system) if system is not None else []
        live: Dict[str, Dict] = {}
        ps = _psutil()
        if ps is not None and hasattr(ps, "win_service_iter"):  # pragma: no cover
            for svc in ps.win_service_iter():
                try:
                    d = svc.as_dict()
                    live[d["name"].lower()] = d
                except Exception:
                    continue
        for s in services:
            ld = live.get(s["name"].lower())
            if ld:
                s["status"] = ld.get("status")
                s["pid"] = ld.get("pid")
                s["binpath_live"] = ld.get("binpath")
            ctx.add_event(s.get("key_last_write"), "Registry", "service_key_modified",
                          f"Service key last written: {s['name']} ({s.get('image_path')})", "services")
        if not services and live:  # pragma: no cover
            services = [{"name": d["name"], "display_name": d.get("display_name"), "image_path": d.get("binpath"),
                         "start_type": d.get("start_type"), "account": d.get("username"), "status": d.get("status"),
                         "pid": d.get("pid"), "description": d.get("description")} for d in live.values()]
        ctx.write_records("services", services)


@register
class StartupCollector(Collector):
    name = "startup_programs"
    title = "Startup Programs"
    category = "Windows"
    description = "Run/RunOnce keys (HKLM/HKCU, WOW64), StartupApproved state, Winlogon, AppInit_DLLs, IFEO debuggers and Startup folders."
    requires_admin = "partial"
    admin_note = "Other users' Run keys and Startup folders require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        software = prov.machine("SOFTWARE")
        records: List[Dict] = wra.parse_run_keys(software, None)
        for prof, nt, _, _ in prov.users():
            if nt is not None:
                records.extend(wra.parse_run_keys(None, nt, prof.username))
        folders = [(None, os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"))]
        for prof in accessible_profiles(ctx):
            folders.append((prof.username, os.path.join(prof.path, "AppData", "Roaming", "Microsoft", "Windows",
                                                       "Start Menu", "Programs", "Startup")))
        for user, folder in folders:
            if not os.path.isdir(folder):
                continue
            for name in os.listdir(folder):
                full = os.path.join(folder, name)
                if not os.path.isfile(full) or name.lower() == "desktop.ini":
                    continue
                item = ctx.acquire(full, subdir="startup_folders")
                rec = {"location": folder, "name": name, "user": user, "command": full, "enabled": True,
                       "file_created": item.source_created if item else None,
                       "file_modified": item.source_modified if item else None,
                       "sha256": item.sha256 if item else None}
                if name.lower().endswith(".lnk") and item:
                    try:
                        with open(ctx.session.path(*item.evidence_path.split("/")), "rb") as fh:
                            lnk = parse_lnk(fh.read())
                        rec["command"] = " ".join(filter(None, [lnk.get("target_path"), lnk.get("arguments")]))
                    except (LnkError, OSError, ValueError) as exc:
                        rec["lnk_error"] = str(exc)
                records.append(rec)
        for r in records:
            ctx.add_event(r.get("key_last_write") or r.get("file_created"), "Startup", "persistence_entry",
                          f"Startup entry {r['name']} -> {str(r.get('command'))[:200]} ({r['location']})", "startup_programs")
        ctx.write_records("startup_entries", records)


@register
class InstalledAppsCollector(Collector):
    name = "installed_apps"
    title = "Installed Applications"
    category = "Windows"
    description = "Uninstall registry entries (machine 64/32-bit and per-user)."
    requires_admin = "no"

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        apps = wra.parse_installed_apps(prov.machine("SOFTWARE"), None)
        for prof, nt, _, _ in prov.users():
            if nt is not None:
                apps.extend(wra.parse_installed_apps(None, nt, prof.username))
        for a in apps:
            ts = (a["install_date"] + "T00:00:00.000000Z") if a.get("install_date") else None
            ctx.add_event(ts, "Registry", "application_installed",
                          f"Installed: {a['name']} {a.get('version') or ''} ({a.get('publisher') or 'unknown publisher'}) [date only]",
                          "installed_apps")
        ctx.write_records("installed_apps", apps)


@register
class ScheduledTasksCollector(Collector):
    name = "scheduled_tasks"
    title = "Scheduled Tasks"
    category = "Windows"
    description = "Task definitions from C:\\Windows\\System32\\Tasks (admin) or `schtasks /query /xml` (standard user)."
    requires_admin = "partial"
    admin_note = "Reading the Tasks folder requires Administrator; standard users see only tasks visible to them."

    def run(self, ctx: CollectionContext) -> None:
        tasks: List[Dict] = []
        root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
        used_folder = False
        if is_admin() and os.path.isdir(root):
            used_folder = True
            for dirpath, _, files in os.walk(root):
                for name in files:
                    ctx.check_cancel()
                    src = os.path.join(dirpath, name)
                    rel = os.path.relpath(src, root)
                    item = ctx.acquire(src, rel.replace(os.sep, "__"), subdir="Tasks")
                    if item is None:
                        continue
                    try:
                        raw = open(ctx.session.path(*item.evidence_path.split("/")), "rb").read()
                        text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8-sig", "replace")
                        rec = parse_task_xml(text, "\\" + rel)
                        rec["file_sha256"] = item.sha256
                        rec["file_modified"] = item.source_modified
                        rec["file_created"] = item.source_created
                        tasks.append(rec)
                    except Exception as exc:
                        ctx.error(f"cannot parse task {rel}: {exc}", "error", src)
        if not used_folder and IS_WINDOWS:  # pragma: no cover
            from ..core import commands

            res = ctx.run_command([commands.system32("schtasks.exe"), "/query", "/xml", "ONE"], name=None, timeout=180)
            if res.ok:
                ctx.save_text("schtasks_query.xml", res.stdout, "schtasks /query /xml ONE")
                for name, xml in split_schtasks_xml(res.stdout):
                    try:
                        tasks.append(parse_task_xml(xml, name))
                    except Exception as exc:
                        ctx.error(f"cannot parse task {name}: {exc}", "error")
            else:
                ctx.error(f"schtasks failed: {res.stderr.strip()}", "error")
            if not is_admin():
                ctx.error("Tasks folder not read (requires Administrator); used schtasks output instead", "requires_admin")
        for t in tasks:
            ctx.add_event(t.get("registration_date"), "Task", "task_registered",
                          f"Scheduled task registered {t['name']} -> {t.get('command_line') or ''}"[:400], "scheduled_tasks")
            ctx.add_event(t.get("file_created"), "Task", "task_file_created",
                          f"Task file created {t['name']}", "scheduled_tasks")
        ctx.write_records("scheduled_tasks", tasks)
