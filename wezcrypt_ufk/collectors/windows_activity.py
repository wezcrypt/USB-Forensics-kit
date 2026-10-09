"""Execution and user-activity collectors."""

from __future__ import annotations

import glob
import os
from typing import Dict, List

from ..analysis.eventdefs import CHANNELS, describe
from ..core import commands
from ..core.context import CollectionContext
from ..core.hashing import sha256_file
from ..core.paths import safe_name
from ..core.winapi import IS_WINDOWS, is_admin
from ..parsers import winreg_artifacts as wra
from ..parsers.evtx_xml import iter_events_file
from ..parsers.jumplist import (CFBError, app_id_from_filename, parse_automatic_destinations,
                                parse_custom_destinations)
from ..parsers.lnk import LnkError, parse_lnk
from ..parsers.prefetch import PrefetchError, parse_prefetch
from ..parsers.registry import Hive, HiveError
from ..parsers.setupapi import parse_setupapi
from .base import Collector, register
from .common import RegistryProvider, accessible_profiles

ERROR_EVT_CHANNEL_NOT_FOUND = 15007
QUERY_BATCH = 15


def _read_evidence(ctx: CollectionContext, item) -> bytes:
    with open(ctx.session.path(*item.evidence_path.split("/")), "rb") as fh:
        return fh.read()


@register
class EventLogsCollector(Collector):
    name = "event_logs"
    title = "Windows Event Logs (EVTX)"
    category = "Windows"
    description = ("Exports key channels with `wevtutil epl` (service-mediated copy, works on locked logs), "
                   "then parses forensic event IDs from the exported copy.")
    requires_admin = "partial"
    admin_note = "The Security and Sysmon channels require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        wevtutil = commands.system32("wevtutil.exe")
        tmp = ctx.session.path("analysis", "tmp")
        os.makedirs(tmp, exist_ok=True)
        total = len(CHANNELS)
        for i, (channel, key, ids, needs_admin) in enumerate(CHANNELS):
            ctx.check_cancel()
            ctx.progress(i / total, channel)
            dest = os.path.join(ctx.evidence_dir(), safe_name(channel.replace("/", "%4")) + ".evtx")
            res = commands.run([wevtutil, "epl", channel, dest], timeout=900)
            ctx.live_action(f"wevtutil epl {channel}", "Exports the log through the Event Log service; starts wevtutil.exe.")
            if not res.ok or not os.path.isfile(dest):
                if res.returncode == ERROR_EVT_CHANNEL_NOT_FOUND:
                    continue
                kind = "requires_admin" if needs_admin and not is_admin() else ("access_denied" if res.returncode == 5 else "error")
                ctx.error(f"could not export {channel}: {(res.stderr or res.stdout).strip()[:300]}", kind, channel)
                continue
            ctx.register_file(f"eventlog:{channel}", dest, os.path.getsize(dest), sha256_file(dest), "wevtutil_epl")
            count = 0
            # Event log XPath queries are limited in the number of OR clauses; query in small ID batches.
            for b, batch in enumerate(ids[j:j + QUERY_BATCH] for j in range(0, len(ids), QUERY_BATCH)):
                ctx.check_cancel()
                query = "*[System[(" + " or ".join(f"EventID={e}" for e in batch) + ")]]"
                xml_out = os.path.join(tmp, f"{key}_{b}.xml")
                q = commands.run([wevtutil, "qe", dest, "/lf:true", "/f:xml", "/rd:true",
                                  f"/c:{ctx.config.eventlog_max_events}", f"/q:{query}"], timeout=1800, stdout_path=xml_out)
                if not q.ok:
                    ctx.error(f"query of exported {channel} failed: {q.stderr.strip()[:300]}", "error", dest)
                    continue
                batch_count = 0

                def records(path=xml_out):
                    nonlocal batch_count
                    for rec in iter_events_file(path, ctx.config.script_block_max_chars):
                        batch_count += 1
                        etype, desc = describe(key, rec)
                        rec["channel_key"] = key
                        rec["event_type"] = etype
                        rec["description"] = desc
                        ctx.add_event(rec.get("time_created"), f"EventLog:{channel}", etype, desc, f"events_{key}",
                                      event_id=rec.get("event_id"), record_id=rec.get("record_id"),
                                      user_sid=rec.get("user_sid"))
                        yield rec

                ctx.write_records(f"events_{key}", records())
                count += batch_count
                if batch_count >= ctx.config.eventlog_max_events:
                    ctx.error(f"{channel}: event limit {ctx.config.eventlog_max_events} reached for IDs {batch[0]}..{batch[-1]}; "
                              "older matching events were not parsed (full log preserved in evidence)", "error")
                try:
                    os.remove(xml_out)
                except OSError:
                    pass
            ctx.log.info("%s: %d events parsed", channel, count)
        ctx.progress(1.0, "done")


@register
class PrefetchCollector(Collector):
    name = "prefetch"
    title = "Prefetch"
    category = "Windows"
    description = "Copies and parses C:\\Windows\\Prefetch\\*.pf (run counts, last 8 run times, loaded files, volumes)."
    requires_admin = "yes"
    admin_note = "The Prefetch folder is readable by Administrators only."

    def run(self, ctx: CollectionContext) -> None:
        folder = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        if not os.path.isdir(folder):
            ctx.error("Prefetch folder not found (prefetching may be disabled, e.g. on some SSD/VM systems)", "not_found", folder)
            return
        try:
            files = sorted(glob.glob(os.path.join(folder, "*.pf")))
        except OSError as exc:
            ctx.error(f"cannot list Prefetch: {exc}", "requires_admin", folder)
            return
        if not files and not is_admin():
            ctx.error("Prefetch folder not readable without Administrator", "requires_admin", folder)
            return
        records = []
        for i, src in enumerate(files):
            ctx.check_cancel()
            ctx.progress(i / max(1, len(files)), os.path.basename(src))
            item = ctx.acquire(src)
            if item is None:
                continue
            try:
                rec = parse_prefetch(_read_evidence(ctx, item))
            except (PrefetchError, ValueError) as exc:
                ctx.error(f"cannot parse {os.path.basename(src)}: {exc}", "error", src)
                continue
            rec["file"] = os.path.basename(src)
            rec["file_sha256"] = item.sha256
            rec["file_created"] = item.source_created
            records.append(rec)
            for t in rec["run_times"]:
                ctx.add_event(t, "Prefetch", "program_execution",
                              f"Executed {rec['executable']} (run count {rec['run_count']})", "prefetch",
                              path=rec.get("executable_path"))
        ctx.write_records("prefetch", records)


@register
class AmcacheCollector(Collector):
    name = "amcache"
    title = "Amcache"
    category = "Windows"
    description = ("Acquires Amcache.hve (locked by the OS) with the built-in `esentutl /y /vss` and parses "
                   "InventoryApplicationFile (path, SHA-1, publisher) and InventoryApplication.")
    requires_admin = "yes"
    admin_note = "esentutl /vss creates a temporary Volume Shadow Copy and requires Administrator."

    def run(self, ctx: CollectionContext) -> None:
        src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "AppCompat", "Programs", "Amcache.hve")
        if not os.path.isfile(src):
            ctx.error("Amcache.hve not found", "not_found", src)
            return
        if not is_admin():
            ctx.error("Amcache acquisition requires Administrator", "requires_admin", src)
            return
        dest = os.path.join(ctx.evidence_dir(), "Amcache.hve")
        res = commands.run([commands.system32("esentutl.exe"), "/y", src, "/vss", "/d", dest], timeout=900)
        ctx.live_action("esentutl /y Amcache.hve /vss",
                        "Creates and deletes a temporary Volume Shadow Copy (VSS events are logged; writes to the "
                        "system volume's shadow storage).")
        if not res.ok or not os.path.isfile(dest):
            ctx.error(f"esentutl copy failed: {(res.stderr or res.stdout).strip()[:300]}", "locked", src)
            return
        ctx.register_file(src, dest, os.path.getsize(dest), sha256_file(dest), "esentutl_vss_copy")
        try:
            with Hive(dest) as hive:
                data = wra.parse_amcache(hive.root())
        except (HiveError, OSError) as exc:
            ctx.error(f"cannot parse Amcache: {exc}", "error", dest)
            return
        for f in data["files"]:
            ctx.add_event(f.get("key_last_write"), "Amcache", "program_first_seen",
                          f"Amcache entry: {f.get('path') or f.get('name')} (SHA1 {f.get('sha1') or '-'})", "amcache_files",
                          path=f.get("path"), sha1=f.get("sha1"))
        ctx.write_records("amcache_files", data["files"])
        ctx.write_records("amcache_applications", data["applications"])


@register
class ShimcacheCollector(Collector):
    name = "shimcache"
    title = "Shimcache (AppCompatCache)"
    category = "Windows"
    description = "AppCompatCache entries from the SYSTEM hive (path, file last-modified time, cache position)."
    requires_admin = "partial"
    admin_note = "An offline SYSTEM hive copy requires Administrator; otherwise the live value is read if permitted."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        system = prov.machine("SYSTEM")
        if system is None:
            ctx.error("SYSTEM hive unavailable", "requires_admin" if not is_admin() else "error")
            return
        entries = wra.shimcache_from_system(system)
        if not entries:
            ctx.error("AppCompatCache value not found or unreadable", "requires_admin" if not is_admin() else "not_found")
        for e in entries:
            e["source"] = prov.source_notes.get("SYSTEM")
            ctx.add_event(e.get("last_modified"), "Shimcache", "file_modified",
                          f"Shimcache entry #{e['position']}: {e['path']} (file last modified; NOT proof of execution)",
                          "shimcache", path=e["path"])
        ctx.write_records("shimcache", entries)


@register
class UserAssistCollector(Collector):
    name = "userassist"
    title = "UserAssist"
    category = "Windows"
    description = "GUI program launches per user (ROT13-decoded) with run counts, focus time and last execution."
    requires_admin = "partial"
    admin_note = "Other users' NTUSER hives require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        records: List[Dict] = []
        for prof, nt, _, _ in prov.users():
            if nt is None:
                continue
            for r in wra.parse_userassist(nt, prof.username):
                records.append(r)
                ctx.add_event(r.get("last_executed"), "UserAssist", "program_execution",
                              f"{prof.username} launched {r['path']} (count {r.get('run_count')})", "userassist",
                              path=r["path"], user=prof.username)
        ctx.write_records("userassist", records)


@register
class ShellBagsCollector(Collector):
    name = "shellbags"
    title = "ShellBags"
    category = "Windows"
    description = "Folders browsed in Explorer (NTUSER and UsrClass BagMRU), including removed/network/USB paths."
    requires_admin = "partial"
    admin_note = "Other users' hives require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        records: List[Dict] = []
        for prof, nt, uc, _ in prov.users():
            for root, label, path in ((nt, "NTUSER", "Software\\Microsoft\\Windows\\Shell\\BagMRU"),
                                      (uc, "UsrClass", "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")):
                bag = root.subkey(path) if root is not None else None
                if bag is None:
                    continue
                for r in wra.parse_shellbags(bag, label, prof.username):
                    records.append(r)
                    ctx.add_event(r.get("key_last_write"), "ShellBags", "folder_accessed",
                                  f"{prof.username} browsed folder {r['path']}", "shellbags", user=prof.username)
        ctx.write_records("shellbags", records)


@register
class JumpListsCollector(Collector):
    name = "jump_lists"
    title = "Jump Lists"
    category = "Windows"
    description = "AutomaticDestinations (OLE + DestList) and CustomDestinations per user."
    requires_admin = "partial"
    admin_note = "Other users' profiles require Administrator."
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        records: List[Dict] = []
        for prof in accessible_profiles(ctx):
            recent = os.path.join(prof.path, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
            for sub, parser in (("AutomaticDestinations", parse_automatic_destinations),
                                ("CustomDestinations", parse_custom_destinations)):
                folder = os.path.join(recent, sub)
                if not os.path.isdir(folder):
                    continue
                for name in sorted(os.listdir(folder)):
                    ctx.check_cancel()
                    src = os.path.join(folder, name)
                    if not os.path.isfile(src):
                        continue
                    item = ctx.acquire(src, subdir=os.path.join(safe_name(prof.username), sub))
                    if item is None:
                        continue
                    try:
                        entries = parser(_read_evidence(ctx, item))
                    except (CFBError, ValueError, IndexError) as exc:
                        ctx.error(f"cannot parse jump list {name}: {exc}", "error", src)
                        continue
                    app = app_id_from_filename(name)
                    for e in entries:
                        e.update(user=prof.username, jumplist_file=name, jumplist_type=sub, **app)
                        records.append(e)
                        target = e.get("target_path") or e.get("destlist_path")
                        ctx.add_event(e.get("last_used") or e.get("target_accessed"), "JumpList", "file_opened",
                                      f"{prof.username} opened {target} via {app['app_hint'] or app['app_id']}",
                                      "jump_lists", path=target, user=prof.username)
        ctx.write_records("jump_lists", records)


def _parse_lnk_folder(ctx: CollectionContext, folder: str, user: str, label: str, records: List[Dict]) -> None:
    if not os.path.isdir(folder):
        return
    for name in sorted(os.listdir(folder)):
        ctx.check_cancel()
        if not name.lower().endswith(".lnk"):
            continue
        src = os.path.join(folder, name)
        item = ctx.acquire(src, subdir=os.path.join(safe_name(user), label))
        if item is None:
            continue
        try:
            rec = parse_lnk(_read_evidence(ctx, item))
        except (LnkError, ValueError, IndexError) as exc:
            ctx.error(f"cannot parse LNK {name}: {exc}", "error", src)
            continue
        rec.update(user=user, lnk_file=name, location=label, lnk_created=item.source_created,
                   lnk_modified=item.source_modified, lnk_sha256=item.sha256)
        records.append(rec)
        ctx.add_event(item.source_created, "LNK", "file_first_opened",
                      f"{user}: LNK created for {rec['target_path']} ({label}) - first open", "lnk_files",
                      path=rec["target_path"], user=user, volume_serial=rec.get("volume_serial"), drive_type=rec.get("drive_type"))
        if item.source_modified and item.source_modified != item.source_created:
            ctx.add_event(item.source_modified, "LNK", "file_last_opened",
                          f"{user}: LNK updated for {rec['target_path']} ({label}) - last open", "lnk_files",
                          path=rec["target_path"], user=user)


@register
class LnkFilesCollector(Collector):
    name = "lnk_files"
    title = "LNK Files"
    category = "Windows"
    description = "Shortcut files in Recent, Office Recent and Desktop: target path, MAC times, volume serial, drive type, machine ID."
    requires_admin = "partial"
    admin_note = "Other users' profiles require Administrator."
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        records: List[Dict] = []
        for prof in accessible_profiles(ctx):
            roaming = os.path.join(prof.path, "AppData", "Roaming", "Microsoft")
            _parse_lnk_folder(ctx, os.path.join(roaming, "Windows", "Recent"), prof.username, "Recent", records)
            _parse_lnk_folder(ctx, os.path.join(roaming, "Office", "Recent"), prof.username, "OfficeRecent", records)
            _parse_lnk_folder(ctx, os.path.join(prof.path, "Desktop"), prof.username, "Desktop", records)
        ctx.write_records("lnk_files", records)


@register
class RecentFilesCollector(Collector):
    name = "recent_files"
    title = "Recent Files & MRU"
    category = "Windows"
    description = "RecentDocs (per extension), RunMRU and Explorer TypedPaths per user."
    requires_admin = "partial"
    admin_note = "Other users' NTUSER hives require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        docs: List[Dict] = []
        mru: List[Dict] = []
        for prof, nt, _, _ in prov.users():
            if nt is None:
                continue
            for r in wra.parse_recentdocs(nt, prof.username):
                docs.append(r)
                ctx.add_event(r.get("opened_utc"), "RecentDocs", "file_opened",
                              f"{prof.username} opened {r['name']} (most recent .{r['extension']})", "recent_docs",
                              user=prof.username)
            for r in wra.parse_run_mru(nt, prof.username):
                mru.append(r)
                ctx.add_event(r.get("used_utc"), r["source"], "typed_command",
                              f"{prof.username} typed '{r['value']}' ({r['source']})", "run_mru", user=prof.username)
        ctx.write_records("recent_docs", docs)
        ctx.write_records("run_mru", mru)


@register
class UsbHistoryCollector(Collector):
    name = "usb_history"
    title = "USB Device History"
    category = "Windows"
    description = ("USBSTOR/USB enumeration keys (first install, last arrival/removal), Portable Devices labels, "
                   "MountedDevices, MountPoints2 per user and setupapi.dev.log first-install times.")
    requires_admin = "partial"
    admin_note = "Device property timestamps (Properties key) and setupapi.dev.log are reliably readable as Administrator."

    def run(self, ctx: CollectionContext) -> None:
        prov = RegistryProvider.for_session(ctx)
        system, software = prov.machine("SYSTEM"), prov.machine("SOFTWARE")
        devices = wra.parse_usb_devices(system, software) if system is not None else []
        for d in devices:
            label = f"{d.get('vendor') or d.get('vid') or ''} {d.get('product') or d.get('pid') or ''} serial {d['serial']}".strip()
            if d.get("friendly_name"):
                label = f"{d['friendly_name']} ({label})"
            for field, etype, verb in (("first_install", "usb_first_install", "first installed"),
                                       ("last_arrival", "usb_connected", "last connected"),
                                       ("last_removal", "usb_removed", "last removed")):
                ctx.add_event(d.get(field), "USB", etype, f"USB device {verb}: {label}", "usb_devices",
                              serial=d["serial"], source=d["source"])
            if not any(d.get(f) for f in ("first_install", "last_arrival", "last_removal")):
                ctx.add_event(d.get("key_last_write"), "USB", "usb_key_updated",
                              f"USB device key last written: {label}", "usb_devices", serial=d["serial"])
        ctx.write_records("usb_devices", devices)
        mounts = []
        for prof, nt, _, _ in prov.users():
            if nt is not None:
                for m in wra.parse_mountpoints2(nt, prof.username):
                    mounts.append(m)
                    ctx.add_event(m.get("key_last_write"), "Registry", "volume_mounted_by_user",
                                  f"{prof.username} MountPoints2 {m['mount_point']}", "mountpoints2", user=prof.username)
        ctx.write_records("mountpoints2", mounts)
        log = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "INF", "setupapi.dev.log")
        if os.path.isfile(log):
            item = ctx.acquire(log)
            if item is not None:
                with open(ctx.session.path(*item.evidence_path.split("/")), "r", encoding="utf-8", errors="replace") as fh:
                    installs = parse_setupapi(fh)
                ctx.write_records("setupapi_usb_installs", installs)
        elif IS_WINDOWS:  # pragma: no cover
            ctx.error("setupapi.dev.log not found", "not_found", log)
