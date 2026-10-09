"""File-system triage (NTFS metadata, hashes, ADS, PE/signature, suspicious indicators) and Recycle Bin."""

from __future__ import annotations

import os
import re
import stat
from typing import Dict, List, Optional

from ..core.config import expand
from ..core.context import CollectionContext
from ..core.hashing import try_sha256_file
from ..core.timeutil import unix_to_iso
from ..core.winapi import (IS_WINDOWS, decode_attributes, is_admin, list_alternate_streams, long_path,
                           ntfs_file_info, read_alternate_stream, strip_long_prefix)
from ..parsers.pe import EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS, parse_pe
from ..parsers.recyclebin import RecycleBinError, parse_recycle_i
from .base import Collector, register
from .signing import lookup, verify_signatures

USER_WRITABLE_HINTS = ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\users\\public\\", "\\desktop\\",
                       "\\programdata\\", "/downloads/", "/tmp/", "/desktop/")
DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png", ".zip", ".rar", ".rtf"}


def parse_zone_identifier(text: str) -> Dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    zone = out.get("ZoneId")
    return {"zone_id": int(zone) if zone and zone.isdigit() else zone, "referrer_url": out.get("ReferrerUrl"),
            "host_url": out.get("HostUrl")}


def suspicious_indicators(path: str, rec: Dict) -> List[str]:
    name = os.path.basename(path)
    low = name.lower()
    ext = os.path.splitext(low)[1]
    lpath = path.lower().replace("/", "\\") if IS_WINDOWS else path.lower()
    ind: List[str] = []
    if "‮" in name:
        ind.append("rtlo_character_in_name")
    parts = low.split(".")
    if len(parts) >= 3 and "." + parts[-2] in DOC_EXTS and ("." + parts[-1]) in (EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS):
        ind.append("double_extension")
    if re.search(r"\s{5,}\.\w+$", name):
        ind.append("padded_extension")
    is_pe = rec.get("pe") is not None
    if is_pe and ext not in EXECUTABLE_EXTENSIONS:
        ind.append("pe_with_non_executable_extension")
    if (is_pe or ext in SCRIPT_EXTENSIONS) and any(h in lpath + "\\" for h in USER_WRITABLE_HINTS):
        ind.append("executable_in_user_writable_location")
    sig = rec.get("signature") or {}
    if is_pe and sig.get("status") == "HashMismatch":
        ind.append("signature_hash_mismatch")
    elif is_pe and sig.get("status") == "NotSigned":
        ind.append("unsigned_executable")
    pe = rec.get("pe") or {}
    if pe.get("packed_suspected"):
        ind.append("high_entropy_or_packed")
    if pe.get("writable_executable_section"):
        ind.append("writable_executable_section")
    zone = rec.get("zone_identifier") or {}
    if (is_pe or ext in SCRIPT_EXTENSIONS) and zone.get("zone_id") in (3, 4):
        ind.append("downloaded_from_internet")
    other_ads = [a for a in rec.get("alternate_streams", []) if a["name"] not in ("Zone.Identifier", "SmartScreen")]
    if other_ads:
        ind.append("non_standard_alternate_data_stream")
    attrs = rec.get("attributes") or []
    if "HIDDEN" in attrs and "SYSTEM" in attrs and (is_pe or ext in SCRIPT_EXTENSIONS):
        ind.append("hidden_system_executable")
    return ind


@register
class FileSystemCollector(Collector):
    name = "filesystem"
    title = "File System Analysis"
    category = "File System"
    description = ("Scans configured high-value folders: MACB timestamps, NTFS file ID/attributes, SHA-256, "
                   "alternate data streams (Zone.Identifier), PE header details, Authenticode signatures and "
                   "suspicious-file indicators.")
    requires_admin = "partial"
    admin_note = "Folders of other users and protected locations require Administrator."
    windows_only = False

    def run(self, ctx: CollectionContext) -> None:
        cfg = ctx.config
        max_hash = cfg.fs_hash_max_mb * 1024 * 1024
        records: List[Dict] = []
        roots = []
        for p in cfg.fs_scan_paths:
            full = os.path.abspath(expand(p))
            if os.path.isdir(full) and full not in roots:
                roots.append(full)
        if not roots:
            ctx.error("none of the configured scan paths exist", "not_found")
        app_dir = os.path.normcase(ctx.session.session_dir)
        truncated = False
        for root in roots:
            for dirpath, dirs, files in os.walk(long_path(root), onerror=lambda e: ctx.error(
                    f"cannot list folder: {e}", "access_denied", getattr(e, "filename", None))):
                ctx.check_cancel()
                plain = strip_long_prefix(dirpath)
                if os.path.normcase(plain).startswith(app_dir):
                    dirs[:] = []  # never scan the kit's own output
                    continue
                rel = os.path.relpath(plain, root)
                depth = 0 if rel == "." else rel.count(os.sep) + 1
                if depth >= cfg.fs_max_depth:
                    dirs[:] = []
                for name in files:
                    if len(records) >= cfg.fs_max_files:
                        truncated = True
                        break
                    full = os.path.join(dirpath, name)
                    rec = self._inspect(full, max_hash)
                    if rec is not None:
                        records.append(rec)
                if truncated:
                    break
                ctx.progress(min(0.7, len(records) / max(1, cfg.fs_max_files)), dirpath)
            if truncated:
                break
        if truncated:
            ctx.error(f"file limit {cfg.fs_max_files} reached; remaining files not scanned", "error")
        pe_paths = [r["path_long"] for r in records if r.get("pe")]
        sigs = verify_signatures(ctx, pe_paths, "file system scan")
        for r in records:
            sig = lookup(sigs, r.get("path_long"))
            if sig:
                r["signature"] = sig
            r["indicators"] = suspicious_indicators(r["path"], r)
            r.pop("path_long", None)
            if r["indicators"] and cfg.fs_copy_suspicious and (r.get("size") or 0) <= cfg.fs_copy_max_mb * 1024 * 1024:
                item = ctx.acquire(r["path"], subdir="suspicious_files")
                r["evidence_copy"] = item.evidence_path if item else None
            ctx.add_event(r.get("created"), "FileSystem", "file_created", f"File created {r['path']}", "files", path=r["path"],
                          sha256=r.get("sha256"))
            if r.get("modified") and r.get("modified") != r.get("created"):
                ctx.add_event(r.get("modified"), "FileSystem", "file_modified", f"File modified {r['path']}", "files",
                              path=r["path"])
        ctx.write_records("files", records)

    def _inspect(self, full: str, max_hash: int) -> Optional[Dict]:
        display = full[4:] if full.startswith("\\\\?\\") else full
        try:
            st = os.stat(full, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        rec: Dict = {
            "path": display,
            "path_long": display,
            "name": os.path.basename(display),
            "extension": os.path.splitext(display)[1].lower(),
            "size": st.st_size,
            "created": unix_to_iso(getattr(st, "st_birthtime", None) or (st.st_ctime if IS_WINDOWS else None)),
            "modified": unix_to_iso(st.st_mtime),
            "accessed": unix_to_iso(st.st_atime),
            "metadata_changed": None if IS_WINDOWS else unix_to_iso(st.st_ctime),
            "attributes": decode_attributes(getattr(st, "st_file_attributes", 0)),
        }
        ntfs = ntfs_file_info(display)
        if ntfs:
            rec["ntfs"] = ntfs
        streams = list_alternate_streams(display)
        rec["alternate_streams"] = [{"name": s.name, "size": s.size} for s in streams]
        for s in streams:
            if s.name == "Zone.Identifier":
                raw = read_alternate_stream(display, s.name, 8192)
                if raw:
                    rec["zone_identifier"] = parse_zone_identifier(raw.decode("utf-8", "replace"))
        rec["sha256"] = try_sha256_file(display, max_hash)
        if rec["sha256"] is None and st.st_size <= max_hash:
            rec["hash_error"] = "unreadable (locked or access denied)"
        pe = parse_pe(display)
        if pe:
            rec["pe"] = pe
        return rec


@register
class RecycleBinCollector(Collector):
    name = "recycle_bin"
    title = "Recycle Bin"
    category = "File System"
    description = "$I metadata (original path, size, deletion time) from $Recycle.Bin on all fixed drives."
    requires_admin = "partial"
    admin_note = "Other users' Recycle Bin folders (other SIDs) require Administrator."

    def run(self, ctx: CollectionContext) -> None:
        drives = []
        try:
            import psutil

            drives = [p.mountpoint for p in psutil.disk_partitions(all=False) if "fixed" in (p.opts or "") or not IS_WINDOWS]
        except Exception:
            drives = [os.environ.get("SystemDrive", "C:") + "\\"]
        records: List[Dict] = []
        for drive in drives:
            rb = os.path.join(drive, "$Recycle.Bin")
            if not os.path.isdir(rb):
                continue
            try:
                sids = os.listdir(rb)
            except OSError as exc:
                ctx.error(f"cannot list {rb}: {exc}", "access_denied", rb)
                continue
            for sid in sids:
                folder = os.path.join(rb, sid)
                try:
                    names = os.listdir(folder)
                except OSError:
                    ctx.error(f"Recycle Bin of {sid} not readable", "requires_admin" if not is_admin() else "access_denied", folder)
                    continue
                for name in names:
                    ctx.check_cancel()
                    if not name.startswith("$I"):
                        continue
                    src = os.path.join(folder, name)
                    item = ctx.acquire(src, subdir=os.path.join(drive[:1] or "root", sid))
                    if item is None:
                        continue
                    try:
                        with open(ctx.session.path(*item.evidence_path.split("/")), "rb") as fh:
                            rec = parse_recycle_i(fh.read())
                    except (RecycleBinError, OSError) as exc:
                        ctx.error(f"cannot parse {name}: {exc}", "error", src)
                        continue
                    r_path = os.path.join(folder, "$R" + name[2:])
                    rec.update(sid=sid, drive=drive, i_file=name, r_file_present=os.path.exists(r_path))
                    if rec["r_file_present"]:
                        try:
                            rec["r_file_size"] = os.path.getsize(r_path)
                        except OSError:
                            pass
                    records.append(rec)
                    ctx.add_event(rec["deleted_utc"], "RecycleBin", "file_deleted",
                                  f"Deleted to Recycle Bin: {rec['original_path']} ({rec['original_size']} bytes, SID {sid})",
                                  "recycle_bin", path=rec["original_path"])
        ctx.write_records("recycle_bin", records)
