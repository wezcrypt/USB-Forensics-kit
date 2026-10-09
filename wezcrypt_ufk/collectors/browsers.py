"""Browser collectors - one module per browser so each gets its own report section and file."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import uuid
from typing import Dict, List, Optional, Tuple

from ..core import commands
from ..core.context import CollectionContext
from ..core.hashing import sha256_file
from ..core.paths import safe_name
from ..core.winapi import IS_WINDOWS, is_admin
from ..parsers import browsers as bp
from .base import Collector, register
from .common import UserProfile, accessible_profiles

SQLITE_SIDECARS = ("-wal", "-journal", "-shm")


class BrowserCollector(Collector):
    category = "Browsers"
    requires_admin = "partial"
    admin_note = "Other users' browser profiles require Administrator."
    windows_only = False
    browser_key = ""
    engine = "chromium"

    def profile_dirs(self, prof: UserProfile) -> List[Tuple[str, str]]:
        raise NotImplementedError

    # ------------------------------------------------------------------ helpers

    def _acquire(self, ctx: CollectionContext, src: str, subdir: str, keep: bool = True,
                 workdir: Optional[str] = None):
        """Acquire src as evidence (keep=True) or into workdir only (keep=False). Handles locked files."""
        if keep:
            item = ctx.acquire(src, subdir=subdir, record_error=False)
        else:
            item = ctx.acquire(src, dest_dir=workdir, record_error=False)
        if item is not None:
            return item
        err = ctx.last_acquire_error
        if err is not None and err.kind == "locked" and ctx.config.use_vss_for_locked and is_admin() and IS_WINDOWS:
            dest_dir = ctx.evidence_dir(subdir) if keep else workdir
            dest = os.path.join(dest_dir, os.path.basename(src))
            res = commands.run([commands.system32("esentutl.exe"), "/y", src, "/vss", "/d", dest], timeout=600)
            ctx.live_action(f"esentutl /y /vss {os.path.basename(src)}",
                            "Creates a temporary Volume Shadow Copy to read a locked file.")
            if res.ok and os.path.isfile(dest):
                digest = sha256_file(dest)
                if keep:
                    return ctx.register_file(src, dest, os.path.getsize(dest), digest, "esentutl_vss_copy")
                from ..core.models import AcquiredFile
                from ..core.timeutil import utc_now_iso

                return AcquiredFile(ctx.module, src, dest, os.path.getsize(dest), digest, "esentutl_vss_copy", utc_now_iso())
        if err is not None:
            hint = " (browser running? enable 'use VSS for locked files' as Administrator)" if err.kind == "locked" else ""
            ctx.error(f"could not acquire {os.path.basename(src)}{hint}: {err}", err.kind, src)
        return None

    def _working_db(self, ctx: CollectionContext, src_db: str, subdir: str, keep: bool, tmp_root: str) -> Optional[str]:
        """Acquire a SQLite DB (+ sidecars) and return the path of a disposable working copy for querying."""
        if not os.path.isfile(src_db):
            return None
        work = os.path.join(tmp_root, uuid.uuid4().hex)
        os.makedirs(work, exist_ok=True)
        main = self._acquire(ctx, src_db, subdir, keep, work)
        if main is None:
            return None
        base = os.path.basename(src_db)
        if keep:  # query a disposable copy so the preserved evidence file is never opened by SQLite
            shutil.copyfile(ctx.session.path(*main.evidence_path.split("/")), os.path.join(work, base))
        for suffix in ("-wal", "-journal"):
            side = src_db + suffix
            if os.path.isfile(side):
                item = self._acquire(ctx, side, subdir, keep, work)
                if item is not None and keep:
                    shutil.copyfile(ctx.session.path(*item.evidence_path.split("/")), os.path.join(work, base + suffix))
        return os.path.join(work, base)

    def _safe_query(self, ctx: CollectionContext, label: str, gen) -> List[Dict]:
        try:
            return list(gen)
        except sqlite3.DatabaseError as exc:
            ctx.error(f"{label}: database error {exc}", "error")
            return []

    # ------------------------------------------------------------------ main

    def run(self, ctx: CollectionContext) -> None:
        tmp_root = ctx.session.path("analysis", "tmp", ctx.module)
        os.makedirs(tmp_root, exist_ok=True)
        found = 0
        try:
            for prof in accessible_profiles(ctx):
                for profile_name, pdir in self.profile_dirs(prof):
                    ctx.check_cancel()
                    found += 1
                    label = f"{prof.username}/{profile_name}"
                    subdir = os.path.join(safe_name(prof.username), safe_name(profile_name))
                    ctx.progress(0.1, label)
                    if self.engine == "firefox":
                        self._firefox(ctx, prof.username, profile_name, pdir, subdir, tmp_root)
                    else:
                        self._chromium(ctx, prof.username, profile_name, pdir, subdir, tmp_root)
        finally:
            shutil.rmtree(tmp_root, ignore_errors=True)
        ctx.write_records("profiles_found", [{"browser": self.title, "profiles": found}])

    def _emit(self, ctx: CollectionContext, artifact: str, rows: List[Dict], user: str, profile: str) -> None:
        for r in rows:
            r["browser"] = self.title
            r["user"] = user
            r["profile"] = profile
        ctx.write_records(artifact, rows)

    def _chromium(self, ctx, user, profile, pdir, subdir, tmp_root) -> None:
        limit = ctx.config.browser_max_rows
        src = f"{self.title} {user}/{profile}"
        hist_db = self._working_db(ctx, os.path.join(pdir, "History"), subdir, True, tmp_root)
        if hist_db:
            visits = self._safe_query(ctx, f"{src} history", bp.chromium_history(hist_db, limit))
            for v in visits:
                ctx.add_event(v["visit_time"], f"Browser:{self.title}", "web_visit",
                              f"[{user}/{profile}] Visited {v['url'][:300]} ({v.get('transition')})", "history",
                              url=v["url"], title=v.get("title"))
            self._emit(ctx, "history", visits, user, profile)
            downloads = self._safe_query(ctx, f"{src} downloads", bp.chromium_downloads(hist_db, limit))
            for d in downloads:
                ctx.add_event(d["start_time"], f"Browser:{self.title}", "file_download",
                              f"[{user}/{profile}] Downloaded {d.get('target_path')} from {str(d.get('source_url'))[:300]}",
                              "downloads", url=d.get("source_url"), path=d.get("target_path"), danger=d.get("danger_type"))
            self._emit(ctx, "downloads", downloads, user, profile)
            if len(visits) >= limit:
                ctx.error(f"{src}: history limited to newest {limit} visits (full database preserved)", "error")
        bm = os.path.join(pdir, "Bookmarks")
        if os.path.isfile(bm):
            item = self._acquire(ctx, bm, subdir)
            if item:
                try:
                    marks = bp.chromium_bookmarks(ctx.session.path(*item.evidence_path.split("/")))
                    for b in marks:
                        ctx.add_event(b.get("added"), f"Browser:{self.title}", "bookmark_added",
                                      f"[{user}/{profile}] Bookmark added {b.get('name')} -> {str(b.get('url'))[:300]}",
                                      "bookmarks", url=b.get("url"))
                    self._emit(ctx, "bookmarks", marks, user, profile)
                except (ValueError, OSError) as exc:
                    ctx.error(f"{src}: bookmarks parse error {exc}", "error", bm)
        prefs: Dict = {}
        for fname in ("Preferences", "Secure Preferences"):
            path = os.path.join(pdir, fname)
            if os.path.isfile(path):
                item = self._acquire(ctx, path, subdir)
                if item:
                    try:
                        with open(ctx.session.path(*item.evidence_path.split("/")), "r", encoding="utf-8") as fh:
                            data = json.load(fh)
                        settings = ((data.get("extensions") or {}).get("settings")) or {}
                        prefs.setdefault("extensions", {}).setdefault("settings", {}).update(settings)
                    except (ValueError, OSError) as exc:
                        ctx.error(f"{src}: {fname} parse error {exc}", "error", path)
        exts = bp.chromium_extensions(pdir, prefs)
        for e in exts:
            ctx.add_event(e.get("install_time"), f"Browser:{self.title}", "extension_installed",
                          f"[{user}/{profile}] Extension installed {e.get('name')} ({e['id']})", "extensions")
        self._emit(ctx, "extensions", exts, user, profile)
        cookie_src = os.path.join(pdir, "Network", "Cookies")
        if not os.path.isfile(cookie_src):
            cookie_src = os.path.join(pdir, "Cookies")
        # Cookies DB is NOT kept as evidence (it holds encrypted values); only metadata is extracted.
        cdb = self._working_db(ctx, cookie_src, subdir, False, tmp_root)
        if cdb:
            cookies = self._safe_query(ctx, f"{src} cookies", bp.chromium_cookies_metadata(cdb, limit))
            self._emit(ctx, "cookies_metadata", cookies, user, profile)
        if ctx.config.collect_browser_cache_index:
            self._emit(ctx, "cache_entries", self._chromium_cache(ctx, pdir, limit), user, profile)

    def _chromium_cache(self, ctx, pdir, limit) -> List[Dict]:
        """Cache keys read in place (read-only) - cache content itself is not copied."""
        out: List[Dict] = []
        for cache_dir in (os.path.join(pdir, "Cache", "Cache_Data"), os.path.join(pdir, "Cache")):
            if not os.path.isdir(cache_dir):
                continue
            data_1 = os.path.join(cache_dir, "data_1")
            if os.path.isfile(data_1):
                out.extend(bp.chromium_blockfile_entries(data_1, limit))
            for name in os.listdir(cache_dir):
                if len(out) >= limit:
                    break
                if name.endswith("_0"):
                    entry = bp.chromium_simple_cache_entry(os.path.join(cache_dir, name))
                    if entry:
                        out.append(entry)
            if out:
                break
        return out[:limit]

    def _firefox(self, ctx, user, profile, pdir, subdir, tmp_root) -> None:
        limit = ctx.config.browser_max_rows
        src = f"Firefox {user}/{profile}"
        places = self._working_db(ctx, os.path.join(pdir, "places.sqlite"), subdir, True, tmp_root)
        if places:
            visits = self._safe_query(ctx, f"{src} history", bp.firefox_history(places, limit))
            for v in visits:
                ctx.add_event(v["visit_time"], "Browser:Firefox", "web_visit",
                              f"[{user}/{profile}] Visited {v['url'][:300]} ({v.get('transition')})", "history", url=v["url"])
            self._emit(ctx, "history", visits, user, profile)
            downloads = self._safe_query(ctx, f"{src} downloads", bp.firefox_downloads(places, limit))
            for d in downloads:
                ctx.add_event(d.get("start_time"), "Browser:Firefox", "file_download",
                              f"[{user}/{profile}] Downloaded {d.get('target_path')} from {str(d.get('source_url'))[:300]}",
                              "downloads", url=d.get("source_url"), path=d.get("target_path"))
            self._emit(ctx, "downloads", downloads, user, profile)
            try:
                marks = bp.firefox_bookmarks(places)
            except sqlite3.DatabaseError as exc:
                ctx.error(f"{src}: bookmarks {exc}", "error")
                marks = []
            for b in marks:
                ctx.add_event(b.get("added"), "Browser:Firefox", "bookmark_added",
                              f"[{user}/{profile}] Bookmark added {b.get('name')} -> {str(b.get('url'))[:300]}", "bookmarks")
            self._emit(ctx, "bookmarks", marks, user, profile)
        ext = os.path.join(pdir, "extensions.json")
        if os.path.isfile(ext):
            item = self._acquire(ctx, ext, subdir)
            if item:
                try:
                    exts = bp.firefox_extensions(ctx.session.path(*item.evidence_path.split("/")))
                    for e in exts:
                        ctx.add_event(e.get("install_time"), "Browser:Firefox", "extension_installed",
                                      f"[{user}/{profile}] Add-on installed {e.get('name')} ({e.get('id')})", "extensions")
                    self._emit(ctx, "extensions", exts, user, profile)
                except (ValueError, OSError) as exc:
                    ctx.error(f"{src}: extensions.json {exc}", "error", ext)
        cdb = self._working_db(ctx, os.path.join(pdir, "cookies.sqlite"), subdir, False, tmp_root)
        if cdb:
            self._emit(ctx, "cookies_metadata",
                       self._safe_query(ctx, f"{src} cookies", bp.firefox_cookies_metadata(cdb, limit)), user, profile)
        if ctx.config.collect_browser_cache_index:
            entries: List[Dict] = []
            local = pdir.replace(os.sep + "Roaming" + os.sep, os.sep + "Local" + os.sep)
            cache = os.path.join(local, "cache2", "entries")
            if os.path.isdir(cache):
                for name in os.listdir(cache)[:limit]:
                    e = bp.firefox_cache2_entry(os.path.join(cache, name))
                    if e:
                        entries.append(e)
            self._emit(ctx, "cache_entries", entries, user, profile)


def _chromium_profiles(user_data: str) -> List[Tuple[str, str]]:
    if not os.path.isdir(user_data):
        return []
    if os.path.isfile(os.path.join(user_data, "History")) or os.path.isfile(os.path.join(user_data, "Preferences")):
        return [("Default", user_data)]  # Opera keeps the profile at the root
    out = []
    for name in sorted(os.listdir(user_data)):
        p = os.path.join(user_data, name)
        if os.path.isdir(p) and (os.path.isfile(os.path.join(p, "History")) or os.path.isfile(os.path.join(p, "Preferences"))):
            out.append((name, p))
    return out


def _local(prof: UserProfile, *parts: str) -> str:
    return os.path.join(prof.path, "AppData", "Local", *parts)


def _roaming(prof: UserProfile, *parts: str) -> str:
    return os.path.join(prof.path, "AppData", "Roaming", *parts)


@register
class ChromeCollector(BrowserCollector):
    name = "browser_chrome"
    title = "Google Chrome"
    browser_key = "chrome"
    description = "History, downloads, bookmarks, extensions, cookie metadata (no values) and cache index."

    def profile_dirs(self, prof):
        return _chromium_profiles(_local(prof, "Google", "Chrome", "User Data"))


@register
class EdgeCollector(BrowserCollector):
    name = "browser_edge"
    title = "Microsoft Edge"
    browser_key = "edge"
    description = "History, downloads, bookmarks, extensions, cookie metadata (no values) and cache index."

    def profile_dirs(self, prof):
        return _chromium_profiles(_local(prof, "Microsoft", "Edge", "User Data"))


@register
class BraveCollector(BrowserCollector):
    name = "browser_brave"
    title = "Brave"
    browser_key = "brave"
    description = "History, downloads, bookmarks, extensions, cookie metadata (no values) and cache index."

    def profile_dirs(self, prof):
        return _chromium_profiles(_local(prof, "BraveSoftware", "Brave-Browser", "User Data"))


@register
class OperaCollector(BrowserCollector):
    name = "browser_opera"
    title = "Opera"
    browser_key = "opera"
    description = "Opera and Opera GX: history, downloads, bookmarks, extensions, cookie metadata and cache index."

    def profile_dirs(self, prof):
        out = []
        for variant in ("Opera Stable", "Opera GX Stable"):
            for name, path in _chromium_profiles(_roaming(prof, "Opera Software", variant)):
                out.append((f"{variant}/{name}", path))
        return out

    def _chromium_cache(self, ctx, pdir, limit):
        # Opera keeps its cache under Local\Opera Software\<variant>\Cache
        local = pdir.replace(os.sep + "Roaming" + os.sep, os.sep + "Local" + os.sep)
        return super()._chromium_cache(ctx, local, limit)


@register
class FirefoxCollector(BrowserCollector):
    name = "browser_firefox"
    title = "Mozilla Firefox"
    browser_key = "firefox"
    engine = "firefox"
    description = "History, downloads, bookmarks, add-ons, cookie metadata (no values) and cache2 index."

    def profile_dirs(self, prof):
        return [(os.path.basename(p), p) for p in bp.firefox_profiles(_roaming(prof))]
