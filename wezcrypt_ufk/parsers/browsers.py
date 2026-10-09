"""Browser artifact parsers (Chromium family and Firefox).

Privacy rules enforced here:
  * cookie VALUES and encrypted_value columns are never selected;
  * Login Data, Web Data (autofill/cards) and session tokens are never opened.
Databases are always opened from a working copy, never from the browser's live profile.
"""

from __future__ import annotations

import json
import os
import sqlite3
import struct
from typing import Dict, Iterator, List, Optional

from ..core.timeutil import prtime_to_iso, unix_to_iso, webkit_to_iso

CHROME_TRANSITIONS = {0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe",
                      5: "generated", 6: "auto_toplevel", 7: "form_submit", 8: "reload", 9: "keyword",
                      10: "keyword_generated"}
CHROME_DOWNLOAD_STATE = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
CHROME_DANGER = {0: "not_dangerous", 1: "dangerous_file", 2: "dangerous_url", 3: "dangerous_content",
                 4: "maybe_dangerous_content", 5: "uncommon_content", 6: "user_validated", 7: "dangerous_host",
                 8: "potentially_unwanted", 9: "allowlisted_by_policy"}


def open_readonly(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{_uri_path(path)}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def _uri_path(path: str) -> str:
    from urllib.parse import quote

    p = os.path.abspath(path).replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    return quote(p, safe="/:")


def _tables(con: sqlite3.Connection) -> set:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(con: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


# ----------------------------------------------------------------------------- Chromium


def chromium_history(path: str, limit: int) -> Iterator[Dict]:
    con = open_readonly(path)
    try:
        if not {"urls", "visits"} <= _tables(con):
            return
        sql = ("SELECT v.id AS visit_id, u.url, u.title, v.visit_time, v.transition, u.visit_count, "
               "u.typed_count, v.from_visit FROM visits v JOIN urls u ON u.id = v.url "
               "ORDER BY v.visit_time DESC LIMIT ?")
        for r in con.execute(sql, (limit,)):
            core = (r["transition"] or 0) & 0xFF
            yield {
                "visit_time": webkit_to_iso(r["visit_time"]),
                "url": r["url"],
                "title": r["title"],
                "transition": CHROME_TRANSITIONS.get(core, core),
                "visit_count": r["visit_count"],
                "typed_count": r["typed_count"],
                "visit_id": r["visit_id"],
                "from_visit": r["from_visit"],
            }
    finally:
        con.close()


def chromium_downloads(path: str, limit: int) -> Iterator[Dict]:
    con = open_readonly(path)
    try:
        if "downloads" not in _tables(con):
            return
        cols = _columns(con, "downloads")
        chain = "downloads_url_chains" in _tables(con)
        wanted = [c for c in ("id", "current_path", "target_path", "start_time", "end_time", "received_bytes",
                              "total_bytes", "state", "danger_type", "interrupt_reason", "opened", "last_access_time",
                              "referrer", "tab_url", "site_url", "mime_type", "original_mime_type") if c in cols]
        for r in con.execute(f"SELECT {', '.join(wanted)} FROM downloads ORDER BY start_time DESC LIMIT ?", (limit,)):
            row = dict(r)
            urls = []
            if chain:
                urls = [u[0] for u in con.execute(
                    "SELECT url FROM downloads_url_chains WHERE id=? ORDER BY chain_index", (row["id"],))]
            yield {
                "start_time": webkit_to_iso(row.get("start_time")),
                "end_time": webkit_to_iso(row.get("end_time")),
                "target_path": row.get("target_path") or row.get("current_path"),
                "source_url": urls[-1] if urls else row.get("tab_url"),
                "url_chain": urls,
                "referrer": row.get("referrer"),
                "tab_url": row.get("tab_url"),
                "mime_type": row.get("mime_type"),
                "received_bytes": row.get("received_bytes"),
                "total_bytes": row.get("total_bytes"),
                "state": CHROME_DOWNLOAD_STATE.get(row.get("state"), row.get("state")),
                "danger_type": CHROME_DANGER.get(row.get("danger_type"), row.get("danger_type")),
                "opened": bool(row.get("opened")),
                "last_access_time": webkit_to_iso(row.get("last_access_time")),
            }
    finally:
        con.close()


def chromium_cookies_metadata(path: str, limit: int) -> Iterator[Dict]:
    """Cookie metadata only. The value / encrypted_value columns are deliberately never read."""
    con = open_readonly(path)
    try:
        if "cookies" not in _tables(con):
            return
        cols = _columns(con, "cookies")
        wanted = [c for c in ("host_key", "name", "path", "creation_utc", "expires_utc", "last_access_utc",
                              "last_update_utc", "is_secure", "is_httponly", "is_persistent", "samesite",
                              "source_scheme") if c in cols]
        assert "value" not in wanted and "encrypted_value" not in wanted
        for r in con.execute(f"SELECT {', '.join(wanted)} FROM cookies ORDER BY creation_utc DESC LIMIT ?", (limit,)):
            row = dict(r)
            yield {
                "host": row.get("host_key"),
                "name": row.get("name"),
                "path": row.get("path"),
                "created": webkit_to_iso(row.get("creation_utc")),
                "expires": webkit_to_iso(row.get("expires_utc")),
                "last_access": webkit_to_iso(row.get("last_access_utc")),
                "secure": bool(row.get("is_secure")),
                "http_only": bool(row.get("is_httponly")),
                "persistent": bool(row.get("is_persistent")),
            }
    finally:
        con.close()


def chromium_bookmarks(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out: List[Dict] = []

    def walk(node: Dict, folder: str) -> None:
        if node.get("type") == "url":
            out.append({
                "folder": folder,
                "name": node.get("name"),
                "url": node.get("url"),
                "added": webkit_to_iso(int(node.get("date_added", 0) or 0)),
                "last_used": webkit_to_iso(int(node.get("date_last_used", 0) or 0)),
            })
        for child in node.get("children", []) or []:
            walk(child, f"{folder}/{node.get('name', '')}" if node.get("type") == "folder" else folder)

    for root_name, root in (data.get("roots") or {}).items():
        if isinstance(root, dict):
            walk(root, root_name)
    return out


def chromium_extensions(profile_dir: str, preferences: Optional[Dict]) -> List[Dict]:
    """Installed extensions from (Secure) Preferences, enriched with manifest.json from the Extensions folder."""
    out: List[Dict] = []
    settings = {}
    if preferences:
        settings = ((preferences.get("extensions") or {}).get("settings")) or {}
    ext_root = os.path.join(profile_dir, "Extensions")
    ids = set(settings.keys())
    if os.path.isdir(ext_root):
        ids |= set(os.listdir(ext_root))
    for ext_id in sorted(ids):
        info = settings.get(ext_id, {}) if isinstance(settings.get(ext_id), dict) else {}
        manifest = info.get("manifest") or _latest_manifest(os.path.join(ext_root, ext_id))
        if not manifest and not info:
            continue
        location = info.get("location")
        if location in (5, 10) and not os.path.isdir(os.path.join(ext_root, ext_id)):
            continue  # component / built-in entries without on-disk presence
        out.append({
            "id": ext_id,
            "name": (manifest or {}).get("name"),
            "version": (manifest or {}).get("version"),
            "description": ((manifest or {}).get("description") or "")[:300],
            "permissions": [str(p) for p in ((manifest or {}).get("permissions") or [])][:50],
            "host_permissions": [str(p) for p in ((manifest or {}).get("host_permissions") or [])][:50],
            "install_time": webkit_to_iso(int(info.get("install_time", 0) or 0)) if info.get("install_time") else None,
            "from_webstore": info.get("from_webstore"),
            "enabled": info.get("state", 1) == 1 if "state" in info else (not info.get("disable_reasons")),
            "location": location,
            "update_url": (manifest or {}).get("update_url"),
        })
    return out


def _latest_manifest(ext_dir: str) -> Optional[Dict]:
    if not os.path.isdir(ext_dir):
        return None
    versions = sorted(os.listdir(ext_dir), reverse=True)
    for v in versions:
        mpath = os.path.join(ext_dir, v, "manifest.json")
        if os.path.isfile(mpath):
            try:
                with open(mpath, "r", encoding="utf-8-sig") as fh:
                    m = json.load(fh)
                name = m.get("name", "")
                if isinstance(name, str) and name.startswith("__MSG_"):
                    m["name"] = _resolve_msg(os.path.join(ext_dir, v), m, name) or name
                return m
            except (OSError, ValueError):
                continue
    return None


def _resolve_msg(ext_ver_dir: str, manifest: Dict, token: str) -> Optional[str]:
    key = token[6:-2]
    loc = manifest.get("default_locale", "en")
    path = os.path.join(ext_ver_dir, "_locales", loc, "messages.json")
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            msgs = json.load(fh)
    except (OSError, ValueError):
        return None
    for k, v in msgs.items():
        if k.lower() == key.lower() and isinstance(v, dict):
            return v.get("message")
    return None


# ----------------------------------------------------------------------------- Firefox


def firefox_history(path: str, limit: int) -> Iterator[Dict]:
    con = open_readonly(path)
    try:
        if not {"moz_places", "moz_historyvisits"} <= _tables(con):
            return
        sql = ("SELECT v.id AS visit_id, p.url, p.title, v.visit_date, v.visit_type, p.visit_count, v.from_visit "
               "FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id ORDER BY v.visit_date DESC LIMIT ?")
        types = {1: "link", 2: "typed", 3: "bookmark", 4: "embed", 5: "redirect_permanent", 6: "redirect_temporary",
                 7: "download", 8: "framed_link", 9: "reload"}
        for r in con.execute(sql, (limit,)):
            yield {
                "visit_time": prtime_to_iso(r["visit_date"]),
                "url": r["url"],
                "title": r["title"],
                "transition": types.get(r["visit_type"], r["visit_type"]),
                "visit_count": r["visit_count"],
                "visit_id": r["visit_id"],
                "from_visit": r["from_visit"],
            }
    finally:
        con.close()


def firefox_downloads(path: str, limit: int) -> Iterator[Dict]:
    con = open_readonly(path)
    try:
        tables = _tables(con)
        if not {"moz_annos", "moz_anno_attributes", "moz_places"} <= tables:
            return
        sql = ("SELECT p.url, a.content, a.dateAdded, n.name FROM moz_annos a "
               "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id JOIN moz_places p ON p.id = a.place_id "
               "WHERE n.name IN ('downloads/destinationFileURI', 'downloads/metaData') ORDER BY a.dateAdded DESC")
        merged: Dict[str, Dict] = {}
        for r in con.execute(sql):
            item = merged.setdefault(r["url"], {"source_url": r["url"], "start_time": prtime_to_iso(r["dateAdded"])})
            if r["name"] == "downloads/destinationFileURI":
                item["target_path"] = _file_uri_to_path(r["content"])
            else:
                try:
                    meta = json.loads(r["content"])
                    item["state"] = {0: "in_progress", 1: "complete", 3: "cancelled", 4: "paused"}.get(meta.get("state"), meta.get("state"))
                    item["end_time"] = unix_to_iso(meta["endTime"] / 1000.0) if meta.get("endTime") else None
                    item["total_bytes"] = meta.get("fileSize")
                except (ValueError, TypeError):
                    pass
        for i, item in enumerate(merged.values()):
            if i >= limit:
                break
            yield item
    finally:
        con.close()


def _file_uri_to_path(uri: Optional[str]) -> Optional[str]:
    if not uri:
        return uri
    from urllib.parse import unquote, urlparse

    if uri.startswith("file:"):
        p = unquote(urlparse(uri).path)
        if len(p) > 2 and p[0] == "/" and p[2] == ":":
            p = p[1:]
        return p.replace("/", "\\") if ":" in p[:3] else p
    return uri


def firefox_bookmarks(path: str) -> List[Dict]:
    con = open_readonly(path)
    try:
        if "moz_bookmarks" not in _tables(con):
            return []
        sql = ("SELECT b.title, p.url, b.dateAdded, b.lastModified, parent.title AS folder FROM moz_bookmarks b "
               "JOIN moz_places p ON p.id = b.fk LEFT JOIN moz_bookmarks parent ON parent.id = b.parent WHERE b.type = 1")
        return [{"folder": r["folder"], "name": r["title"], "url": r["url"], "added": prtime_to_iso(r["dateAdded"]),
                 "last_modified": prtime_to_iso(r["lastModified"])} for r in con.execute(sql)]
    finally:
        con.close()


def firefox_cookies_metadata(path: str, limit: int) -> Iterator[Dict]:
    con = open_readonly(path)
    try:
        if "moz_cookies" not in _tables(con):
            return
        cols = _columns(con, "moz_cookies")
        wanted = [c for c in ("host", "name", "path", "creationTime", "expiry", "lastAccessed", "isSecure",
                              "isHttpOnly") if c in cols]
        for r in con.execute(f"SELECT {', '.join(wanted)} FROM moz_cookies ORDER BY creationTime DESC LIMIT ?", (limit,)):
            row = dict(r)
            exp = row.get("expiry")
            yield {
                "host": row.get("host"),
                "name": row.get("name"),
                "path": row.get("path"),
                "created": prtime_to_iso(row.get("creationTime")),
                "expires": unix_to_iso(exp / 1000.0 if exp and exp > 10 ** 11 else exp) if exp else None,
                "last_access": prtime_to_iso(row.get("lastAccessed")),
                "secure": bool(row.get("isSecure")),
                "http_only": bool(row.get("isHttpOnly")),
            }
    finally:
        con.close()


def firefox_extensions(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for addon in data.get("addons", []) or []:
        if addon.get("location") in ("app-builtin", "app-system-defaults"):
            continue
        loc = addon.get("defaultLocale") or {}
        out.append({
            "id": addon.get("id"),
            "name": loc.get("name"),
            "version": addon.get("version"),
            "description": (loc.get("description") or "")[:300],
            "type": addon.get("type"),
            "enabled": addon.get("active"),
            "install_time": unix_to_iso((addon.get("installDate") or 0) / 1000.0) if addon.get("installDate") else None,
            "update_time": unix_to_iso((addon.get("updateDate") or 0) / 1000.0) if addon.get("updateDate") else None,
            "location": addon.get("location"),
            "source_uri": addon.get("sourceURI"),
            "permissions": ((addon.get("userPermissions") or {}).get("permissions") or [])[:50],
        })
    return out


def firefox_profiles(appdata: str) -> List[str]:
    """Profile directories listed in profiles.ini (falls back to listing the Profiles folder)."""
    base = os.path.join(appdata, "Mozilla", "Firefox")
    ini = os.path.join(base, "profiles.ini")
    out: List[str] = []
    if os.path.isfile(ini):
        import configparser

        cp = configparser.RawConfigParser()
        try:
            cp.read(ini, encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError):
            cp = None
        if cp is not None:
            for section in cp.sections():
                if cp.has_option(section, "Path"):
                    rel = cp.get(section, "Path")
                    is_rel = cp.get(section, "IsRelative", fallback="1") == "1"
                    path = os.path.join(base, *rel.split("/")) if is_rel else rel
                    if os.path.isdir(path) and path not in out:
                        out.append(path)
    prof = os.path.join(base, "Profiles")
    if os.path.isdir(prof):
        for name in os.listdir(prof):
            p = os.path.join(prof, name)
            if os.path.isdir(p) and p not in out:
                out.append(p)
    return out


# ----------------------------------------------------------------------------- caches

SIMPLE_MAGIC = 0xFCFB6D1BA7725C30


def chromium_simple_cache_entry(path: str) -> Optional[Dict]:
    """Chromium 'simple' cache entry file (<hash>_0): header carries the key (normally the URL)."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20 + 4096)
    except OSError:
        return None
    if len(head) < 20 or struct.unpack_from("<Q", head, 0)[0] != SIMPLE_MAGIC:
        return None
    key_len = struct.unpack_from("<I", head, 12)[0]
    key = head[20:20 + key_len].decode("utf-8", "replace")
    st = os.stat(path)
    return {"key": _strip_cache_key(key), "file": os.path.basename(path), "size": st.st_size,
            "modified": unix_to_iso(st.st_mtime)}


def chromium_blockfile_entries(data_1_path: str, limit: int) -> Iterator[Dict]:
    """Chromium 'blockfile' cache: EntryStore records (256-byte blocks) in data_1 contain inline keys."""
    try:
        fh = open(data_1_path, "rb")
    except OSError:
        return
    with fh:
        header = fh.read(8192)
        if len(header) < 8 or struct.unpack_from("<I", header, 0)[0] != 0xC104CAC3:
            return
        count = 0
        while count < limit:
            block = fh.read(256)
            if len(block) < 256:
                break
            key_len = struct.unpack_from("<i", block, 32)[0]
            long_key = struct.unpack_from("<I", block, 36)[0]
            if not (0 < key_len <= 160) or long_key:
                continue
            raw = block[96:96 + key_len]
            try:
                key = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if not key.isprintable() or ("://" not in key and not key.startswith("_dk_")):
                continue
            created = struct.unpack_from("<Q", block, 24)[0]
            count += 1
            yield {"key": _strip_cache_key(key), "created": webkit_to_iso(created), "file": "data_1"}


def _strip_cache_key(key: str) -> str:
    # Partitioned keys look like "1/0/_dk_https://site https://site https://real/url"
    if key.startswith(("1/0/", "0/0/")) or key.startswith("_dk_"):
        parts = key.split(" ")
        return parts[-1]
    return key


def firefox_cache2_entry(path: str) -> Optional[Dict]:
    """Firefox cache2 entry: metadata offset stored big-endian in the last 4 bytes; key follows the header."""
    try:
        size = os.path.getsize(path)
        if size < 4:
            return None
        with open(path, "rb") as fh:
            fh.seek(size - 4)
            meta_off = struct.unpack(">I", fh.read(4))[0]
            if meta_off >= size:
                return None
            chunks = (meta_off + 262143) // 262144
            fh.seek(meta_off + 4 + chunks * 2)
            hdr = fh.read(4 * 7 + 4 + 4096)
    except OSError:
        return None
    if len(hdr) < 28:
        return None
    version, fetch_count, last_fetched, last_modified, frecency, expiration, key_size = struct.unpack_from(">7I", hdr, 0)
    off = 28
    if version >= 2:
        off += 4  # flags
    key = hdr[off:off + key_size].decode("utf-8", "replace")
    if ":" not in key:
        return None
    idx = key.find(":http")
    url = key[idx + 1:] if idx >= 0 else key
    return {"key": url, "file": os.path.basename(path), "fetch_count": fetch_count,
            "last_fetched": unix_to_iso(last_fetched), "last_modified": unix_to_iso(last_modified),
            "expires": unix_to_iso(expiration) if expiration and expiration != 0xFFFFFFFF else None,
            "size": size}
