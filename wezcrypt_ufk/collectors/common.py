"""Helpers shared by collectors: user profile discovery and registry source selection."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..core import commands
from ..core.context import CollectionContext
from ..core.winapi import IS_WINDOWS, is_admin
from ..parsers.registry import Hive, HiveError, RegKey, live_root


@dataclass
class UserProfile:
    username: str
    path: str
    sid: str = ""
    is_current: bool = False

    @property
    def accessible(self) -> bool:
        try:
            os.listdir(self.path)
            return True
        except OSError:
            return False


def user_profiles() -> List[UserProfile]:
    """Interactive user profiles from ProfileList (Windows) plus the current user's profile."""
    current = os.path.normcase(os.path.abspath(os.environ.get("USERPROFILE") or os.path.expanduser("~")))
    out: List[UserProfile] = []
    if IS_WINDOWS:  # pragma: no cover
        plist = live_root("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
        for key in (plist.subkeys() if plist is not None else []):
            if not key.name.startswith("S-1-5-21-") and not key.name.startswith("S-1-12-1-"):
                continue  # skip service accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE)
            path = key.value("ProfileImagePath")
            if not isinstance(path, str) or not path:
                continue
            path = os.path.expandvars(path)
            out.append(UserProfile(os.path.basename(path), path, key.name,
                                   os.path.normcase(os.path.abspath(path)) == current))
    if not any(p.is_current for p in out):
        out.append(UserProfile(os.path.basename(current), current, "", True))
    return out


def accessible_profiles(ctx: CollectionContext) -> List[UserProfile]:
    res = []
    for p in user_profiles():
        if p.accessible:
            res.append(p)
        elif os.path.isdir(p.path):
            ctx.error(f"user profile not readable: {p.username}", "requires_admin" if not is_admin() else "access_denied", p.path)
    return res


class RegistryProvider:
    """Acquires registry hives once per session (reg save / file copy) and serves parsed roots.

    Preference: offline hive copy (evidence, hashed) -> live registry (read-only winreg) fallback.
    SAM and SECURITY hives are intentionally never acquired (credential material).
    """

    _instances: Dict[str, "RegistryProvider"] = {}
    _class_lock = threading.Lock()

    def __init__(self, ctx: CollectionContext):
        self.ctx = ctx
        self._lock = threading.Lock()
        self._hives: Dict[str, Optional[Hive]] = {}
        self._user_hives: Optional[List[Tuple[UserProfile, Optional[RegKey], Optional[RegKey], str]]] = None
        self.source_notes: Dict[str, str] = {}

    @classmethod
    def for_session(cls, ctx: CollectionContext) -> "RegistryProvider":
        with cls._class_lock:
            sid = ctx.session.session_id
            inst = cls._instances.get(sid)
            if inst is None:
                from ..core.context import CollectionContext as Ctx

                hive_ctx = Ctx(ctx.session, ctx.config, "registry_hives", ctx.shared, ctx.cancel_event)
                inst = cls(hive_ctx)
                cls._instances[sid] = inst
            return inst

    @classmethod
    def release(cls, session_id: str) -> None:
        with cls._class_lock:
            inst = cls._instances.pop(session_id, None)
        if inst is not None:
            inst.close()

    def close(self) -> None:
        for hive in self._hives.values():
            if hive is not None:
                hive.close()
        if self._user_hives:
            for _, nt, uc, _ in self._user_hives:
                for k in (nt, uc):
                    h = getattr(k, "hive", None)
                    if h is not None:
                        h.close()
        self.ctx.close()

    # -------------------------------------------------------------- acquisition primitives

    def _reg_save(self, key: str, filename: str) -> Optional[str]:
        if not IS_WINDOWS or not self.ctx.config.acquire_registry_hives:
            return None
        dest_dir = self.ctx.evidence_dir()
        dest = os.path.join(dest_dir, filename)
        if os.path.exists(dest):
            return dest
        res = commands.run([commands.system32("reg.exe"), "save", key, dest], timeout=300)
        self.ctx.live_action(f"reg.exe save {key}", "Exports a registry hive using the documented backup API; "
                             "starts reg.exe (process creation logged by the OS).")
        if not res.ok or not os.path.isfile(dest):
            kind = "requires_admin" if not is_admin() else "error"
            self.ctx.error(f"reg save failed for {key}: {res.stderr.strip() or res.stdout.strip()}", kind, key)
            return None
        from ..core.hashing import sha256_file

        self.ctx.register_file(f"registry:{key}", dest, os.path.getsize(dest), sha256_file(dest), "reg_save")
        return dest

    def _open(self, path: Optional[str], label: str) -> Optional[Hive]:
        if not path:
            return None
        try:
            hive = Hive(path)
        except (OSError, HiveError) as exc:
            self.ctx.error(f"cannot parse hive {label}: {exc}", "error", path)
            return None
        if hive.dirty:
            self.ctx.error(f"hive {label} is dirty (unreplayed transaction log entries); newest changes may be "
                           "missing from the offline copy", "error", path)
        return hive

    # -------------------------------------------------------------- machine hives

    def machine(self, name: str) -> Optional[RegKey]:
        """name: SYSTEM or SOFTWARE."""
        name = name.upper()
        with self._lock:
            if name not in self._hives:
                path = self._reg_save(f"HKLM\\{name}", f"{name}.hive") if is_admin() else None
                self._hives[name] = self._open(path, name)
            hive = self._hives[name]
        if hive is not None:
            self.source_notes[name] = "offline hive copy (reg save)"
            return hive.root()
        live = live_root(f"HKLM\\{name}")
        self.source_notes[name] = "live registry (read-only)" if live is not None else "unavailable"
        return live

    # -------------------------------------------------------------- user hives

    def users(self) -> List[Tuple[UserProfile, Optional[RegKey], Optional[RegKey], str]]:
        """List of (profile, ntuser_root, usrclass_root, source_description)."""
        with self._lock:
            if self._user_hives is None:
                self._user_hives = self._load_users()
            return self._user_hives

    def _load_users(self):
        out = []
        admin = is_admin()
        for prof in user_profiles():
            self.ctx.check_cancel()
            ntuser = usrclass = None
            source = "unavailable"
            safe = "".join(c if c.isalnum() else "_" for c in prof.username)
            loaded = bool(prof.sid) and live_root(f"HKU\\{prof.sid}") is not None
            if loaded and admin:
                p1 = self._reg_save(f"HKU\\{prof.sid}", f"NTUSER_{safe}.hive")
                p2 = self._reg_save(f"HKU\\{prof.sid}_Classes", f"UsrClass_{safe}.hive")
                h1, h2 = self._open(p1, f"NTUSER({prof.username})"), self._open(p2, f"UsrClass({prof.username})")
                ntuser = h1.root() if h1 else None
                usrclass = h2.root() if h2 else None
                source = "offline hive copy (reg save)" if ntuser else source
            elif not loaded and admin:
                for fname, label in (("NTUSER.DAT", "NTUSER"),
                                     (os.path.join("AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"), "UsrClass")):
                    src = os.path.join(prof.path, fname)
                    if not os.path.isfile(src):
                        continue
                    item = self.ctx.acquire(src, f"{label}_{safe}.hive")
                    hive = self._open(self.ctx.session.path(*item.evidence_path.split("/")), f"{label}({prof.username})") if item else None
                    if hive is not None:
                        if label == "NTUSER":
                            ntuser = hive.root()
                            source = "offline hive copy (file)"
                        else:
                            usrclass = hive.root()
            if ntuser is None and prof.is_current and IS_WINDOWS:
                ntuser = live_root("HKCU")
                usrclass = live_root("HKCU\\Software\\Classes")
                source = "live registry (read-only)" if ntuser is not None else source
            if ntuser is None and not prof.is_current and not admin:
                self.ctx.error(f"registry of user '{prof.username}' requires Administrator", "requires_admin", prof.path)
            out.append((prof, ntuser, usrclass, source))
        return out

    def current_user_only(self) -> List[Tuple[UserProfile, Optional[RegKey], Optional[RegKey], str]]:
        return [u for u in self.users() if u[1] is not None]
