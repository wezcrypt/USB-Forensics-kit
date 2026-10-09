"""Evidence manifest creation and verification."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from .hashing import sha256_file
from .timeutil import utc_now_iso
from .winapi import long_path

MANIFEST_NAME = "manifest.json"
MANIFEST_HASH_NAME = "manifest.sha256"
COVERED_DIRS = ("evidence", "parsed")


def _iter_files(session_dir: str, subdirs: Iterable[str]):
    for sub in subdirs:
        base = os.path.join(session_dir, sub)
        if not os.path.isdir(long_path(base)):
            continue
        for root, dirs, files in os.walk(long_path(base)):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel = os.path.relpath(full, long_path(session_dir)).replace("\\", "/")
                yield rel, full


def build_manifest(session_dir: str, session_id: str, tool_version: str,
                   known_sources: Optional[Dict[str, Dict]] = None,
                   progress: Optional[Callable[[int, str], None]] = None,
                   subdirs: Iterable[str] = COVERED_DIRS) -> Dict:
    """Hash every file under the covered directories and write manifest.json + manifest.sha256."""
    known_sources = known_sources or {}
    entries = []
    for i, (rel, full) in enumerate(_iter_files(session_dir, subdirs)):
        if progress:
            progress(i, rel)
        st = os.stat(full)
        item = {"path": rel, "size": st.st_size, "sha256": sha256_file(full)}
        src = known_sources.get(rel)
        if src:
            item["source_path"] = src.get("source_path")
            item["acquisition_sha256"] = src.get("sha256")
            item["method"] = src.get("method")
        entries.append(item)
    manifest = {
        "session_id": session_id,
        "tool_version": tool_version,
        "created_utc": utc_now_iso(),
        "algorithm": "SHA-256",
        "covered_directories": list(subdirs),
        "file_count": len(entries),
        "total_bytes": sum(e["size"] for e in entries),
        "files": entries,
    }
    path = os.path.join(session_dir, MANIFEST_NAME)
    with open(long_path(path), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, ensure_ascii=False)
    digest = sha256_file(path)
    with open(long_path(os.path.join(session_dir, MANIFEST_HASH_NAME)), "w", encoding="utf-8") as fh:
        fh.write(f"{digest}  {MANIFEST_NAME}\n")
    manifest["_manifest_sha256"] = digest
    return manifest


@dataclass
class VerificationResult:
    session_dir: str
    verified_utc: str
    manifest_ok: bool = True
    manifest_message: str = ""
    ok: List[str] = field(default_factory=list)
    modified: List[Dict] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unexpected: List[str] = field(default_factory=list)
    custody_problems: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.manifest_ok and not self.modified and not self.missing and not self.custody_problems

    def to_dict(self) -> Dict:
        return {
            "session_dir": self.session_dir,
            "verified_utc": self.verified_utc,
            "passed": self.passed,
            "manifest_ok": self.manifest_ok,
            "manifest_message": self.manifest_message,
            "ok_count": len(self.ok),
            "modified": self.modified,
            "missing": self.missing,
            "unexpected": self.unexpected,
            "custody_problems": self.custody_problems,
        }


def verify_manifest(session_dir: str, progress: Optional[Callable[[int, int, str], None]] = None,
                    cancel_check: Optional[Callable[[], None]] = None) -> VerificationResult:
    from .custody import CustodyLog

    result = VerificationResult(session_dir=session_dir, verified_utc=utc_now_iso())
    mpath = os.path.join(session_dir, MANIFEST_NAME)
    if not os.path.isfile(long_path(mpath)):
        result.manifest_ok = False
        result.manifest_message = "manifest.json not found"
        return result
    hpath = os.path.join(session_dir, MANIFEST_HASH_NAME)
    actual = sha256_file(mpath)
    if os.path.isfile(long_path(hpath)):
        with open(long_path(hpath), "r", encoding="utf-8") as fh:
            expected = fh.read().split()[0].strip().lower() if fh else ""
        if expected != actual:
            result.manifest_ok = False
            result.manifest_message = "manifest.json hash does not match manifest.sha256"
        else:
            result.manifest_message = "manifest.json hash verified"
    else:
        result.manifest_ok = False
        result.manifest_message = "manifest.sha256 not found"
    with open(long_path(mpath), "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    listed = {e["path"]: e for e in manifest.get("files", [])}
    total = len(listed)
    for i, (rel, entry) in enumerate(listed.items()):
        if cancel_check:
            cancel_check()
        if progress:
            progress(i, total, rel)
        full = os.path.join(session_dir, *rel.split("/"))
        if not os.path.isfile(long_path(full)):
            result.missing.append(rel)
            continue
        digest = sha256_file(full)
        if digest != entry["sha256"]:
            result.modified.append({"path": rel, "expected": entry["sha256"], "actual": digest})
        else:
            result.ok.append(rel)
    for rel, _ in _iter_files(session_dir, manifest.get("covered_directories", COVERED_DIRS)):
        if rel not in listed:
            result.unexpected.append(rel)
    custody = os.path.join(session_dir, "chain_of_custody.jsonl")
    if os.path.isfile(long_path(custody)):
        result.custody_problems = CustodyLog(custody).verify()
    else:
        result.custody_problems = ["chain_of_custody.jsonl not found"]
    return result
