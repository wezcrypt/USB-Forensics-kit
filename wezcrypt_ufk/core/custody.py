"""Tamper-evident chain of custody log (hash-chained JSON Lines)."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import socket
import threading
from typing import Any, Dict, List, Optional

from .timeutil import utc_now_iso

GENESIS = "0" * 64


def _canonical(entry: Dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def current_actor() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    return f"{user}@{socket.gethostname()}"


class CustodyLog:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def _last(self) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(self.path):
            return None
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        return last

    def append(self, action: str, details: Optional[Dict[str, Any]] = None, actor: Optional[str] = None,
               examiner: str = "") -> Dict[str, Any]:
        with self._lock:
            last = self._last()
            entry = {
                "seq": (last["seq"] + 1) if last else 1,
                "utc": utc_now_iso(),
                "action": action,
                "actor": actor or current_actor(),
                "examiner": examiner,
                "details": details or {},
                "prev_hash": last["entry_hash"] if last else GENESIS,
            }
            entry["entry_hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self) -> List[Dict[str, Any]]:
        if not os.path.isfile(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> List[str]:
        """Return a list of integrity problems; empty when the chain is intact."""
        problems: List[str] = []
        prev = GENESIS
        try:
            entries = self.entries()
        except ValueError as exc:
            return [f"custody log is not valid JSON Lines: {exc}"]
        for i, entry in enumerate(entries, 1):
            stored = entry.get("entry_hash")
            body = {k: v for k, v in entry.items() if k != "entry_hash"}
            if entry.get("seq") != i:
                problems.append(f"entry {i}: sequence number {entry.get('seq')} out of order")
            if entry.get("prev_hash") != prev:
                problems.append(f"entry {i}: prev_hash does not match previous entry")
            if hashlib.sha256(_canonical(body)).hexdigest() != stored:
                problems.append(f"entry {i}: entry_hash mismatch (entry modified)")
            prev = stored
        return problems
