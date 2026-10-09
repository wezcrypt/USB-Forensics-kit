"""Runtime context handed to each collector."""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional

from . import commands
from .acquire import AcquisitionError, copy_with_hash, source_times
from .config import Config
from .logging_setup import get_logger
from .models import AcquiredFile, ErrorRecord, LiveAction, TimelineEvent
from .paths import safe_name
from .session import Session
from .timeutil import utc_now_iso
from .winapi import long_path


class CollectionCancelled(Exception):
    pass


class SharedState:
    """Thread-safe accumulators shared by all collectors of one session."""

    def __init__(self):
        self.lock = threading.Lock()
        self.errors: List[ErrorRecord] = []
        self.live_actions: List[LiveAction] = []
        self.acquired: List[AcquiredFile] = []


class CollectionContext:
    def __init__(self, session: Session, config: Config, module: str, shared: SharedState,
                 cancel_event: Optional[threading.Event] = None,
                 progress_cb: Optional[Callable[[str, float, str], None]] = None):
        self.session = session
        self.config = config
        self.module = module
        self.shared = shared
        self.cancel_event = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self.log = get_logger(f"collector.{module}")
        self.record_counts: Dict[str, int] = {}
        self.files_acquired = 0
        self.error_count = 0
        self._event_fh = None
        self._lock = threading.Lock()
        self.last_acquire_error: Optional[AcquisitionError] = None

    # ----- paths -----
    def evidence_dir(self, *parts: str) -> str:
        path = self.session.path("evidence", self.module, *parts)
        os.makedirs(long_path(path), exist_ok=True)
        return path

    def parsed_dir(self) -> str:
        path = self.session.path("parsed", self.module)
        os.makedirs(long_path(path), exist_ok=True)
        return path

    # ----- control -----
    def check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise CollectionCancelled(self.module)

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def progress(self, fraction: float, message: str = "") -> None:
        if self._progress_cb:
            self._progress_cb(self.module, max(0.0, min(1.0, fraction)), message)

    # ----- reporting problems -----
    def error(self, message: str, kind: str = "error", path: Optional[str] = None, detail: Optional[str] = None) -> None:
        rec = ErrorRecord(self.module, message, kind, path, utc_now_iso(), detail)
        with self.shared.lock:
            self.shared.errors.append(rec)
        self.error_count += 1
        self.log.warning("%s [%s] %s", message, kind, path or "")

    def live_action(self, action: str, impact: str) -> None:
        with self.shared.lock:
            self.shared.live_actions.append(LiveAction(self.module, action, impact, utc_now_iso()))
        self.log.info("live action: %s", action)

    # ----- evidence -----
    def acquire(self, src: str, rel_dest: Optional[str] = None, subdir: str = "",
                record_error: bool = True, dest_dir: Optional[str] = None) -> Optional[AcquiredFile]:
        """Copy a source file into evidence/<module>/<subdir>/ with hashing. Errors are recorded, not raised.

        dest_dir: alternative destination (e.g. a temporary working folder); such copies are not registered
        as evidence."""
        self.check_cancel()
        name = rel_dest or safe_name(os.path.basename(src), 200)
        if dest_dir is not None:
            os.makedirs(long_path(dest_dir), exist_ok=True)
            dest = os.path.join(dest_dir, name)
        else:
            dest = os.path.join(self.evidence_dir(subdir) if subdir else self.evidence_dir(), name)
        try:
            created, modified, accessed = source_times(src)
        except OSError:
            created = modified = accessed = None
        try:
            final, size, digest, method = copy_with_hash(src, dest, self.check_cancel)
        except CollectionCancelled:
            raise
        except AcquisitionError as exc:
            self.last_acquire_error = exc
            if record_error:
                self.error(f"could not acquire file: {exc}", exc.kind, src)
            return None
        if dest_dir is not None:
            return AcquiredFile(self.module, src, final, size, digest, method, utc_now_iso(),
                                created, modified, accessed, verified=True)
        return self.register_file(src, final, size, digest, method, created, modified, accessed)

    def register_file(self, src: str, final_path: str, size: int, digest: str, method: str,
                      created=None, modified=None, accessed=None) -> AcquiredFile:
        rel = os.path.relpath(final_path, self.session.session_dir).replace("\\", "/")
        item = AcquiredFile(self.module, src, rel, size, digest, method, utc_now_iso(),
                            created, modified, accessed, verified=True)
        with self.shared.lock:
            self.shared.acquired.append(item)
        self.files_acquired += 1
        return item

    def save_text(self, name: str, text: str, source: str) -> Optional[AcquiredFile]:
        """Store command output / exported text as evidence (UTF-8)."""
        from .hashing import sha256_file

        path = os.path.join(self.evidence_dir(), safe_name(name, 200))
        from .paths import unique_path

        path = unique_path(path)
        with open(long_path(path), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return self.register_file(source, path, os.path.getsize(long_path(path)), sha256_file(path), "generated_output")

    def run_command(self, args, name: Optional[str] = None, timeout: int = 120, impact: str = "") -> commands.CommandResult:
        self.check_cancel()
        res = commands.run(args, timeout=timeout)
        self.live_action("executed: " + " ".join(os.path.basename(args[0]) if i == 0 else a for i, a in enumerate(args)),
                         impact or "Starts a short-lived built-in Windows process (process creation is logged by the OS).")
        if name:
            self.save_text(name, res.stdout + (("\n--- stderr ---\n" + res.stderr) if res.stderr.strip() else ""),
                           "command: " + " ".join(args))
        if res.timed_out:
            self.error(f"command timed out: {args[0]}", "error")
        return res

    def powershell_json(self, script: str, name: str, timeout: int = 180) -> List[Any]:
        self.check_cancel()
        self.live_action(f"executed PowerShell query ({name})",
                         "Starts powershell.exe; may be recorded in PowerShell/Script Block logs of the host.")
        data = commands.powershell_json(script, timeout)
        self.save_text(name + ".json", json.dumps(data, indent=1, ensure_ascii=False, default=str), "powershell: " + name)
        return data

    # ----- parsed output -----
    def write_records(self, artifact: str, records: Iterable[Dict[str, Any]]) -> int:
        path = os.path.join(self.parsed_dir(), safe_name(artifact) + ".jsonl")
        count = 0
        with open(long_path(path), "a", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                count += 1
                if count % 2000 == 0:
                    self.check_cancel()
        self.record_counts[artifact] = self.record_counts.get(artifact, 0) + count
        return count

    def add_event(self, timestamp: Optional[str], source: str, event_type: str, description: str,
                  artifact: str = "", **details: Any) -> None:
        if not timestamp:
            return
        ev = TimelineEvent(timestamp, source, event_type, description, self.module, artifact,
                           {k: v for k, v in details.items() if v not in (None, "", [], {})})
        with self._lock:
            if self._event_fh is None:
                self._event_fh = open(long_path(os.path.join(self.parsed_dir(), "_timeline.jsonl")), "a", encoding="utf-8")
            self._event_fh.write(json.dumps(ev.to_dict(), ensure_ascii=False, default=str) + "\n")
        self.record_counts["timeline_events"] = self.record_counts.get("timeline_events", 0) + 1

    def close(self) -> None:
        with self._lock:
            if self._event_fh is not None:
                self._event_fh.close()
                self._event_fh = None
