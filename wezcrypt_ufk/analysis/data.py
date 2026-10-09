"""Read access to a session's parsed output (JSON Lines)."""

from __future__ import annotations

import json
import os
from typing import Dict, Iterator, List

from ..core.winapi import long_path


class SessionData:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        self.parsed = os.path.join(session_dir, "parsed")

    def modules(self) -> List[str]:
        if not os.path.isdir(long_path(self.parsed)):
            return []
        return sorted(d for d in os.listdir(long_path(self.parsed)) if os.path.isdir(long_path(os.path.join(self.parsed, d))))

    def artifacts(self, module: str) -> List[str]:
        folder = os.path.join(self.parsed, module)
        if not os.path.isdir(long_path(folder)):
            return []
        return sorted(f[:-6] for f in os.listdir(long_path(folder)) if f.endswith(".jsonl") and not f.startswith("_"))

    def records(self, module: str, artifact: str) -> Iterator[Dict]:
        path = os.path.join(self.parsed, module, artifact + ".jsonl")
        if not os.path.isfile(long_path(path)):
            return
        with open(long_path(path), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue

    def all(self, module: str, artifact: str) -> List[Dict]:
        return list(self.records(module, artifact))

    def records_prefix(self, module_prefix: str, artifact: str) -> Iterator[Dict]:
        for m in self.modules():
            if m.startswith(module_prefix):
                for r in self.records(m, artifact):
                    r.setdefault("_module", m)
                    yield r

    def event_records(self, key: str) -> Iterator[Dict]:
        return self.records("event_logs", f"events_{key}")

    def count(self, module: str, artifact: str) -> int:
        path = os.path.join(self.parsed, module, artifact + ".jsonl")
        if not os.path.isfile(long_path(path)):
            return 0
        with open(long_path(path), "rb") as fh:
            return sum(1 for line in fh if line.strip())

    def timeline_files(self) -> List[str]:
        out = []
        for m in self.modules():
            p = os.path.join(self.parsed, m, "_timeline.jsonl")
            if os.path.isfile(long_path(p)):
                out.append(p)
        return out
