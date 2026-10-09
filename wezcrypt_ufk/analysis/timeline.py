"""Unified timeline: merges per-module event files into one chronologically sorted JSON Lines file.

Each module file is sorted on its own (memory bounded by the largest module), then all are k-way merged.
"""

from __future__ import annotations

import heapq
import json
import os
from typing import Dict, Iterator, List, Optional

from ..core.winapi import long_path
from .data import SessionData


def _sorted_copy(path: str, tmp_dir: str) -> str:
    rows = []
    with open(long_path(path), "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ts = json.loads(line).get("timestamp") or ""
            except ValueError:
                continue
            rows.append((ts, line))
    rows.sort(key=lambda r: r[0])
    out = os.path.join(tmp_dir, os.path.basename(os.path.dirname(path)) + ".sorted.jsonl")
    with open(long_path(out), "w", encoding="utf-8") as fh:
        for _, line in rows:
            fh.write(line + "\n")
    return out


def _stream(path: str) -> Iterator[tuple]:
    with open(long_path(path), "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield (json.loads(line).get("timestamp") or "", line)


def build_timeline(session_dir: str) -> Dict:
    data = SessionData(session_dir)
    out_dir = os.path.join(session_dir, "analysis")
    tmp = os.path.join(out_dir, "tmp_timeline")
    os.makedirs(long_path(tmp), exist_ok=True)
    sorted_files = [_sorted_copy(p, tmp) for p in data.timeline_files()]
    out_path = os.path.join(out_dir, "timeline.jsonl")
    count = 0
    first = last = None
    sources: Dict[str, int] = {}
    with open(long_path(out_path), "w", encoding="utf-8") as fh:
        for ts, line in heapq.merge(*[_stream(p) for p in sorted_files], key=lambda r: r[0]):
            fh.write(line + "\n")
            count += 1
            first = first or ts
            last = ts
            src = json.loads(line).get("source", "")
            sources[src] = sources.get(src, 0) + 1
    for p in sorted_files:
        os.remove(long_path(p))
    os.rmdir(long_path(tmp))
    return {"events": count, "first": first, "last": last, "by_source": sources, "path": "analysis/timeline.jsonl"}


def iter_timeline(session_dir: str, limit: Optional[int] = None, newest_first: bool = False) -> List[Dict]:
    """Load timeline events (optionally the newest N)."""
    path = os.path.join(session_dir, "analysis", "timeline.jsonl")
    if not os.path.isfile(long_path(path)):
        return []
    if newest_first or limit:
        from collections import deque

        buf: deque = deque(maxlen=limit) if limit else deque()
        with open(long_path(path), "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    buf.append(line)
        rows = [json.loads(line) for line in buf]
        return list(reversed(rows)) if newest_first else rows
    with open(long_path(path), "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
