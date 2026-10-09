"""SHA-256 helpers used for evidence integrity."""

from __future__ import annotations

import hashlib
from typing import BinaryIO, Optional

from .winapi import long_path

CHUNK_SIZE = 1024 * 1024


def sha256_stream(stream: BinaryIO, cancel_check=None) -> str:
    digest = hashlib.sha256()
    while True:
        if cancel_check is not None:
            cancel_check()
        block = stream.read(CHUNK_SIZE)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def sha256_file(path: str, cancel_check=None) -> str:
    with open(long_path(path), "rb") as fh:
        return sha256_stream(fh, cancel_check)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def try_sha256_file(path: str, max_size: Optional[int] = None) -> Optional[str]:
    """Hash a file, returning None on access errors or when it exceeds max_size bytes."""
    import os

    try:
        if max_size is not None and os.path.getsize(long_path(path)) > max_size:
            return None
        return sha256_file(path)
    except OSError:
        return None
