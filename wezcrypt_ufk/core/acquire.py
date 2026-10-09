"""Forensically careful file acquisition.

Sources are only ever opened read-only. Data is hashed while it is read, written to the evidence
folder, then the copy is re-hashed and compared. A mismatch is reported, never silently accepted.
"""

from __future__ import annotations

import errno
import hashlib
import os
from typing import Callable, Optional, Tuple

from .hashing import CHUNK_SIZE, sha256_file
from .paths import unique_path
from .timeutil import unix_to_iso
from .winapi import IS_WINDOWS, long_path, open_shared_read

ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_ACCESS_DENIED = 5


class AcquisitionError(Exception):
    def __init__(self, message: str, kind: str = "error", path: Optional[str] = None):
        super().__init__(message)
        self.kind = kind
        self.path = path


class IntegrityError(AcquisitionError):
    pass


def classify_os_error(exc: OSError) -> str:
    winerror = getattr(exc, "winerror", None)
    if winerror in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION):
        return "locked"
    if winerror == ERROR_ACCESS_DENIED or isinstance(exc, PermissionError) or exc.errno in (errno.EACCES, errno.EPERM):
        return "access_denied"
    if isinstance(exc, FileNotFoundError) or exc.errno == errno.ENOENT:
        return "not_found"
    return "error"


def source_times(path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """(created, modified, accessed) of the source. st_ctime is creation time on Windows only."""
    st = os.stat(long_path(path))
    created = unix_to_iso(getattr(st, "st_birthtime", None) or (st.st_ctime if IS_WINDOWS else None))
    return created, unix_to_iso(st.st_mtime), unix_to_iso(st.st_atime)


def _open_source(path: str):
    """Return (file object, method). Falls back to full-share open on sharing violations."""
    try:
        return open(long_path(path), "rb"), "read_only_copy"
    except OSError as exc:
        kind = classify_os_error(exc)
        if kind == "locked" or (IS_WINDOWS and kind == "access_denied"):
            try:
                return open_shared_read(path), "shared_read_copy"
            except OSError as exc2:
                raise AcquisitionError(f"{exc2}", classify_os_error(exc2), path) from exc2
        raise AcquisitionError(str(exc), kind, path) from exc


def copy_with_hash(src: str, dest: str, cancel_check: Optional[Callable[[], None]] = None,
                   opener=None) -> Tuple[str, int, str, str]:
    """Copy src -> dest (dest never overwritten). Returns (dest_path, size, sha256, method)."""
    dest = unique_path(dest)
    os.makedirs(long_path(os.path.dirname(dest)), exist_ok=True)
    if opener is not None:
        fh, method = opener(src)
    else:
        fh, method = _open_source(src)
    digest = hashlib.sha256()
    size = 0
    try:
        with fh, open(long_path(dest), "xb") as out:
            while True:
                if cancel_check:
                    cancel_check()
                block = fh.read(CHUNK_SIZE)
                if not block:
                    break
                digest.update(block)
                out.write(block)
                size += len(block)
            out.flush()
            os.fsync(out.fileno())
    except BaseException as exc:
        try:
            os.remove(long_path(dest))
        except OSError:
            pass
        if isinstance(exc, OSError):
            raise AcquisitionError(f"read failed: {exc}", classify_os_error(exc), src) from exc
        raise
    source_hash = digest.hexdigest()
    copy_hash = sha256_file(dest)
    if copy_hash != source_hash:
        raise IntegrityError(f"post-copy verification failed for {src}", "error", src)
    return dest, size, source_hash, method
