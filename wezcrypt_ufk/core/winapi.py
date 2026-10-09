"""Thin ctypes wrappers around documented Win32 APIs.

Every function degrades gracefully on non-Windows hosts so that parsers and tests stay portable.
Nothing here enables privileges or bypasses access checks: calls run with the caller's token.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List, Optional

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:  # pragma: no cover - exercised on Windows only
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    GENERIC_READ = 0x80000000
    FILE_SHARE_READ = 0x1
    FILE_SHARE_WRITE = 0x2
    FILE_SHARE_DELETE = 0x4
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetDriveTypeW.restype = wintypes.UINT

    class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * (260 + 36))]

    _kernel32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    _kernel32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _kernel32.FindNextStreamW.restype = wintypes.BOOL
    _kernel32.FindClose.argtypes = [wintypes.HANDLE]

    class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _kernel32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL


DRIVE_TYPES = {0: "unknown", 1: "no_root_dir", 2: "removable", 3: "fixed", 4: "remote", 5: "cdrom", 6: "ramdisk"}

FILE_ATTRIBUTE_FLAGS = {
    0x1: "READONLY", 0x2: "HIDDEN", 0x4: "SYSTEM", 0x10: "DIRECTORY", 0x20: "ARCHIVE",
    0x80: "NORMAL", 0x100: "TEMPORARY", 0x200: "SPARSE", 0x400: "REPARSE_POINT",
    0x800: "COMPRESSED", 0x1000: "OFFLINE", 0x2000: "NOT_CONTENT_INDEXED", 0x4000: "ENCRYPTED",
}


def decode_attributes(value: int) -> List[str]:
    return [name for bit, name in FILE_ATTRIBUTE_FLAGS.items() if value & bit]


def long_path(path: str) -> str:
    """Return a path usable beyond MAX_PATH on Windows (\\\\?\\ prefix). No-op elsewhere."""
    if not IS_WINDOWS:
        return path
    p = os.path.abspath(path)
    if p.startswith("\\\\?\\"):
        return p
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def strip_long_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def is_admin() -> bool:
    if IS_WINDOWS:  # pragma: no cover
        try:
            return bool(_shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def drive_type(root: str) -> str:
    """Return the Win32 drive type ('removable', 'fixed', ...) for the volume containing root."""
    if not IS_WINDOWS:
        return "unknown"
    drive = os.path.splitdrive(os.path.abspath(root))[0]  # pragma: no cover
    if not drive:  # pragma: no cover
        return "unknown"
    return DRIVE_TYPES.get(_kernel32.GetDriveTypeW(drive + "\\"), "unknown")  # pragma: no cover


def open_shared_read(path: str):
    """Open a file read-only with full sharing (READ|WRITE|DELETE).

    Many artifacts (browser databases, logs) are held open by their owner process with sharing
    flags that still permit concurrent readers; CPython's open() does not request DELETE sharing,
    so this is the documented way to read them without stopping the owning process.
    """
    if not IS_WINDOWS:
        return open(path, "rb")
    handle = _kernel32.CreateFileW(  # pragma: no cover
        long_path(path), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None,
    )
    if handle == INVALID_HANDLE_VALUE or handle is None:  # pragma: no cover
        err = ctypes.get_last_error()
        raise OSError(err, ctypes.FormatError(err).strip(), path)
    try:  # pragma: no cover
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except Exception:  # pragma: no cover
        _kernel32.CloseHandle(handle)
        raise
    return os.fdopen(fd, "rb")  # pragma: no cover


@dataclass
class AlternateStream:
    name: str
    size: int


def list_alternate_streams(path: str) -> List[AlternateStream]:
    """Enumerate NTFS alternate data streams (excluding the unnamed ::$DATA stream)."""
    if not IS_WINDOWS:
        return []
    streams: List[AlternateStream] = []  # pragma: no cover
    data = _WIN32_FIND_STREAM_DATA()  # pragma: no cover
    handle = _kernel32.FindFirstStreamW(long_path(path), 0, ctypes.byref(data), 0)  # pragma: no cover
    if handle == INVALID_HANDLE_VALUE or handle is None:  # pragma: no cover
        return streams
    try:  # pragma: no cover
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                clean = name[1:] if name.startswith(":") else name
                if clean.endswith(":$DATA"):
                    clean = clean[: -len(":$DATA")]
                streams.append(AlternateStream(clean, int(data.StreamSize)))
            if not _kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:  # pragma: no cover
        _kernel32.FindClose(handle)
    return streams  # pragma: no cover


def read_alternate_stream(path: str, stream: str, limit: int = 65536) -> Optional[bytes]:
    if not IS_WINDOWS:
        return None
    try:  # pragma: no cover
        with open(long_path(path) + ":" + stream, "rb") as fh:
            return fh.read(limit)
    except OSError:  # pragma: no cover
        return None


def ntfs_file_info(path: str) -> Optional[dict]:
    """NTFS metadata from GetFileInformationByHandle: MFT reference, link count, volume serial, attributes."""
    if not IS_WINDOWS:
        return None
    handle = _kernel32.CreateFileW(  # pragma: no cover
        long_path(path), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None,
        OPEN_EXISTING, 0x02000000, None,  # FILE_FLAG_BACKUP_SEMANTICS allows opening directories
    )
    if handle == INVALID_HANDLE_VALUE or handle is None:  # pragma: no cover
        return None
    try:  # pragma: no cover
        info = _BY_HANDLE_FILE_INFORMATION()
        if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return None
        index = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        return {
            "volume_serial": f"{info.dwVolumeSerialNumber:08X}",
            "file_index": index,
            "mft_entry": index & 0x0000FFFFFFFFFFFF,
            "mft_sequence": index >> 48,
            "link_count": info.nNumberOfLinks,
            "attributes": decode_attributes(info.dwFileAttributes),
        }
    finally:  # pragma: no cover
        _kernel32.CloseHandle(handle)


def decompress_xpress_huffman(data: bytes, uncompressed_size: int) -> bytes:
    """Decompress LZXPRESS Huffman data via ntdll!RtlDecompressBufferEx (used by Win10+ prefetch)."""
    if not IS_WINDOWS:
        raise OSError("LZXPRESS Huffman decompression requires Windows (ntdll)")
    ntdll = ctypes.WinDLL("ntdll")  # pragma: no cover
    fmt = 0x0004  # COMPRESSION_FORMAT_XPRESS_HUFF
    ws_buffer = ctypes.c_ulong()  # pragma: no cover
    ws_fragment = ctypes.c_ulong()  # pragma: no cover
    status = ntdll.RtlGetCompressionWorkSpaceSize(  # pragma: no cover
        ctypes.c_ushort(fmt), ctypes.byref(ws_buffer), ctypes.byref(ws_fragment)
    )
    if status != 0:  # pragma: no cover
        raise OSError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status & 0xFFFFFFFF:08X}")
    workspace = ctypes.create_string_buffer(ws_buffer.value)  # pragma: no cover
    out = ctypes.create_string_buffer(uncompressed_size)  # pragma: no cover
    final_size = ctypes.c_ulong()  # pragma: no cover
    src = ctypes.create_string_buffer(data, len(data))  # pragma: no cover
    status = ntdll.RtlDecompressBufferEx(  # pragma: no cover
        ctypes.c_ushort(fmt), out, ctypes.c_ulong(uncompressed_size), src, ctypes.c_ulong(len(data)),
        ctypes.byref(final_size), workspace,
    )
    if status != 0:  # pragma: no cover
        raise OSError(f"RtlDecompressBufferEx failed: 0x{status & 0xFFFFFFFF:08X}")
    return out.raw[: final_size.value]  # pragma: no cover
