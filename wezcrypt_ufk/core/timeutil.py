"""Timestamp conversion helpers. Every timestamp the kit emits is ISO 8601 UTC with a trailing 'Z'."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

UTC = timezone.utc
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
# Timestamps outside this window are treated as invalid/unset values.
_MIN_VALID = datetime(1980, 1, 1, tzinfo=UTC)
_MAX_VALID = datetime(2100, 1, 1, tzinfo=UTC)


def utc_now() -> datetime:
    return datetime.now(UTC)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Format a datetime as fixed-width ISO 8601 UTC (microsecond precision) so strings sort correctly."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utc_now_iso() -> str:
    return to_iso(utc_now())


def _valid(dt: datetime) -> Optional[datetime]:
    return dt if _MIN_VALID <= dt < _MAX_VALID else None


def filetime_to_dt(value: Optional[int]) -> Optional[datetime]:
    """Windows FILETIME (100ns intervals since 1601-01-01 UTC)."""
    if not value or value <= 0 or value >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return _valid(_FILETIME_EPOCH + timedelta(microseconds=value // 10))
    except OverflowError:
        return None


def filetime_to_iso(value: Optional[int]) -> Optional[str]:
    return to_iso(filetime_to_dt(value))


def webkit_to_iso(value: Optional[int]) -> Optional[str]:
    """Chromium timestamps: microseconds since 1601-01-01 UTC."""
    if not value or value <= 0:
        return None
    try:
        return to_iso(_valid(_FILETIME_EPOCH + timedelta(microseconds=int(value))))
    except OverflowError:
        return None


def prtime_to_iso(value: Optional[int]) -> Optional[str]:
    """Firefox PRTime: microseconds since the Unix epoch."""
    if not value or value <= 0:
        return None
    try:
        return to_iso(_valid(_UNIX_EPOCH + timedelta(microseconds=int(value))))
    except OverflowError:
        return None


def unix_to_iso(value: Optional[float]) -> Optional[str]:
    if value is None or value <= 0:
        return None
    try:
        return to_iso(_valid(datetime.fromtimestamp(float(value), UTC)))
    except (OverflowError, OSError, ValueError):
        return None


def unix_ms_to_iso(value: Optional[int]) -> Optional[str]:
    if not value or value <= 0:
        return None
    return unix_to_iso(int(value) / 1000.0)


def dos_datetime_to_str(dos_date: int, dos_time: int) -> Optional[str]:
    """MS-DOS packed date/time. The time zone is not stored, so the value is returned without a 'Z'."""
    if not dos_date:
        return None
    try:
        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2
        return datetime(year, month, day, hour, minute, second).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Windows event XML uses up to 9 fractional digits (100ns); Python accepts at most 6.
    if "." in text:
        head, _, tail = text.partition(".")
        frac = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[i:]
                break
        text = f"{head}.{frac[:6].ljust(6, '0')}{rest}"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def normalize_iso(value: Optional[str]) -> Optional[str]:
    return to_iso(parse_iso(value))
