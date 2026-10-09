"""Run built-in Windows utilities without a console window and with bounded runtime."""

from __future__ import annotations

import base64
import json
import locale
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from .winapi import IS_WINDOWS

CREATE_NO_WINDOW = 0x08000000


@dataclass
class CommandResult:
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def console_encoding() -> str:
    if IS_WINDOWS:  # pragma: no cover
        try:
            import ctypes

            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            pass
    return locale.getpreferredencoding(False) or "utf-8"


def system32(name: str) -> str:
    """Absolute path to a System32 tool so a planted binary in the CWD/USB is never executed."""
    if IS_WINDOWS:  # pragma: no cover
        root = os.environ.get("SystemRoot", r"C:\Windows")
        # A 32-bit process would be redirected; the kit is built x64 so System32 is native.
        candidate = os.path.join(root, "System32", name)
        if os.path.isfile(candidate):
            return candidate
        candidate = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", name)
        if os.path.isfile(candidate):
            return candidate
    return shutil.which(name) or name


def run(args: Sequence[str], timeout: int = 120, encoding: Optional[str] = None,
        stdout_path: Optional[str] = None) -> CommandResult:
    args = list(args)
    kwargs = {}
    if IS_WINDOWS:  # pragma: no cover
        kwargs["creationflags"] = CREATE_NO_WINDOW
    enc = encoding or console_encoding()
    try:
        if stdout_path:
            with open(stdout_path, "wb") as out:
                proc = subprocess.run(args, stdout=out, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                      timeout=timeout, **kwargs)
            return CommandResult(args, proc.returncode, "", proc.stderr.decode(enc, "replace"))
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                              timeout=timeout, **kwargs)
        return CommandResult(args, proc.returncode, proc.stdout.decode(enc, "replace"),
                             proc.stderr.decode(enc, "replace"))
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(enc, "replace") if exc.stdout else ""
        return CommandResult(args, -1, out, f"timed out after {timeout}s", timed_out=True)
    except OSError as exc:
        return CommandResult(args, -1, "", str(exc))


def run_powershell(script: str, timeout: int = 180) -> CommandResult:
    """Run a PowerShell script with UTF-8 output. The script is passed encoded to avoid quoting issues."""
    prefix = "$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    return run([system32("powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], timeout=timeout, encoding="utf-8")


def powershell_json(script: str, timeout: int = 180) -> Any:
    """Run a script whose output is ConvertTo-Json; returns a list (possibly empty)."""
    res = run_powershell(script, timeout)
    if not res.ok:
        raise RuntimeError(res.stderr.strip() or f"powershell exited with {res.returncode}")
    text = res.stdout.strip().lstrip("\ufeff")
    if not text:
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else [data]
