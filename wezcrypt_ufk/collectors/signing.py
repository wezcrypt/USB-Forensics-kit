"""Authenticode signature verification via PowerShell Get-AuthenticodeSignature (handles catalog signing)."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Dict, Iterable, Optional

from ..core import commands
from ..core.context import CollectionContext
from ..core.winapi import IS_WINDOWS

_SCRIPT = r"""
$paths = Get-Content -LiteralPath '{listfile}' -Encoding UTF8
$out = foreach ($p in $paths) {{
  if (-not $p) {{ continue }}
  try {{
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    [pscustomobject]@{{ Path=$p; Status=[string]$s.Status; SignatureType=[string]$s.SignatureType;
      Signer=$(if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ $null }});
      Issuer=$(if ($s.SignerCertificate) {{ $s.SignerCertificate.Issuer }} else {{ $null }});
      Thumbprint=$(if ($s.SignerCertificate) {{ $s.SignerCertificate.Thumbprint }} else {{ $null }});
      IsOSBinary=$s.IsOSBinary }}
  }} catch {{
    [pscustomobject]@{{ Path=$p; Status='Error'; SignatureType=$null; Signer=$null; Issuer=$null; Thumbprint=$null; IsOSBinary=$null }}
  }}
}}
@($out) | ConvertTo-Json -Depth 3 -Compress
"""

BATCH = 300


def verify_signatures(ctx: CollectionContext, paths: Iterable[str], label: str) -> Dict[str, Dict]:
    """Return {normcase(path): signature-info}. Empty dict when disabled or unavailable."""
    unique = sorted({p for p in paths if p and os.path.isfile(p)})
    if not unique or not IS_WINDOWS or not ctx.config.verify_signatures:
        return {}
    results: Dict[str, Dict] = {}
    ctx.live_action(f"Authenticode verification of {len(unique)} files ({label})",
                    "Starts powershell.exe (Get-AuthenticodeSignature); reads files, may update last-access times "
                    "if NTFS last-access updates are enabled.")
    tmpdir = ctx.session.path("analysis", "tmp")
    os.makedirs(tmpdir, exist_ok=True)
    for start in range(0, len(unique), BATCH):
        ctx.check_cancel()
        chunk = unique[start:start + BATCH]
        fd, listfile = tempfile.mkstemp(prefix="sig_", suffix=".txt", dir=tmpdir)
        with os.fdopen(fd, "w", encoding="utf-8-sig") as fh:
            fh.write("\n".join(chunk))
        try:
            res = commands.run_powershell(_SCRIPT.format(listfile=listfile.replace("'", "''")), timeout=600)
            if not res.ok:
                ctx.error(f"signature verification failed: {res.stderr.strip()[:300]}", "error")
                continue
            text = res.stdout.strip().lstrip("﻿")
            data = json.loads(text) if text else []
            for item in (data if isinstance(data, list) else [data]):
                results[os.path.normcase(item.get("Path") or "")] = {
                    "status": item.get("Status"),
                    "signature_type": item.get("SignatureType"),
                    "signer": item.get("Signer"),
                    "issuer": item.get("Issuer"),
                    "thumbprint": item.get("Thumbprint"),
                    "is_os_binary": item.get("IsOSBinary"),
                }
        except ValueError as exc:
            ctx.error(f"could not parse signature output: {exc}", "error")
        finally:
            try:
                os.remove(listfile)
            except OSError:
                pass
    return results


def lookup(sigs: Dict[str, Dict], path: Optional[str]) -> Optional[Dict]:
    if not path:
        return None
    return sigs.get(os.path.normcase(path))
