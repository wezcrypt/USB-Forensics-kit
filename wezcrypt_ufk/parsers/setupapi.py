"""setupapi.dev.log parser - device installation times (recorded in the host's LOCAL time)."""

from __future__ import annotations

import re
from typing import Dict, Iterable, List

_SECTION = re.compile(r">>>\s+\[Device Install \((?P<kind>[^)]*)\)\s+-\s+(?P<device>[^\]]+)\]")
_START = re.compile(r">>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")


def parse_setupapi(lines: Iterable[str], usb_only: bool = True) -> List[Dict]:
    out: List[Dict] = []
    pending = None
    for line in lines:
        m = _SECTION.search(line)
        if m:
            pending = {"device": m.group("device").strip(), "install_type": m.group("kind")}
            continue
        if pending is not None:
            s = _START.search(line)
            if s:
                dev = pending["device"]
                up = dev.upper()
                if not usb_only or "USBSTOR" in up or up.startswith("USB\\") or "WPDBUSENUM" in up:
                    serial = dev.split("\\")[-1] if "\\" in dev else ""
                    out.append({
                        "device": dev,
                        "install_type": pending["install_type"],
                        "serial": serial[:-2] if serial.endswith("&0") else serial,
                        "first_install_local": s.group("ts").replace("/", "-").replace(" ", "T"),
                        "time_zone": "host-local (not UTC)",
                    })
                pending = None
    return out
