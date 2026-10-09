"""Scheduled task XML (Task Scheduler 2.0 schema) parser."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from ..core.timeutil import normalize_iso

NS = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"


def _text(node: Optional[ET.Element], path: str) -> Optional[str]:
    if node is None:
        return None
    found = node.find(path.replace("t:", NS))
    return found.text.strip() if found is not None and found.text else None


def parse_task_xml(xml_text: str, name: str = "") -> Dict:
    xml_text = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text.lstrip("﻿"))
    root = ET.fromstring(xml_text)
    reg = root.find(f"{NS}RegistrationInfo")
    actions: List[Dict] = []
    act_root = root.find(f"{NS}Actions")
    for act in (list(act_root) if act_root is not None else []):
        kind = act.tag.replace(NS, "")
        if kind == "Exec":
            actions.append({"type": "exec", "command": _text(act, "t:Command"), "arguments": _text(act, "t:Arguments"),
                            "working_directory": _text(act, "t:WorkingDirectory")})
        elif kind == "ComHandler":
            actions.append({"type": "com", "class_id": _text(act, "t:ClassId"), "data": _text(act, "t:Data")})
        else:
            actions.append({"type": kind.lower()})
    triggers = []
    trig_root = root.find(f"{NS}Triggers")
    for trig in (list(trig_root) if trig_root is not None else []):
        triggers.append({"type": trig.tag.replace(NS, ""), "start": _text(trig, "t:StartBoundary"),
                         "enabled": (_text(trig, "t:Enabled") or "true").lower() == "true"})
    principal = root.find(f"{NS}Principals/{NS}Principal")
    settings = root.find(f"{NS}Settings")
    uri = _text(reg, "t:URI") or name
    return {
        "name": uri,
        "author": _text(reg, "t:Author"),
        "description": _text(reg, "t:Description"),
        "registration_date": normalize_iso(_text(reg, "t:Date")) if _text(reg, "t:Date") else None,
        "registration_date_raw": _text(reg, "t:Date"),
        "enabled": (_text(settings, "t:Enabled") or "true").lower() == "true",
        "hidden": (_text(settings, "t:Hidden") or "false").lower() == "true",
        "run_as": _text(principal, "t:UserId") or _text(principal, "t:GroupId"),
        "run_level": _text(principal, "t:RunLevel"),
        "actions": actions,
        "triggers": triggers,
        "command_line": " ".join(filter(None, [actions[0].get("command"), actions[0].get("arguments")])) if actions and actions[0].get("type") == "exec" else None,
    }


def split_schtasks_xml(output: str) -> List[tuple]:
    """`schtasks /query /xml ONE` returns all tasks in one <Tasks> root; a comment names each task.

    Returns (task_name, task_xml) tuples."""
    output = output.lstrip("﻿")
    docs = []
    for m in re.finditer(r"<!--\s*(.*?)\s*-->\s*(<Task\b.*?</Task>)", output, re.S):
        docs.append((m.group(1), m.group(2)))
    return docs
