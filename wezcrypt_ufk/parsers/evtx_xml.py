"""Streaming parser for Windows event XML as produced by `wevtutil qe /f:xml`."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Dict, Iterable, Iterator, Optional, Union

from ..core.timeutil import normalize_iso

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
LEVELS = {"0": "LogAlways", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def event_to_dict(elem: ET.Element, max_field_chars: int = 4000) -> Dict:
    system = elem.find(f"{NS}System")
    rec: Dict = {"event_id": None, "provider": None, "channel": None, "computer": None, "record_id": None,
                 "time_created": None, "level": None, "user_sid": None, "process_id": None, "data": {}}
    if system is not None:
        prov = system.find(f"{NS}Provider")
        if prov is not None:
            rec["provider"] = prov.get("Name")
        eid = system.find(f"{NS}EventID")
        if eid is not None and eid.text:
            try:
                rec["event_id"] = int(eid.text.strip())
            except ValueError:
                rec["event_id"] = eid.text.strip()
        tc = system.find(f"{NS}TimeCreated")
        if tc is not None:
            rec["time_created"] = normalize_iso(tc.get("SystemTime"))
        for name, key in (("Channel", "channel"), ("Computer", "computer"), ("EventRecordID", "record_id")):
            node = system.find(f"{NS}{name}")
            if node is not None and node.text:
                rec[key] = node.text.strip()
        lvl = system.find(f"{NS}Level")
        if lvl is not None and lvl.text:
            rec["level"] = LEVELS.get(lvl.text.strip(), lvl.text.strip())
        sec = system.find(f"{NS}Security")
        if sec is not None:
            rec["user_sid"] = sec.get("UserID")
        ex = system.find(f"{NS}Execution")
        if ex is not None:
            rec["process_id"] = ex.get("ProcessID")
    data: Dict[str, str] = {}
    ed = elem.find(f"{NS}EventData")
    if ed is not None:
        unnamed = 0
        for d in ed:
            name = d.get("Name")
            if not name:
                name = f"Data{unnamed}"
                unnamed += 1
            data[name] = _clip((d.text or "").strip(), max_field_chars)
    ud = elem.find(f"{NS}UserData")
    if ud is not None:
        for container in ud:
            for child in container.iter():
                if child is container:
                    continue
                if len(child) == 0:
                    data[_local(child.tag)] = _clip((child.text or "").strip(), max_field_chars)
    rec["data"] = data
    return rec


def _clip(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[:limit] + f"...[truncated {len(text) - limit} chars]"
    return text


def iter_events(chunks: Iterable[Union[str, bytes]], max_field_chars: int = 4000) -> Iterator[Dict]:
    """Parse a stream of concatenated <Event> elements (no root element) incrementally."""
    parser = ET.XMLPullParser(events=("end",))
    parser.feed("<Events>")
    for chunk in chunks:
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", "replace")
        parser.feed(chunk)
        yield from _drain(parser, max_field_chars)
    parser.feed("</Events>")
    yield from _drain(parser, max_field_chars)
    parser.close()


def _drain(parser: ET.XMLPullParser, max_field_chars: int) -> Iterator[Dict]:
    for _, elem in parser.read_events():
        if elem.tag == f"{NS}Event" or elem.tag == "Event":
            yield event_to_dict(elem, max_field_chars)
            elem.clear()


def iter_events_file(path: str, max_field_chars: int = 4000, encoding: Optional[str] = None) -> Iterator[Dict]:
    """Parse a file holding wevtutil XML output."""
    def chunks():
        with open(path, "rb") as fh:
            head = fh.read(4)
            enc = encoding
            if enc is None:
                enc = "utf-16" if head[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
            fh.seek(0)
            import codecs

            reader = codecs.getreader(enc)(fh, errors="replace")
            while True:
                block = reader.read(1 << 20)
                if not block:
                    break
                # XML declarations cannot appear mid-document
                yield block.replace('<?xml version="1.0" encoding="UTF-8"?>', "")

    yield from iter_events(chunks(), max_field_chars)
