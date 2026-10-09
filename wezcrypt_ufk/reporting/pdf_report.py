"""PDF report (ReportLab). Uses a Unicode TrueType font when available and shapes Arabic text for display."""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional
from xml.sax.saxutils import escape

from ..core.logging_setup import get_logger

log = get_logger("report.pdf")

ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]")
FONT_CANDIDATES = [
    (r"C:\Windows\Fonts\tahoma.ttf", r"C:\Windows\Fonts\tahomabd.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
]

COPPER = "#b8743d"
NAVY = "#18202e"
SEV_COLORS = {"critical": "#d9534f", "high": "#e07b39", "medium": "#c9a227", "low": "#3f8fc0", "info": "#7d8799"}


def _register_fonts():
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    for regular, bold in FONT_CANDIDATES:
        if os.path.isfile(regular):
            try:
                pdfmetrics.registerFont(TTFont("WZ", regular))
                pdfmetrics.registerFont(TTFont("WZ-Bold", bold if os.path.isfile(bold) else regular))
                return "WZ", "WZ-Bold", True
            except Exception:  # corrupt/unsupported font file
                continue
    return "Helvetica", "Helvetica-Bold", False


def _shape(text: str) -> str:
    if not ARABIC_RE.search(text):
        return text
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display

        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return text


def _p(text, style, limit: int = 1500):
    from reportlab.platypus import Paragraph

    s = "" if text is None else str(text)
    if len(s) > limit:
        s = s[:limit] + " …"
    return Paragraph(escape(_shape(s)).replace("\n", "<br/>"), style)


def build_pdf(d: Dict, out_path: str, timeline_rows: int = 1500, hash_rows: int = 3000) -> str:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import LongTable, PageBreak, SimpleDocTemplate, Spacer, Table, TableStyle

    font, bold, unicode_font = _register_fonts()
    if not unicode_font:
        log.warning("no Unicode TrueType font found; non-Latin text may not render in the PDF")
    base = getSampleStyleSheet()
    st = {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=bold, fontSize=20, textColor=colors.HexColor(NAVY), alignment=TA_LEFT),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=bold, fontSize=14, textColor=colors.HexColor(COPPER), spaceBefore=10),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=bold, fontSize=11.5, textColor=colors.HexColor(NAVY)),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontName=font, fontSize=9, leading=12),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontName=font, fontSize=7.2, leading=9),
        "mono": ParagraphStyle("m", parent=base["BodyText"], fontName=font, fontSize=6.8, leading=8.5),
        "th": ParagraphStyle("th", parent=base["BodyText"], fontName=bold, fontSize=7.5, leading=9, textColor=colors.white),
    }
    page = landscape(A4)
    width = page[0] - 24 * mm
    s = d["session"]
    summ = d["summary"]
    about = d["about"]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font, 7.5)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(12 * mm, 8 * mm, f"{about['Application']} v{about['Version']} · Case {s.get('case_id')} · "
                                           f"Session {s.get('session_id')}")
        canvas.drawRightString(page[0] - 12 * mm, 8 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(colors.HexColor(COPPER))
        canvas.line(12 * mm, page[1] - 10 * mm, page[0] - 12 * mm, page[1] - 10 * mm)
        canvas.restoreState()

    def table(headers: List[str], rows: List[List], ratios: List[float], style=st["small"]):
        data = [[_p(h, st["th"]) for h in headers]] + [[_p(c, style, 900) for c in r] for r in rows]
        t = LongTable(data, colWidths=[width * r for r in ratios], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(NAVY)),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c4c9d2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f7")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    story = [
        _p(about["Application"], st["title"]),
        _p("Digital Forensic Investigation Report", st["h2"]),
        Spacer(1, 6),
    ]
    info = [["Case ID", s.get("case_id")], ["Session ID", s.get("session_id")], ["Examiner", s.get("examiner")],
            ["Organization", s.get("organization")], ["Host", s.get("hostname")], ["Platform", s.get("platform")],
            ["Administrator rights", s.get("is_admin")], ["Collection started (UTC)", s.get("started_utc")],
            ["Collection finished (UTC)", s.get("finished_utc")], ["Tool version", f"{s.get('tool_name')} {s.get('tool_version')}"],
            ["Modules", ", ".join(s.get("modules_requested") or [])], ["Evidence files", len(d["hashes"])],
            ["Manifest SHA-256", d.get("manifest_sha256")], ["Report generated (UTC)", summ.get("analyzed_utc")]]
    t = Table([[_p(k, st["body"]), _p(v, st["body"])] for k, v in info], colWidths=[width * 0.22, width * 0.78])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c4c9d2")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef0f4"))]))
    story += [t, Spacer(1, 8), _p("Executive summary", st["h1"]), _p(summ.get("executive_summary", ""), st["body"]),
              _p("Technical recommendations", st["h1"])]
    for r in summ.get("recommendations", []):
        story.append(_p("• " + r, st["body"]))

    story += [PageBreak(), _p(f"Findings ({len(d['findings'])})", st["h1"])]
    for f in d["findings"]:
        color = SEV_COLORS.get(f.get("severity"), "#333333")
        story.append(_p(f"[{str(f.get('severity')).upper()}] {f.get('rule_id')} — {f.get('title')}",
                        ParagraphStyle("fh", parent=st["h2"], textColor=colors.HexColor(color))))
        story.append(_p(f"{f.get('description')}  Category: {f.get('category')}; MITRE: {', '.join(f.get('mitre') or []) or '-'}; "
                        f"Confidence: {f.get('confidence')}; Window: {f.get('first_seen') or '-'} → {f.get('last_seen') or '-'}", st["body"]))
        ev = f.get("evidence") or []
        if ev:
            rows = [[e.get("source"), "; ".join(f"{k}={v}" for k, v in e.items() if k != "source")] for e in ev[:8]]
            story.append(table(["Evidence source", "Details"], rows, [0.2, 0.8]))
            if len(ev) > 8:
                story.append(_p(f"… {len(ev) - 8} more evidence item(s) in the HTML/JSON report.", st["small"]))
        if f.get("recommendation"):
            story.append(_p("Recommendation: " + f["recommendation"], st["body"]))
        story.append(Spacer(1, 5))

    story += [PageBreak(), _p("Collection modules", st["h1"]),
              table(["Module", "Status", "Started (UTC)", "Seconds", "Files", "Records", "Errors"],
                    [[m.get("title"), m.get("status"), m.get("started_utc"), m.get("duration_seconds"), m.get("files_acquired"),
                      ", ".join(f"{k}:{v}" for k, v in (m.get("record_counts") or {}).items()), m.get("errors")] for m in d["modules"]],
                    [0.17, 0.08, 0.15, 0.07, 0.06, 0.4, 0.07])]

    tl = d["timeline"][-timeline_rows:]
    story += [PageBreak(), _p("Timeline", st["h1"]),
              _p(f"Most recent {len(tl)} of {d['timeline_total']} events (complete timeline: reports/csv/timeline.csv).", st["small"]),
              table(["Timestamp (UTC)", "Source", "Type", "Description"],
                    [[e.get("timestamp"), e.get("source"), e.get("event_type"), e.get("description")] for e in tl],
                    [0.15, 0.13, 0.12, 0.6])]

    hashes = d["hashes"][:hash_rows]
    story += [PageBreak(), _p("Evidence integrity (SHA-256)", st["h1"]),
              _p(f"{len(d['hashes'])} files in manifest; manifest SHA-256 {d.get('manifest_sha256')}."
                 + (f" First {hash_rows} listed; see manifest.json." if len(d["hashes"]) > hash_rows else ""), st["small"]),
              table(["Evidence file", "SHA-256", "Bytes", "Source"],
                    [[h["evidence_path"], h["sha256"], h["size"], h.get("source_path")] for h in hashes],
                    [0.3, 0.33, 0.07, 0.3], st["mono"])]

    story += [PageBreak(), _p(f"Errors, warnings and inaccessible items ({len(d['errors'])})", st["h1"]),
              table(["Time (UTC)", "Module", "Kind", "Message", "Path"],
                    [[e.get("utc"), e.get("module"), e.get("kind"), e.get("message"), e.get("path")] for e in d["errors"]],
                    [0.13, 0.1, 0.09, 0.43, 0.25]),
              _p(f"Operations performed on the live system ({len(d['live_actions'])})", st["h1"]),
              table(["Time (UTC)", "Module", "Action", "Impact"],
                    [[a.get("utc"), a.get("module"), a.get("action"), a.get("impact")] for a in d["live_actions"]],
                    [0.13, 0.1, 0.37, 0.4]),
              _p("Chain of custody", st["h1"]),
              table(["#", "Time (UTC)", "Action", "Actor", "Entry hash"],
                    [[c.get("seq"), c.get("utc"), c.get("action"), c.get("actor"), c.get("entry_hash")] for c in d["custody"]],
                    [0.04, 0.15, 0.2, 0.2, 0.41], st["mono"])]

    doc = SimpleDocTemplate(out_path, pagesize=page, leftMargin=12 * mm, rightMargin=12 * mm, topMargin=14 * mm,
                            bottomMargin=14 * mm, title=f"{about['Application']} report {s.get('case_id')}",
                            author=s.get("examiner") or about["Developer"], creator=f"{about['Application']} {about['Version']}")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return out_path


def pdf_available() -> Optional[str]:
    import importlib.util

    if importlib.util.find_spec("reportlab") is not None:
        return None
    return "reportlab is not installed"
