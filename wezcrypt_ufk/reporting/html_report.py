"""Self-contained, offline HTML reports (searchable, filterable, paginated tables; no external resources)."""

from __future__ import annotations

import html
import json
from typing import Any, Dict, List, Optional

CSS = """
:root{--bg:#10151f;--panel:#171e2b;--panel2:#1d2636;--line:#2a3447;--text:#e4e8ef;--muted:#9aa5b8;
--copper:#c8834a;--copper2:#e0a271;--crit:#d9534f;--high:#e07b39;--med:#d6b043;--low:#5fa8d3;--info:#7d8799;--ok:#5cb85c}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 "Segoe UI",Tahoma,Arial,sans-serif}
header{background:var(--panel);border-bottom:2px solid var(--copper);padding:18px 28px}
header h1{margin:0;font-size:20px;font-weight:600;letter-spacing:.3px}header h1 span{color:var(--copper)}
header .sub{color:var(--muted);font-size:12.5px;margin-top:4px}
nav{display:flex;flex-wrap:wrap;gap:2px;background:var(--panel2);padding:0 20px;border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
nav button{background:none;border:0;color:var(--muted);padding:11px 14px;cursor:pointer;font:inherit;border-bottom:2px solid transparent}
nav button.active,nav button:hover{color:var(--text);border-bottom-color:var(--copper)}
main{padding:22px 28px;max-width:1600px;margin:0 auto}section{display:none}section.active{display:block}
h2{font-size:16px;font-weight:600;color:var(--copper2);margin:6px 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--copper);padding:12px 14px;border-radius:4px}
.card .v{font-size:22px;font-weight:600}.card .k{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.box{background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:14px 16px;margin-bottom:16px}
.kv{display:grid;grid-template-columns:220px 1fr;gap:4px 16px}.kv div:nth-child(odd){color:var(--muted)}
.tools{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
input[type=search],select{background:var(--panel2);border:1px solid var(--line);color:var(--text);padding:7px 10px;border-radius:3px;font:inherit;min-width:260px}
select{min-width:150px}.count{color:var(--muted);font-size:12.5px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);font-size:13px}
th{background:var(--panel2);color:var(--copper2);text-align:left;padding:8px;border-bottom:1px solid var(--line);position:sticky;top:42px;cursor:pointer;white-space:nowrap}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word;max-width:640px}
tr:hover td{background:#202a3c}.mono{font-family:Consolas,"Courier New",monospace;font-size:12px}
.sev{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:10px;font-size:11.5px;font-weight:600;text-transform:uppercase;color:#10151f}
.sev-critical{background:var(--crit);color:#fff}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.st-completed{color:var(--ok)}.st-partial{color:var(--med)}.st-failed{color:var(--crit)}.st-skipped,.st-cancelled{color:var(--muted)}
details summary{cursor:pointer;color:var(--copper2)}pre{white-space:pre-wrap;margin:6px 0;font-family:Consolas,monospace;font-size:12px;color:#cfd6e2}
.pager{display:flex;gap:6px;align-items:center;margin:10px 0}.pager button{background:var(--panel2);color:var(--text);border:1px solid var(--line);padding:4px 10px;cursor:pointer;border-radius:3px}
.note{color:var(--muted);font-size:12.5px;margin:6px 0 12px}ul.rec li{margin-bottom:6px}
footer{color:var(--muted);font-size:12px;text-align:center;padding:24px}a{color:var(--copper2)}
@media print{nav,.tools,.pager{display:none}section{display:block!important}body,main{background:#fff;color:#000}
table,.box,.card{background:#fff;color:#000}th{position:static;color:#000}}
"""

JS = r"""
const DATA = JSON.parse(document.getElementById('report-data').textContent);
const PAGE = 100;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function cell(v,col){
  if(v==null||v==='')return '';
  if(col.type==='sev')return '<span class="sev sev-'+esc(v)+'">'+esc(v)+'</span>';
  if(col.type==='status')return '<span class="st-'+esc(v)+'">'+esc(v)+'</span>';
  if(typeof v==='object'){const t=JSON.stringify(v,null,1);if(t.length<120&&!Array.isArray(v[0]))return '<span class="mono">'+esc(t)+'</span>';
    return '<details><summary>'+(Array.isArray(v)?v.length+' item(s)':'details')+'</summary><pre>'+esc(t)+'</pre></details>';}
  const s=String(v);return col.mono?'<span class="mono">'+esc(s)+'</span>':esc(s);
}
function makeTable(id){
  const spec=DATA.tables[id];const root=document.getElementById('t-'+id);if(!root||!spec)return;
  let rows=spec.rows,page=0,sortCol=null,sortDir=1;
  const tools=document.createElement('div');tools.className='tools';
  const q=document.createElement('input');q.type='search';q.placeholder='Search...';tools.appendChild(q);
  const filters=[];
  (spec.filters||[]).forEach(f=>{const sel=document.createElement('select');const vals=[...new Set(spec.rows.map(r=>r[f]).filter(x=>x!=null&&x!==''))].sort();
    sel.innerHTML='<option value="">All '+esc(f)+'</option>'+vals.map(v=>'<option>'+esc(v)+'</option>').join('');sel.dataset.key=f;tools.appendChild(sel);filters.push(sel);});
  const cnt=document.createElement('span');cnt.className='count';tools.appendChild(cnt);root.appendChild(tools);
  const tbl=document.createElement('table');root.appendChild(tbl);
  const pager=document.createElement('div');pager.className='pager';root.appendChild(pager);
  function apply(){const term=q.value.toLowerCase();
    rows=spec.rows.filter(r=>filters.every(s=>!s.value||String(r[s.dataset.key])===s.value)&&(!term||JSON.stringify(r).toLowerCase().includes(term)));
    if(sortCol){rows=rows.slice().sort((a,b)=>{const x=a[sortCol],y=b[sortCol];if(x==y)return 0;if(x==null)return 1;if(y==null)return -1;
      if(sortCol==='severity'){const o={critical:4,high:3,medium:2,low:1,info:0};return (o[x]-o[y])*sortDir;}
      return (x>y?1:-1)*sortDir;});}
    page=0;render();}
  function render(){const start=page*PAGE,part=rows.slice(start,start+PAGE);
    let h='<thead><tr>'+spec.columns.map(c=>'<th data-k="'+esc(c.key)+'">'+esc(c.label)+(sortCol===c.key?(sortDir>0?' ▲':' ▼'):'')+'</th>').join('')+'</tr></thead><tbody>';
    h+=part.map(r=>'<tr>'+spec.columns.map(c=>'<td>'+cell(r[c.key],c)+'</td>').join('')+'</tr>').join('');
    tbl.innerHTML=h+'</tbody>';
    tbl.querySelectorAll('th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;sortDir=(sortCol===k)?-sortDir:1;sortCol=k;apply();});
    const pages=Math.max(1,Math.ceil(rows.length/PAGE));cnt.textContent=rows.length+' of '+spec.rows.length+' rows';
    pager.innerHTML='';if(pages>1){const prev=document.createElement('button');prev.textContent='‹ Prev';prev.onclick=()=>{if(page>0){page--;render();}};
      const next=document.createElement('button');next.textContent='Next ›';next.onclick=()=>{if(page<pages-1){page++;render();}};
      const lab=document.createElement('span');lab.className='count';lab.textContent='Page '+(page+1)+' / '+pages;pager.append(prev,lab,next);}}
  q.addEventListener('input',apply);filters.forEach(s=>s.addEventListener('change',apply));apply();
}
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('section').forEach(s=>s.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.s).classList.add('active');});
Object.keys(DATA.tables).forEach(makeTable);
"""


def _json_script(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, default=str)
    return text.replace("</", "<\\/").replace("<!--", "<\\!--")


def table_spec(rows: List[Dict], columns: List[tuple], filters: Optional[List[str]] = None) -> Dict:
    cols = []
    for c in columns:
        key, label = c[0], c[1]
        opts = c[2] if len(c) > 2 else {}
        cols.append({"key": key, "label": label, **opts})
    keys = [c["key"] for c in cols]
    slim = [{k: r.get(k) for k in keys} for r in rows]
    return {"columns": cols, "rows": slim, "filters": filters or []}


def render_page(title: str, subtitle: str, sections: List[Dict], tables: Dict[str, Dict], footer: str) -> str:
    """sections: [{"id","label","html"}] - html may contain <div id="t-<table>"></div> placeholders."""
    nav = "".join(f'<button data-s="{s["id"]}" class="{"active" if i == 0 else ""}">{html.escape(s["label"])}</button>'
                  for i, s in enumerate(sections))
    body = "".join(f'<section id="{s["id"]}" class="{"active" if i == 0 else ""}">{s["html"]}</section>'
                   for i, s in enumerate(sections))
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{CSS}</style></head><body>'
            f'<header><h1>{html.escape(title.split(" — ")[0])} <span>{html.escape(title.split(" — ")[1] if " — " in title else "")}</span></h1>'
            f'<div class="sub">{html.escape(subtitle)}</div></header><nav>{nav}</nav><main>{body}</main>'
            f'<footer>{footer}</footer>'
            f'<script type="application/json" id="report-data">{_json_script({"tables": tables})}</script>'
            f'<script>{JS}</script></body></html>')


def kv_html(items: List[tuple]) -> str:
    return '<div class="kv">' + "".join(f"<div>{html.escape(str(k))}</div><div>{html.escape('' if v is None else str(v))}</div>"
                                        for k, v in items) + "</div>"


def cards_html(items: List[tuple]) -> str:
    return '<div class="cards">' + "".join(f'<div class="card"><div class="v">{html.escape(str(v))}</div>'
                                           f'<div class="k">{html.escape(k)}</div></div>' for k, v in items) + "</div>"


def footer_html(about: Dict) -> str:
    return (f'{html.escape(about["Application"])} v{html.escape(about["Version"])} &middot; {html.escape(about["Developer"])} &middot; '
            f'<a href="{html.escape(about["Website"])}">{html.escape(about["Website"])}</a> &middot; {html.escape(about["License"])} License'
            ' &middot; Generated offline; all times UTC.')


def build_main_report(d: Dict) -> str:
    s = d["session"]
    summ = d["summary"]
    sev = summ.get("severity_counts", {})
    tl = summ.get("timeline", {})
    findings = [{**f, "evidence_count": len(f.get("evidence") or []), "mitre": ", ".join(f.get("mitre") or [])} for f in d["findings"]]
    modules = d["modules"]
    overview = (
        cards_html([("Critical", sev.get("critical", 0)), ("High", sev.get("high", 0)), ("Medium", sev.get("medium", 0)),
                    ("Low", sev.get("low", 0)), ("Info", sev.get("info", 0)), ("Timeline events", tl.get("events", 0)),
                    ("Evidence files", len(d["hashes"])), ("Errors / warnings", len(d["errors"]))])
        + '<h2>Executive summary</h2><div class="box">' + html.escape(summ.get("executive_summary", "Analysis not available.")) + "</div>"
        + "<h2>Investigation session</h2><div class=\"box\">" + kv_html([
            ("Case ID", s.get("case_id")), ("Session ID", s.get("session_id")), ("Examiner", s.get("examiner")),
            ("Organization", s.get("organization")), ("Host", s.get("hostname")), ("OS account used", s.get("os_user")),
            ("Administrator", s.get("is_admin")), ("Platform", s.get("platform")),
            ("Collection started (UTC)", s.get("started_utc")), ("Collection finished (UTC)", s.get("finished_utc")),
            ("Tool", f'{s.get("tool_name")} {s.get("tool_version")}'), ("Session status", s.get("status")),
            ("Manifest SHA-256", d.get("manifest_sha256")), ("Modules", ", ".join(s.get("modules_requested") or [])),
            ("Timeline range", f'{tl.get("first")} → {tl.get("last")}' if tl.get("first") else "-"),
            ("Notes", s.get("notes")),
        ]) + "</div>"
        + "<h2>Recommendations</h2><div class=\"box\"><ul class=\"rec\">"
        + "".join(f"<li>{html.escape(r)}</li>" for r in summ.get("recommendations", [])) + "</ul></div>"
    )
    tl_note = (f'<p class="note">Showing the most recent {len(d["timeline"])} of {d["timeline_total"]} events. The complete '
               "timeline is in reports/csv/timeline.csv and analysis/timeline.jsonl.</p>" if d["timeline_truncated"] else "")
    sections = [
        {"id": "s-overview", "label": "Overview", "html": overview},
        {"id": "s-findings", "label": f"Findings ({len(findings)})", "html": '<h2>Findings</h2><p class="note">Findings are '
         'rule-based leads backed by the listed evidence; severity reflects indicator strength, not a verdict.</p><div id="t-findings"></div>'},
        {"id": "s-timeline", "label": "Timeline", "html": "<h2>Unified timeline</h2>" + tl_note + '<div id="t-timeline"></div>'},
        {"id": "s-modules", "label": "Modules", "html": '<h2>Collection modules</h2><div id="t-modules"></div>'},
        {"id": "s-hashes", "label": "Evidence & SHA-256", "html": '<h2>Evidence manifest (SHA-256)</h2><div id="t-hashes"></div>'},
        {"id": "s-observables", "label": "Observables", "html": '<h2>Observables (IOCs for enrichment)</h2><p class="note">'
         'Extracted from findings and live remote connections. Presence here does not mean malicious.</p><div id="t-observables"></div>'},
        {"id": "s-errors", "label": "Errors & warnings", "html": '<h2>Collection errors, limitations and inaccessible items</h2><div id="t-errors"></div>'},
        {"id": "s-live", "label": "Live actions", "html": '<h2>Operations performed on the live system</h2><p class="note">Documented '
         'for transparency: actions the kit performed that can leave traces or affect system state.</p><div id="t-live"></div>'},
        {"id": "s-custody", "label": "Chain of custody", "html": '<h2>Chain of custody (hash-chained)</h2><div id="t-custody"></div>'},
    ]
    tables = {
        "findings": table_spec(findings, [("severity", "Severity", {"type": "sev"}), ("rule_id", "Rule"), ("title", "Title"),
                                          ("category", "Category"), ("description", "Description"), ("first_seen", "First seen"),
                                          ("last_seen", "Last seen"), ("confidence", "Confidence"), ("mitre", "MITRE ATT&CK"),
                                          ("evidence", "Evidence"), ("recommendation", "Recommendation")],
                               ["severity", "category"]),
        "timeline": table_spec(d["timeline"], [("timestamp", "Timestamp (UTC)", {"mono": True}), ("source", "Source"),
                                               ("event_type", "Type"), ("description", "Description"), ("module", "Module"),
                                               ("details", "Details")], ["source", "event_type", "module"]),
        "modules": table_spec(modules, [("title", "Module"), ("status", "Status", {"type": "status"}), ("started_utc", "Started"),
                                        ("duration_seconds", "Seconds"), ("files_acquired", "Files"), ("record_counts", "Records"),
                                        ("errors", "Errors"), ("message", "Message")], ["status"]),
        "hashes": table_spec(d["hashes"], [("evidence_path", "Evidence file", {"mono": True}), ("sha256", "SHA-256", {"mono": True}),
                                           ("size", "Bytes"), ("source_path", "Original source", {"mono": True}),
                                           ("method", "Method"), ("acquired_utc", "Acquired (UTC)")], ["method"]),
        "observables": table_spec(d["observables"], [("type", "Type"), ("value", "Value", {"mono": True}), ("sources", "Referenced by")], ["type"]),
        "errors": table_spec(d["errors"], [("utc", "Time (UTC)"), ("module", "Module"), ("kind", "Kind"), ("message", "Message"),
                                           ("path", "Path", {"mono": True})], ["module", "kind"]),
        "live": table_spec(d["live_actions"], [("utc", "Time (UTC)"), ("module", "Module"), ("action", "Action"), ("impact", "Impact")], ["module"]),
        "custody": table_spec(d["custody"], [("seq", "#"), ("utc", "Time (UTC)"), ("action", "Action"), ("actor", "Actor"),
                                             ("examiner", "Examiner"), ("details", "Details"), ("entry_hash", "Entry hash", {"mono": True})]),
    }
    title = "WezCrypt USB Forensics Kit — Investigation Report"
    subtitle = f"Case {s.get('case_id')} · Host {s.get('hostname')} · Session {s.get('session_id')} · Generated {summ.get('analyzed_utc', '')} UTC"
    return render_page(title, subtitle, sections, tables, footer_html(d["about"]))


BROWSER_TABLES = [
    ("history", "History", [("visit_time", "Visited (UTC)", {"mono": True}), ("url", "URL"), ("title", "Title"),
                            ("transition", "Transition"), ("visit_count", "Visits"), ("user", "User"), ("profile", "Profile")],
     ["user", "profile", "transition"]),
    ("downloads", "Downloads", [("start_time", "Started (UTC)", {"mono": True}), ("target_path", "Saved to"), ("source_url", "Source URL"),
                                ("state", "State"), ("danger_type", "Danger"), ("total_bytes", "Bytes"), ("user", "User"), ("profile", "Profile")],
     ["user", "state", "danger_type"]),
    ("bookmarks", "Bookmarks", [("added", "Added (UTC)", {"mono": True}), ("name", "Name"), ("url", "URL"), ("folder", "Folder"),
                                ("user", "User"), ("profile", "Profile")], ["user", "profile"]),
    ("extensions", "Extensions", [("name", "Name"), ("id", "ID", {"mono": True}), ("version", "Version"), ("enabled", "Enabled"),
                                  ("install_time", "Installed (UTC)"), ("permissions", "Permissions"), ("user", "User"), ("profile", "Profile")],
     ["user", "enabled"]),
    ("cookies_metadata", "Cookie metadata", [("host", "Host"), ("name", "Cookie name"), ("created", "Created (UTC)"),
                                             ("last_access", "Last access (UTC)"), ("expires", "Expires (UTC)"), ("secure", "Secure"),
                                             ("http_only", "HttpOnly"), ("user", "User"), ("profile", "Profile")], ["user", "secure"]),
    ("cache_entries", "Cache index", [("key", "Cached URL"), ("created", "Created (UTC)"), ("last_fetched", "Last fetched (UTC)"),
                                      ("modified", "File modified (UTC)"), ("size", "Bytes"), ("user", "User"), ("profile", "Profile")], ["user"]),
]


def build_browser_report(browser_title: str, artifacts: Dict[str, List[Dict]], session: Dict, about: Dict) -> str:
    counts = [(title, len(artifacts.get(key, []))) for key, title, _, _ in BROWSER_TABLES]
    overview = cards_html(counts) + '<div class="box">' + kv_html([
        ("Browser", browser_title), ("Case ID", session.get("case_id")), ("Session ID", session.get("session_id")),
        ("Host", session.get("hostname")), ("Collected (UTC)", session.get("started_utc")),
        ("Privacy", "Cookie values, saved passwords, autofill and session tokens are never collected."),
    ]) + "</div>"
    sections = [{"id": "b-overview", "label": "Overview", "html": "<h2>Summary</h2>" + overview}]
    tables = {}
    for key, title, cols, filters in BROWSER_TABLES:
        sections.append({"id": f"b-{key}", "label": f"{title} ({len(artifacts.get(key, []))})",
                         "html": f'<h2>{html.escape(title)}</h2><div id="t-{key}"></div>'})
        tables[key] = table_spec(artifacts.get(key, []), cols, filters)
    return render_page(f"WezCrypt USB Forensics Kit — {browser_title} Report",
                       f"Case {session.get('case_id')} · Host {session.get('hostname')} · Session {session.get('session_id')}",
                       sections, tables, footer_html(about))
