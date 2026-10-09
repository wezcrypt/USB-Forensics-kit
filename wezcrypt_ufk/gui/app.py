"""Tkinter GUI. Long-running work runs in worker threads; the UI is updated from a queue polled on the Tk loop."""

from __future__ import annotations

import csv
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Dict, List, Optional

from .. import ABOUT, __app_name__, __version__
from ..core.config import Config
from ..core.logging_setup import LOGGER_NAME
from ..core.paths import default_output_root, detect_run_location
from ..core.winapi import is_admin
from . import theme

PAGES = [("dashboard", "Dashboard"), ("collect", "Evidence Collection"), ("progress", "Live Progress"),
         ("explorer", "Evidence Explorer"), ("timeline", "Timeline Analysis"), ("hashes", "Hash Verification"),
         ("reports", "Report Generator"), ("settings", "Settings"), ("about", "About")]
MAX_TABLE_ROWS = 5000


class QueueLogHandler(logging.Handler):
    def __init__(self, q: "queue.Queue"):
        super().__init__(logging.INFO)
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    def emit(self, record):
        try:
            self.q.put(("log", self.format(record)))
        except Exception:
            pass


def open_path(path: str) -> None:
    if not path or not os.path.exists(path):
        messagebox.showwarning(__app_name__, f"Path not found:\n{path}")
        return
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 - opens with the examiner's default viewer
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def make_tree(parent, columns: List[str], widths: Optional[Dict[str, int]] = None, height: int = 15) -> ttk.Treeview:
    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True)
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    for c in columns:
        tree.heading(c, text=c, command=lambda col=c: sort_tree(tree, col))
        tree.column(c, width=(widths or {}).get(c, 140), stretch=True, anchor="w")
    vs = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    hs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vs.grid(row=0, column=1, sticky="ns")
    hs.grid(row=1, column=0, sticky="ew")
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    for sev, color in theme.SEVERITY.items():
        tree.tag_configure(sev, foreground=color)
    tree.tag_configure("failed", foreground=theme.ERR)
    tree.tag_configure("partial", foreground=theme.WARN)
    tree.tag_configure("completed", foreground=theme.OK)
    return tree


def sort_tree(tree: ttk.Treeview, col: str) -> None:
    rows = [(tree.set(k, col), k) for k in tree.get_children("")]
    reverse = getattr(tree, "_sort_reverse", {}).get(col, False)

    def key(v):
        try:
            return (0, float(v[0]))
        except ValueError:
            return (1, v[0].lower())

    rows.sort(key=key, reverse=reverse)
    for i, (_, k) in enumerate(rows):
        tree.move(k, "", i)
    tree._sort_reverse = {**getattr(tree, "_sort_reverse", {}), col: not reverse}


def cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)[:400]
    return str(v)[:400]


class App:
    def __init__(self, root: tk.Tk, config: Config):
        self.root = root
        self.config = config
        self.q: "queue.Queue" = queue.Queue()
        self.current_session: Optional[str] = None
        self.orchestrator = None
        self.busy = False
        root.title(f"{__app_name__} {__version__}")
        root.geometry("1360x840")
        root.minsize(1100, 700)
        theme.apply(root)
        if sys.platform == "win32":
            from ..core.paths import bundled_resource

            try:
                root.iconbitmap(bundled_resource("assets", "wezcrypt.ico"))
            except tk.TclError:
                pass
        self.log_handler = QueueLogHandler(self.q)
        logging.getLogger(LOGGER_NAME).addHandler(self.log_handler)
        self._build_shell()
        self.pages: Dict[str, ttk.Frame] = {}
        builders = {"dashboard": self._page_dashboard, "collect": self._page_collect, "progress": self._page_progress,
                    "explorer": self._page_explorer, "timeline": self._page_timeline, "hashes": self._page_hashes,
                    "reports": self._page_reports, "settings": self._page_settings, "about": self._page_about}
        for key, _ in PAGES:
            frame = ttk.Frame(self.content, padding=22)
            builders[key](frame)
            self.pages[key] = frame
        self.show("dashboard")
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(100, self._poll)

    # ------------------------------------------------------------------ shell

    def _build_shell(self) -> None:
        side = ttk.Frame(self.root, style="Side.TFrame", width=230)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ttk.Label(side, text="WEZCRYPT", style="Brand.TLabel").pack(anchor="w", padx=18, pady=(20, 0))
        ttk.Label(side, text="USB Forensics Kit", style="PanelMuted.TLabel").pack(anchor="w", padx=18, pady=(0, 18))
        self.nav: Dict[str, ttk.Button] = {}
        for key, label in PAGES:
            b = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show(k))
            b.pack(fill="x")
            self.nav[key] = b
        admin = is_admin()
        ttk.Label(side, text=("● Administrator" if admin else "● Standard user"), style="PanelMuted.TLabel",
                  foreground=theme.OK if admin else theme.WARN).pack(side="bottom", anchor="w", padx=18, pady=14)
        right = ttk.Frame(self.root)
        right.pack(side="left", fill="both", expand=True)
        self.status_var = tk.StringVar(value="Ready")
        bar = ttk.Frame(right, style="Panel.TFrame")
        bar.pack(side="bottom", fill="x")
        ttk.Label(bar, textvariable=self.status_var, style="PanelMuted.TLabel").pack(side="left", padx=12, pady=5)
        self.session_var = tk.StringVar(value="No session loaded")
        ttk.Label(bar, textvariable=self.session_var, style="PanelMuted.TLabel").pack(side="right", padx=12)
        self.content = ttk.Frame(right)
        self.content.pack(fill="both", expand=True)

    def show(self, key: str) -> None:
        for k, f in self.pages.items():
            f.pack_forget()
            self.nav[k].configure(style="Nav.TButton")
        self.pages[key].pack(fill="both", expand=True)
        self.nav[key].configure(style="NavActive.TButton")
        refresh = getattr(self, f"_refresh_{key}", None)
        if refresh:
            refresh()

    def header(self, parent, title: str, subtitle: str = "") -> None:
        ttk.Label(parent, text=title, style="Title.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(parent, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(2, 14))

    def output_root(self) -> str:
        return self.config.output_dir or default_output_root()

    def set_session(self, path: Optional[str]) -> None:
        self.current_session = path
        self.session_var.set(f"Session: {os.path.basename(path)}" if path else "No session loaded")

    def run_bg(self, label: str, fn: Callable, done: Optional[Callable] = None,
               finally_cb: Optional[Callable] = None) -> None:
        if self.busy:
            messagebox.showinfo(__app_name__, "Another operation is running. Please wait or cancel it.")
            return
        self.busy = True
        self.status_var.set(label + "...")

        def worker():
            try:
                result = fn()
                self.q.put(("done", (label, done, result, None, finally_cb)))
            except Exception as exc:  # reported in the UI
                logging.getLogger(LOGGER_NAME).exception("%s failed", label)
                self.q.put(("done", (label, done, None, exc, finally_cb)))

        threading.Thread(target=worker, daemon=True, name="gui-worker").start()

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self._append_log(payload)
                elif kind == "progress":
                    self._on_progress(*payload)
                elif kind == "status":
                    self._on_status(*payload)
                elif kind == "done":
                    label, done, result, exc, finally_cb = payload
                    self.busy = False
                    if finally_cb:
                        finally_cb()
                    self.status_var.set(f"{label}: {'failed' if exc else 'finished'}")
                    if exc:
                        messagebox.showerror(__app_name__, f"{label} failed:\n{exc}")
                    elif done:
                        done(result)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _on_close(self) -> None:
        if self.orchestrator is not None and self.busy:
            if not messagebox.askyesno(__app_name__, "A collection is running. Cancel it and exit?"):
                return
            self.orchestrator.cancel()
        logging.getLogger(LOGGER_NAME).removeHandler(self.log_handler)
        self.root.destroy()

    # ------------------------------------------------------------------ dashboard

    def _page_dashboard(self, p) -> None:
        self.header(p, "Dashboard", "System status, evidence statistics and recent investigation sessions")
        self.cards = ttk.Frame(p)
        self.cards.pack(fill="x", pady=(0, 14))
        self.dash_warn = ttk.Label(p, text="", style="Muted.TLabel", foreground=theme.WARN, wraplength=1000, justify="left")
        self.dash_warn.pack(anchor="w", pady=(0, 10))
        ttk.Label(p, text="Recent sessions", style="H2.TLabel").pack(anchor="w", pady=(4, 6))
        btns = ttk.Frame(p)
        btns.pack(fill="x", pady=(0, 6))
        ttk.Button(btns, text="Load selected session", style="Accent.TButton", command=self._dash_load).pack(side="left")
        ttk.Button(btns, text="Open session folder", command=self._dash_open).pack(side="left", padx=8)
        ttk.Button(btns, text="Open session report", command=self._dash_report).pack(side="left")
        ttk.Button(btns, text="Refresh", command=self._refresh_dashboard).pack(side="left", padx=8)
        self.dash_tree = make_tree(p, ["Started (UTC)", "Case", "Status", "Host", "Admin", "Files", "Errors", "Folder"],
                                   {"Folder": 420, "Case": 180}, 12)
        self.dash_tree.bind("<Double-1>", lambda e: self._dash_load())

    def _card(self, parent, key: str, value: str, color: Optional[str] = None) -> None:
        f = ttk.Frame(parent, style="Panel.TFrame", padding=(16, 10))
        f.pack(side="left", padx=(0, 10), fill="y")
        lbl = ttk.Label(f, text=value, style="CardValue.TLabel")
        if color:
            lbl.configure(foreground=color)
        lbl.pack(anchor="w")
        ttk.Label(f, text=key, style="CardKey.TLabel").pack(anchor="w")

    def _refresh_dashboard(self) -> None:
        from ..core.session import list_sessions

        for w in self.cards.winfo_children():
            w.destroy()
        loc = detect_run_location()
        root = self.output_root()
        sessions = list_sessions(root)
        free = "-"
        try:
            import shutil

            probe = root if os.path.isdir(root) else loc.app_dir
            free = f"{shutil.disk_usage(probe).free / (1024 ** 3):.1f} GB"
        except OSError:
            pass
        sev: Dict[str, int] = {}
        if self.current_session:
            try:
                with open(os.path.join(self.current_session, "analysis", "summary.json"), encoding="utf-8") as fh:
                    sev = json.load(fh).get("severity_counts", {})
            except (OSError, ValueError):
                sev = {}
        self._card(self.cards, "Privileges", "Admin" if is_admin() else "Standard", theme.OK if is_admin() else theme.WARN)
        self._card(self.cards, "Kit drive type", loc.drive_type, theme.OK if loc.is_removable else theme.WARN)
        self._card(self.cards, "Free space (output)", free)
        self._card(self.cards, "Sessions", str(len(sessions)))
        self._card(self.cards, "High / Critical (loaded)", f"{sev.get('high', 0)} / {sev.get('critical', 0)}",
                   theme.SEVERITY["high"] if sev.get("high") or sev.get("critical") else None)
        self._card(self.cards, "Medium / Low (loaded)", f"{sev.get('medium', 0)} / {sev.get('low', 0)}")
        warnings = loc.warnings()
        if not is_admin():
            warnings.append("Running as a standard user: Prefetch, Amcache, Security log and other users' artifacts "
                            "will not be collected. Re-launch as Administrator for full coverage.")
        self.dash_warn.configure(text="\n".join("⚠ " + w for w in warnings) or f"Output folder: {root}")
        self.dash_tree.delete(*self.dash_tree.get_children())
        for s in sessions[:200]:
            st = s.get("stats") or {}
            self.dash_tree.insert("", "end", values=(s.get("started_utc"), s.get("case_id"), s.get("status"), s.get("hostname"),
                                                     s.get("is_admin"), st.get("files_acquired", ""), st.get("errors", ""),
                                                     s.get("session_dir")),
                                  tags=("completed" if s.get("status") == "completed" else "partial",))

    def _dash_selected(self) -> Optional[str]:
        sel = self.dash_tree.selection()
        if not sel:
            messagebox.showinfo(__app_name__, "Select a session first.")
            return None
        return self.dash_tree.item(sel[0], "values")[7]

    def _dash_load(self) -> None:
        path = self._dash_selected()
        if path:
            self.set_session(path)
            self._refresh_dashboard()
            self.status_var.set(f"Loaded session {os.path.basename(path)}")

    def _dash_open(self) -> None:
        path = self._dash_selected()
        if path:
            open_path(path)

    def _dash_report(self) -> None:
        path = self._dash_selected()
        if path:
            open_path(os.path.join(path, "reports", "report.html"))

    # ------------------------------------------------------------------ collection

    def _page_collect(self, p) -> None:
        from ..collectors.base import all_collectors

        self.header(p, "Evidence Collection", "Select evidence types, confirm authorisation and start the collection")
        form = ttk.Frame(p)
        form.pack(fill="x")
        self.case_var = tk.StringVar()
        self.examiner_var = tk.StringVar(value=self.config.examiner)
        self.notes_var = tk.StringVar()
        for i, (label, var, w) in enumerate((("Case ID (optional)", self.case_var, 30), ("Examiner", self.examiner_var, 30),
                                              ("Authorisation / notes", self.notes_var, 44))):
            ttk.Label(form, text=label).grid(row=0, column=i * 2, sticky="w", padx=(0, 6))
            ttk.Entry(form, textvariable=var, width=w).grid(row=0, column=i * 2 + 1, sticky="w", padx=(0, 18))
        body = ttk.Frame(p)
        body.pack(fill="both", expand=True, pady=12)
        self.module_vars: Dict[str, tk.BooleanVar] = {}
        collectors = sorted(all_collectors(), key=lambda c: (c.category, c.title))
        cats: Dict[str, list] = {}
        for c in collectors:
            cats.setdefault(c.category, []).append(c)
        admin = is_admin()
        layout = {"Windows": (0, 0, 2), "System": (0, 1, 1), "Network": (0, 2, 1), "Browsers": (1, 1, 1),
                  "File System": (1, 2, 1)}
        for cat, (row, col, rowspan) in layout.items():
            if cat not in cats:
                continue
            lf = ttk.LabelFrame(body, text=cat, padding=10)
            lf.grid(row=row, column=col, rowspan=rowspan, sticky="nsew", padx=(0, 10), pady=(0, 8))
            items = cats[cat]
            per_col = 9 if cat == "Windows" else len(items)
            for i, c in enumerate(items):
                var = tk.BooleanVar(value=c.default_enabled)
                self.module_vars[c.name] = var
                mark = {"yes": "  [A]", "partial": "  [a]", "no": ""}[c.requires_admin]
                cb = ttk.Checkbutton(lf, text=c.title + mark, variable=var)
                cb.grid(row=i % per_col, column=i // per_col, sticky="w", pady=1, padx=(0, 18))
                if c.requires_admin == "yes" and not admin:
                    cb.configure(text=c.title + "  [A - not available]")
        for col in range(3):
            body.columnconfigure(col, weight=1)
        ttk.Label(p, text="[A] requires Administrator    [a] Administrator recommended for complete data"
                  + ("" if admin else "    -  currently running as a standard user"), style="Muted.TLabel").pack(anchor="w")
        opts = ttk.Frame(p)
        opts.pack(fill="x", pady=(4, 8))
        ttk.Button(opts, text="Select all", command=lambda: [v.set(True) for v in self.module_vars.values()]).pack(side="left")
        ttk.Button(opts, text="Select none", command=lambda: [v.set(False) for v in self.module_vars.values()]).pack(side="left", padx=6)
        ttk.Label(opts, text="   Reports:").pack(side="left")
        self.fmt_vars = {f: tk.BooleanVar(value=True) for f in ("html", "json", "csv", "pdf")}
        for f, v in self.fmt_vars.items():
            ttk.Checkbutton(opts, text=f.upper(), variable=v).pack(side="left", padx=4)
        bottom = ttk.Frame(p)
        bottom.pack(fill="x", pady=(8, 0))
        self.auth_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(bottom, text="I confirm I am authorised to examine this system and that collection actions are "
                                     "documented in the chain of custody.", variable=self.auth_var).pack(anchor="w")
        self.start_btn = ttk.Button(bottom, text="Start collection", style="Accent.TButton", command=self._start_collection)
        self.start_btn.pack(anchor="w", pady=10)

    def _start_collection(self) -> None:
        from ..core.orchestrator import Orchestrator

        if not self.auth_var.get():
            messagebox.showwarning(__app_name__, "Confirm authorisation before starting.")
            return
        modules = [k for k, v in self.module_vars.items() if v.get()]
        if not modules:
            messagebox.showwarning(__app_name__, "Select at least one evidence type.")
            return
        formats = [f for f, v in self.fmt_vars.items() if v.get()]
        self.config.examiner = self.examiner_var.get().strip()
        self.orchestrator = Orchestrator(
            self.config, modules, case_id=self.case_var.get().strip(), examiner=self.config.examiner,
            notes=self.notes_var.get().strip(), progress_cb=lambda m, f, msg: self.q.put(("progress", (m, f, msg))),
            status_cb=lambda e, d: self.q.put(("status", (e, d))), report_formats=formats)
        self.prog_tree.delete(*self.prog_tree.get_children())
        from ..collectors.base import get_collector

        for m in modules:
            self.prog_tree.insert("", "end", iid=m, values=(get_collector(m).title, "queued", "0%", "", "", ""))
        self.overall.configure(maximum=len(modules), value=0)
        self.log_text.delete("1.0", "end")
        self.cancel_btn.configure(state="normal")
        self.start_btn.configure(state="disabled")
        self.show("progress")
        orch = self.orchestrator
        self.run_bg("Collection", orch.run, self._collection_done, self._collection_reset)

    def _collection_reset(self) -> None:
        self.cancel_btn.configure(state="disabled")
        self.start_btn.configure(state="normal")

    def _collection_done(self, session) -> None:
        self.set_session(session.session_dir)
        ver = session.stats.get("post_collection_verification", {})
        self.prog_label.configure(text=f"Session {session.status}. Integrity verification: "
                                       f"{'PASSED' if ver.get('passed') else 'NOT PASSED'}. Output: {session.session_dir}")
        messagebox.showinfo(__app_name__, f"Collection {session.status}.\n\nIntegrity verification: "
                                          f"{'PASSED' if ver.get('passed') else 'NOT PASSED'}\n\n{session.session_dir}")

    # ------------------------------------------------------------------ progress

    def _page_progress(self, p) -> None:
        self.header(p, "Live Progress", "Per-module status of the running collection")
        top = ttk.Frame(p)
        top.pack(fill="x", pady=(0, 8))
        self.overall = ttk.Progressbar(top, mode="determinate", length=600)
        self.overall.pack(side="left", fill="x", expand=True)
        self.cancel_btn = ttk.Button(top, text="Cancel collection", state="disabled", command=self._cancel)
        self.cancel_btn.pack(side="left", padx=10)
        self.prog_label = ttk.Label(p, text="Idle", style="Muted.TLabel")
        self.prog_label.pack(anchor="w", pady=(0, 8))
        holder = ttk.Frame(p, height=300)
        holder.pack(fill="both", expand=True)
        self.prog_tree = make_tree(holder, ["Module", "Status", "Progress", "Files", "Errors", "Detail"],
                                   {"Module": 230, "Detail": 520}, 12)
        ttk.Label(p, text="Log", style="H2.TLabel").pack(anchor="w", pady=(10, 4))
        self.log_text = theme.text_widget(p, height=10)
        self.log_text.pack(fill="both", expand=False)

    def _cancel(self) -> None:
        if self.orchestrator is not None and messagebox.askyesno(__app_name__, "Cancel the running collection?\n"
                                                                               "Evidence gathered so far is kept and hashed."):
            self.orchestrator.cancel()
            self.cancel_btn.configure(state="disabled")
            self.prog_label.configure(text="Cancelling - waiting for modules to stop safely...")

    def _append_log(self, line: str) -> None:
        self.log_text.insert("end", line + "\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 3000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.see("end")

    def _on_progress(self, module: str, frac: float, msg: str) -> None:
        if self.prog_tree.exists(module):
            vals = list(self.prog_tree.item(module, "values"))
            vals[2] = f"{int(frac * 100)}%"
            vals[5] = msg[:200]
            self.prog_tree.item(module, values=vals)

    def _on_status(self, event: str, data: Dict) -> None:
        if event == "module_started" and self.prog_tree.exists(data["module"]):
            vals = list(self.prog_tree.item(data["module"], "values"))
            vals[1] = "running"
            self.prog_tree.item(data["module"], values=vals)
        elif event == "module_finished" and self.prog_tree.exists(data["module"]):
            r = data["result"]
            self.prog_tree.item(data["module"], values=(r["title"], r["status"], "100%", r["files_acquired"], r["errors"],
                                                        r.get("message") or ", ".join(f"{k}:{v}" for k, v in r["record_counts"].items())[:200]),
                                tags=(r["status"],))
            self.overall.step(1)
        elif event == "phase":
            self.prog_label.configure(text=f"Phase: {data['name']}")
        elif event == "session_started":
            self.prog_label.configure(text=f"Collecting into {data['session_dir']}")

    # ------------------------------------------------------------------ explorer

    def _page_explorer(self, p) -> None:
        self.header(p, "Evidence Explorer", "Browse parsed artifacts of the loaded session")
        bar = ttk.Frame(p)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Open session...", command=self._browse_session).pack(side="left")
        ttk.Button(bar, text="Open evidence folder", command=lambda: self.current_session and open_path(
            os.path.join(self.current_session, "evidence"))).pack(side="left", padx=8)
        ttk.Label(bar, text="Filter:").pack(side="left", padx=(16, 4))
        self.exp_filter = tk.StringVar()
        e = ttk.Entry(bar, textvariable=self.exp_filter, width=40)
        e.pack(side="left")
        e.bind("<Return>", lambda ev: self._exp_load())
        ttk.Button(bar, text="Apply", command=self._exp_load).pack(side="left", padx=6)
        self.exp_info = ttk.Label(bar, text="", style="Muted.TLabel")
        self.exp_info.pack(side="left", padx=10)
        pane = ttk.PanedWindow(p, orient="horizontal")
        pane.pack(fill="both", expand=True)
        left = ttk.Frame(pane, width=280)
        self.exp_artifacts = ttk.Treeview(left, show="tree", height=25)
        self.exp_artifacts.pack(fill="both", expand=True)
        self.exp_artifacts.bind("<<TreeviewSelect>>", lambda e: self._exp_load())
        pane.add(left, weight=1)
        right = ttk.Frame(pane)
        self.exp_table_holder = ttk.Frame(right)
        self.exp_table_holder.pack(fill="both", expand=True)
        self.exp_detail = theme.text_widget(right, height=9)
        self.exp_detail.pack(fill="x", pady=(8, 0))
        pane.add(right, weight=4)
        self.exp_tree = None
        self.exp_rows: List[Dict] = []

    def _browse_session(self) -> None:
        path = filedialog.askdirectory(initialdir=self.output_root(), title="Select a session folder")
        if path:
            if not os.path.isfile(os.path.join(path, "session.json")):
                messagebox.showwarning(__app_name__, "Not a session folder (session.json missing).")
                return
            self.set_session(path)
            self._refresh_explorer()

    def _refresh_explorer(self) -> None:
        from ..analysis.data import SessionData

        self.exp_artifacts.delete(*self.exp_artifacts.get_children())
        if not self.current_session:
            self.exp_info.configure(text="Load a session from the Dashboard or 'Open session...'")
            return
        data = SessionData(self.current_session)
        for m in data.modules():
            node = self.exp_artifacts.insert("", "end", text=m, open=False)
            for a in data.artifacts(m):
                self.exp_artifacts.insert(node, "end", iid=f"{m}|{a}", text=f"{a} ({data.count(m, a)})")

    def _exp_load(self) -> None:
        from ..analysis.data import SessionData

        sel = self.exp_artifacts.selection()
        if not sel or "|" not in sel[0] or not self.current_session:
            return
        module, artifact = sel[0].split("|", 1)
        term = self.exp_filter.get().strip().lower()
        rows = []
        total = 0
        for r in SessionData(self.current_session).records(module, artifact):
            total += 1
            if term and term not in json.dumps(r, ensure_ascii=False).lower():
                continue
            if len(rows) < MAX_TABLE_ROWS:
                rows.append(r)
        cols: List[str] = []
        for r in rows[:200]:
            for k in r:
                if k not in cols:
                    cols.append(k)
        cols = cols[:25] or ["(empty)"]
        for w in self.exp_table_holder.winfo_children():
            w.destroy()
        self.exp_tree = make_tree(self.exp_table_holder, cols, height=18)
        self.exp_rows = rows
        for i, r in enumerate(rows):
            self.exp_tree.insert("", "end", iid=str(i), values=[cell(r.get(c)) for c in cols])
        self.exp_tree.bind("<<TreeviewSelect>>", self._exp_detail)
        self.exp_info.configure(text=f"{len(rows)} shown / {total} records" + (" (display limit)" if len(rows) >= MAX_TABLE_ROWS else ""))

    def _exp_detail(self, _evt=None) -> None:
        sel = self.exp_tree.selection() if self.exp_tree else ()
        if sel:
            self.exp_detail.delete("1.0", "end")
            self.exp_detail.insert("1.0", json.dumps(self.exp_rows[int(sel[0])], indent=2, ensure_ascii=False, default=str))

    # ------------------------------------------------------------------ timeline

    def _page_timeline(self, p) -> None:
        self.header(p, "Timeline Analysis", "Unified, chronologically ordered events from all sources (UTC)")
        bar = ttk.Frame(p)
        bar.pack(fill="x", pady=(0, 8))
        self.tl_text = tk.StringVar()
        self.tl_source = tk.StringVar(value="(all)")
        self.tl_from = tk.StringVar()
        self.tl_to = tk.StringVar()
        ttk.Label(bar, text="Search").pack(side="left")
        ttk.Entry(bar, textvariable=self.tl_text, width=30).pack(side="left", padx=4)
        ttk.Label(bar, text="Source").pack(side="left", padx=(10, 0))
        self.tl_source_cb = ttk.Combobox(bar, textvariable=self.tl_source, width=28, state="readonly", values=["(all)"])
        self.tl_source_cb.pack(side="left", padx=4)
        ttk.Label(bar, text="From").pack(side="left", padx=(10, 0))
        ttk.Entry(bar, textvariable=self.tl_from, width=20).pack(side="left", padx=4)
        ttk.Label(bar, text="To").pack(side="left")
        ttk.Entry(bar, textvariable=self.tl_to, width=20).pack(side="left", padx=4)
        ttk.Button(bar, text="Apply", style="Accent.TButton", command=self._tl_load).pack(side="left", padx=6)
        ttk.Button(bar, text="Export CSV", command=self._tl_export).pack(side="left")
        self.tl_info = ttk.Label(p, text="Dates: YYYY-MM-DD or YYYY-MM-DDTHH:MM (UTC)", style="Muted.TLabel")
        self.tl_info.pack(anchor="w", pady=(0, 6))
        self.tl_tree = make_tree(p, ["Timestamp (UTC)", "Source", "Type", "Description", "Module"],
                                 {"Timestamp (UTC)": 200, "Description": 700}, 22)
        self.tl_rows: List[Dict] = []

    def _tl_matches(self, ev: Dict) -> bool:
        ts = ev.get("timestamp") or ""
        if self.tl_from.get().strip() and ts < self.tl_from.get().strip():
            return False
        if self.tl_to.get().strip() and ts[:len(self.tl_to.get().strip())] > self.tl_to.get().strip():
            return False
        if self.tl_source.get() not in ("", "(all)") and ev.get("source") != self.tl_source.get():
            return False
        term = self.tl_text.get().strip().lower()
        return not term or term in (ev.get("description") or "").lower() or term in json.dumps(ev.get("details") or {}).lower()

    def _refresh_timeline(self) -> None:
        if not self.current_session:
            self.tl_info.configure(text="Load a session first (Dashboard).")
            return
        try:
            with open(os.path.join(self.current_session, "analysis", "summary.json"), encoding="utf-8") as fh:
                sources = sorted((json.load(fh).get("timeline") or {}).get("by_source", {}).keys())
            self.tl_source_cb.configure(values=["(all)"] + sources)
        except (OSError, ValueError):
            pass
        self._tl_load()

    def _tl_iter(self):
        path = os.path.join(self.current_session, "analysis", "timeline.jsonl")
        if not os.path.isfile(path):
            return
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    ev = json.loads(line)
                    if self._tl_matches(ev):
                        yield ev

    def _tl_load(self) -> None:
        if not self.current_session:
            return
        from collections import deque

        matched = 0
        rows: deque = deque(maxlen=MAX_TABLE_ROWS)
        for ev in self._tl_iter():
            matched += 1
            rows.append(ev)
        self.tl_rows = list(rows)
        self.tl_tree.delete(*self.tl_tree.get_children())
        for ev in self.tl_rows:
            self.tl_tree.insert("", "end", values=(ev.get("timestamp"), ev.get("source"), ev.get("event_type"),
                                                   ev.get("description"), ev.get("module")))
        self.tl_info.configure(text=f"{matched} matching events" + (f"; showing the most recent {len(self.tl_rows)}"
                                                                    if matched > len(self.tl_rows) else ""))

    def _tl_export(self) -> None:
        if not self.current_session:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")],
                                            initialdir=os.path.join(self.current_session, "reports"),
                                            initialfile="timeline_filtered.csv")
        if not path:
            return
        n = 0
        with open(path, "w", encoding="utf-8-sig", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "source", "event_type", "description", "module", "details"])
            for ev in self._tl_iter():
                w.writerow([ev.get("timestamp"), ev.get("source"), ev.get("event_type"), ev.get("description"),
                            ev.get("module"), json.dumps(ev.get("details") or {}, ensure_ascii=False)])
                n += 1
        messagebox.showinfo(__app_name__, f"Exported {n} events to\n{path}")

    # ------------------------------------------------------------------ hashes

    def _page_hashes(self, p) -> None:
        self.header(p, "Hash Verification", "Re-hash evidence against the SHA-256 manifest and validate the custody chain")
        bar = ttk.Frame(p)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Button(bar, text="Verify loaded session", style="Accent.TButton", command=self._verify_current).pack(side="left")
        ttk.Button(bar, text="Verify other session...", command=self._verify_other).pack(side="left", padx=8)
        ttk.Button(bar, text="Hash a file...", command=self._hash_file).pack(side="left")
        self.hash_result = ttk.Label(p, text="", style="Muted.TLabel", wraplength=1000, justify="left")
        self.hash_result.pack(anchor="w", pady=(0, 8))
        self.hash_tree = make_tree(p, ["Result", "File", "Expected SHA-256", "Actual SHA-256"],
                                   {"File": 420, "Expected SHA-256": 300, "Actual SHA-256": 300}, 20)

    def _verify(self, path: str) -> None:
        from ..core.custody import CustodyLog
        from ..core.integrity import verify_manifest

        def work():
            res = verify_manifest(path)
            CustodyLog(os.path.join(path, "chain_of_custody.jsonl")).append(
                "integrity_verification", {"passed": res.passed, "modified": len(res.modified), "missing": len(res.missing)},
                examiner=self.config.examiner)
            return res

        def done(res):
            self.hash_tree.delete(*self.hash_tree.get_children())
            for m in res.modified:
                self.hash_tree.insert("", "end", values=("MODIFIED", m["path"], m["expected"], m["actual"]), tags=("critical",))
            for m in res.missing:
                self.hash_tree.insert("", "end", values=("MISSING", m, "", ""), tags=("high",))
            for m in res.unexpected:
                self.hash_tree.insert("", "end", values=("NOT IN MANIFEST", m, "", ""), tags=("medium",))
            for c in res.custody_problems:
                self.hash_tree.insert("", "end", values=("CUSTODY", c, "", ""), tags=("critical",))
            for m in res.ok[:MAX_TABLE_ROWS]:
                self.hash_tree.insert("", "end", values=("OK", m, "", ""), tags=("completed",))
            self.hash_result.configure(
                text=f"{'PASSED' if res.passed else 'FAILED'} - {res.manifest_message}. OK {len(res.ok)}, modified "
                     f"{len(res.modified)}, missing {len(res.missing)}, not in manifest {len(res.unexpected)}, custody issues "
                     f"{len(res.custody_problems)}.  ({path})",
                foreground=theme.OK if res.passed else theme.ERR)

        self.run_bg("Integrity verification", work, done)

    def _verify_current(self) -> None:
        if not self.current_session:
            messagebox.showinfo(__app_name__, "Load a session first (Dashboard) or use 'Verify other session...'.")
            return
        self._verify(self.current_session)

    def _verify_other(self) -> None:
        path = filedialog.askdirectory(initialdir=self.output_root(), title="Select a session folder")
        if path:
            self._verify(path)

    def _hash_file(self) -> None:
        from ..core.hashing import sha256_file

        path = filedialog.askopenfilename(title="Select a file to hash")
        if not path:
            return

        def done(digest):
            self.hash_result.configure(text=f"SHA-256 {digest}  {path}", foreground=theme.TEXT)
            self.root.clipboard_clear()
            self.root.clipboard_append(digest)
            self.status_var.set("SHA-256 copied to clipboard")

        self.run_bg("Hashing file", lambda: sha256_file(path), done)

    # ------------------------------------------------------------------ reports

    def _page_reports(self, p) -> None:
        self.header(p, "Report Generator", "Re-run analysis and generate HTML, PDF, JSON and CSV reports for the loaded session")
        box = ttk.Frame(p)
        box.pack(fill="x")
        self.rep_fmt = {f: tk.BooleanVar(value=True) for f in ("html", "json", "csv", "pdf")}
        for f, v in self.rep_fmt.items():
            ttk.Checkbutton(box, text=f.upper(), variable=v).pack(side="left", padx=(0, 10))
        self.rep_reanalyze = tk.BooleanVar(value=True)
        ttk.Checkbutton(box, text="Re-run analysis first", variable=self.rep_reanalyze).pack(side="left", padx=14)
        ioc = ttk.Frame(p)
        ioc.pack(fill="x", pady=10)
        ttk.Label(ioc, text="IOC file (optional)").pack(side="left")
        self.rep_ioc = tk.StringVar(value=self.config.ioc_file)
        ttk.Entry(ioc, textvariable=self.rep_ioc, width=70).pack(side="left", padx=6)
        ttk.Button(ioc, text="Browse...", command=lambda: self.rep_ioc.set(
            filedialog.askopenfilename(title="IOC list", filetypes=[("Text", "*.txt"), ("All", "*.*")]) or self.rep_ioc.get())).pack(side="left")
        btns = ttk.Frame(p)
        btns.pack(fill="x", pady=(0, 10))
        ttk.Button(btns, text="Generate reports", style="Accent.TButton", command=self._generate).pack(side="left")
        ttk.Button(btns, text="Open HTML report", command=lambda: self.current_session and open_path(
            os.path.join(self.current_session, "reports", "report.html"))).pack(side="left", padx=8)
        ttk.Button(btns, text="Open PDF report", command=lambda: self.current_session and open_path(
            os.path.join(self.current_session, "reports", "report.pdf"))).pack(side="left")
        ttk.Button(btns, text="Open reports folder", command=lambda: self.current_session and open_path(
            os.path.join(self.current_session, "reports"))).pack(side="left", padx=8)
        self.rep_info = ttk.Label(p, text="", style="Muted.TLabel")
        self.rep_info.pack(anchor="w")
        self.rep_tree = make_tree(p, ["File", "SHA-256", "Bytes"], {"File": 420, "SHA-256": 470}, 16)
        self.rep_tree.bind("<Double-1>", self._open_report_row)

    def _refresh_reports(self) -> None:
        self.rep_info.configure(text=f"Session: {self.current_session or 'none loaded'}")
        self.rep_tree.delete(*self.rep_tree.get_children())
        if self.current_session:
            path = os.path.join(self.current_session, "reports", "report_hashes.json")
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    for f in json.load(fh).get("files", []):
                        self.rep_tree.insert("", "end", values=(f["path"], f["sha256"], f["size"]))

    def _open_report_row(self, _evt=None) -> None:
        sel = self.rep_tree.selection()
        if sel and self.current_session:
            open_path(os.path.join(self.current_session, *self.rep_tree.item(sel[0], "values")[0].split("/")))

    def _generate(self) -> None:
        if not self.current_session:
            messagebox.showinfo(__app_name__, "Load a session first (Dashboard).")
            return
        formats = [f for f, v in self.rep_fmt.items() if v.get()]
        if not formats:
            messagebox.showwarning(__app_name__, "Select at least one format.")
            return
        session = self.current_session
        cfg = Config(**self.config.to_dict())
        cfg.ioc_file = self.rep_ioc.get().strip()
        reanalyze = self.rep_reanalyze.get()

        def work():
            from ..analysis.engine import run_analysis
            from ..core.custody import CustodyLog
            from ..reporting.generator import generate_reports

            custody = CustodyLog(os.path.join(session, "chain_of_custody.jsonl"))
            if reanalyze or not os.path.isfile(os.path.join(session, "analysis", "summary.json")):
                summary = run_analysis(session, cfg)
                custody.append("analysis_rerun", summary, examiner=cfg.examiner)
            out = generate_reports(session, formats, cfg)
            custody.append("reports_generated", {"files": out}, examiner=cfg.examiner)
            return out

        self.run_bg("Report generation", work, lambda out: (self._refresh_reports(),
                                                            self.status_var.set(f"{len(out)} report files generated")))

    # ------------------------------------------------------------------ settings

    SETTINGS = [
        ("output_dir", "Output folder (empty = <kit>\\WezCrypt_Cases)", "dir"),
        ("examiner", "Default examiner", "str"), ("organization", "Organization", "str"),
        ("case_prefix", "Case ID prefix", "str"), ("max_workers", "Parallel modules (1-16)", "int"),
        ("eventlog_max_events", "Max events per log channel", "int"),
        ("script_block_max_chars", "Max characters per event field", "int"),
        ("browser_max_rows", "Max browser rows per table", "int"),
        ("fs_max_depth", "File scan depth", "int"), ("fs_max_files", "File scan max files", "int"),
        ("fs_hash_max_mb", "Max file size to hash (MB)", "int"), ("fs_copy_max_mb", "Max suspicious file copy (MB)", "int"),
        ("html_timeline_limit", "Timeline rows in HTML report", "int"),
        ("failed_logon_threshold", "Failed logon threshold", "int"),
        ("failed_logon_window_minutes", "Failed logon window (minutes)", "int"),
        ("ioc_file", "IOC file", "file"),
        ("verify_signatures", "Verify Authenticode signatures (PowerShell)", "bool"),
        ("hash_process_executables", "Hash running process executables", "bool"),
        ("acquire_registry_hives", "Export registry hives (reg save)", "bool"),
        ("use_vss_for_locked", "Use VSS (esentutl) for locked browser files - Administrator", "bool"),
        ("fs_copy_suspicious", "Copy suspicious files into evidence", "bool"),
        ("collect_browser_cache_index", "Index browser caches", "bool"),
    ]

    def _page_settings(self, p) -> None:
        self.header(p, "Settings", f"Stored next to the kit: {Config.path()}")
        canvas = tk.Canvas(p, bg=theme.BG, highlightthickness=0)
        frame = ttk.Frame(canvas)
        sb = ttk.Scrollbar(p, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(fill="both", expand=True)
        canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        self.set_vars: Dict[str, tk.Variable] = {}
        row = 0
        for key, label, kind in self.SETTINGS:
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3, padx=(0, 14))
            if kind == "bool":
                var = tk.BooleanVar(value=getattr(self.config, key))
                ttk.Checkbutton(frame, variable=var).grid(row=row, column=1, sticky="w")
            else:
                var = tk.StringVar(value=str(getattr(self.config, key)))
                ttk.Entry(frame, textvariable=var, width=60 if kind in ("dir", "file", "str") else 12).grid(row=row, column=1, sticky="w")
                if kind == "dir":
                    ttk.Button(frame, text="Browse...", command=lambda v=var: v.set(filedialog.askdirectory() or v.get())).grid(row=row, column=2, padx=6)
                elif kind == "file":
                    ttk.Button(frame, text="Browse...", command=lambda v=var: v.set(filedialog.askopenfilename() or v.get())).grid(row=row, column=2, padx=6)
            self.set_vars[key] = var
            row += 1
        ttk.Label(frame, text="File-system scan paths (one per line, %ENV% allowed)").grid(row=row, column=0, sticky="nw", pady=6)
        self.paths_text = theme.text_widget(frame, height=7)
        self.paths_text.grid(row=row, column=1, columnspan=2, sticky="we", pady=6)
        self.paths_text.insert("1.0", "\n".join(self.config.fs_scan_paths))
        row += 1
        btns = ttk.Frame(frame)
        btns.grid(row=row, column=0, columnspan=3, sticky="w", pady=12)
        ttk.Button(btns, text="Save settings", style="Accent.TButton", command=self._save_settings).pack(side="left")
        ttk.Button(btns, text="Restore defaults", command=self._defaults).pack(side="left", padx=8)

    def _save_settings(self) -> None:
        data = {k: v.get() for k, v in self.set_vars.items()}
        data["fs_scan_paths"] = self.paths_text.get("1.0", "end").strip()
        rejected = self.config.update(data)
        if rejected:
            messagebox.showerror(__app_name__, "Invalid values for: " + ", ".join(rejected))
            return
        try:
            path = self.config.save()
        except OSError as exc:
            messagebox.showerror(__app_name__, f"Cannot save settings: {exc}")
            return
        self.status_var.set(f"Settings saved to {path}")

    def _defaults(self) -> None:
        d = Config()
        for k, v in self.set_vars.items():
            v.set(getattr(d, k) if isinstance(v, tk.BooleanVar) else str(getattr(d, k)))
        self.paths_text.delete("1.0", "end")
        self.paths_text.insert("1.0", "\n".join(d.fs_scan_paths))

    # ------------------------------------------------------------------ about

    def _page_about(self, p) -> None:
        self.header(p, "About")
        box = ttk.Frame(p, style="Panel.TFrame", padding=22)
        box.pack(anchor="w", fill="x")
        for i, (k, v) in enumerate(ABOUT.items()):
            ttk.Label(box, text=k, style="PanelMuted.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 30), pady=3)
            ttk.Label(box, text=v, style="Panel.TLabel").grid(row=i, column=1, sticky="w")
        ttk.Button(p, text="Visit https://wezcrypt.com", command=lambda: webbrowser.open(ABOUT["Website"])).pack(anchor="w", pady=14)
        ttk.Label(p, style="Muted.TLabel", wraplength=900, justify="left", text=(
            "For use only on systems you are authorised to examine. The kit never extracts passwords, cookie values or "
            "session tokens, never enables privileges or bypasses Windows access controls, and documents every operation "
            "that touches the live system in the chain of custody.")).pack(anchor="w")


def run_gui(config: Config) -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Cannot start the GUI ({exc}). Use the command line: WezCryptUFK --help")
        return 1
    App(root, config)
    root.mainloop()
    return 0
