"""Visual identity: dark navy/charcoal surfaces, copper accents, flat minimal ttk styling."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

BG = "#10151f"
PANEL = "#171e2b"
PANEL2 = "#1d2636"
LINE = "#2a3447"
TEXT = "#e4e8ef"
MUTED = "#9aa5b8"
COPPER = "#c8834a"
COPPER_HI = "#e0a271"
COPPER_DARK = "#8f5a30"
OK = "#5cb85c"
WARN = "#d6b043"
ERR = "#d9534f"
SEVERITY = {"critical": "#d9534f", "high": "#e07b39", "medium": "#d6b043", "low": "#5fa8d3", "info": "#7d8799"}


def base_family() -> str:
    return "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"


def mono_family() -> str:
    return "Consolas" if sys.platform == "win32" else "DejaVu Sans Mono"


def apply(root: tk.Tk) -> None:
    family = base_family()
    for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
        try:
            tkfont.nametofont(name).configure(family=family, size=10)
        except tk.TclError:
            pass
    root.configure(bg=BG)
    root.option_add("*Font", (family, 10))
    root.option_add("*TCombobox*Listbox.background", PANEL2)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", COPPER_DARK)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL2, bordercolor=LINE,
                    lightcolor=PANEL, darkcolor=PANEL, troughcolor=PANEL2, focuscolor=COPPER, font=(family, 10))
    style.configure("TFrame", background=BG)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("Side.TFrame", background=PANEL)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
    style.configure("Muted.TLabel", background=BG, foreground=MUTED)
    style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED)
    style.configure("Title.TLabel", background=BG, foreground=TEXT, font=(family, 16, "bold"))
    style.configure("H2.TLabel", background=BG, foreground=COPPER_HI, font=(family, 11, "bold"))
    style.configure("CardValue.TLabel", background=PANEL, foreground=TEXT, font=(family, 18, "bold"))
    style.configure("CardKey.TLabel", background=PANEL, foreground=MUTED, font=(family, 9))
    style.configure("Brand.TLabel", background=PANEL, foreground=COPPER, font=(family, 13, "bold"))
    style.configure("TButton", background=PANEL2, foreground=TEXT, bordercolor=LINE, padding=(12, 6), relief="flat")
    style.map("TButton", background=[("active", LINE), ("disabled", PANEL)], foreground=[("disabled", MUTED)])
    style.configure("Accent.TButton", background=COPPER, foreground="#10151f", bordercolor=COPPER, font=(family, 10, "bold"))
    style.map("Accent.TButton", background=[("active", COPPER_HI), ("disabled", COPPER_DARK)])
    style.configure("Nav.TButton", background=PANEL, foreground=MUTED, anchor="w", padding=(18, 9), bordercolor=PANEL)
    style.map("Nav.TButton", background=[("active", PANEL2)], foreground=[("active", TEXT)])
    style.configure("NavActive.TButton", background=PANEL2, foreground=COPPER_HI, anchor="w", padding=(18, 9),
                    bordercolor=PANEL2, font=(family, 10, "bold"))
    style.configure("TCheckbutton", background=BG, foreground=TEXT, indicatorbackground=PANEL2, indicatorforeground=COPPER)
    style.map("TCheckbutton", background=[("active", BG)], indicatorbackground=[("selected", COPPER)])
    style.configure("Panel.TCheckbutton", background=PANEL, foreground=TEXT, indicatorbackground=PANEL2)
    style.map("Panel.TCheckbutton", background=[("active", PANEL)], indicatorbackground=[("selected", COPPER)])
    style.configure("TEntry", fieldbackground=PANEL2, foreground=TEXT, insertcolor=TEXT, bordercolor=LINE, padding=5)
    style.configure("TCombobox", fieldbackground=PANEL2, foreground=TEXT, background=PANEL2, arrowcolor=COPPER)
    style.map("TCombobox", fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", TEXT)])
    style.configure("TSpinbox", fieldbackground=PANEL2, foreground=TEXT, arrowcolor=COPPER)
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=24, bordercolor=LINE)
    style.map("Treeview", background=[("selected", COPPER_DARK)], foreground=[("selected", TEXT)])
    style.configure("Treeview.Heading", background=PANEL2, foreground=COPPER_HI, relief="flat", font=(family, 9, "bold"))
    style.map("Treeview.Heading", background=[("active", LINE)])
    style.configure("Horizontal.TProgressbar", background=COPPER, troughcolor=PANEL2, bordercolor=LINE, thickness=10)
    style.configure("TLabelframe", background=BG, bordercolor=LINE)
    style.configure("TLabelframe.Label", background=BG, foreground=COPPER_HI, font=(family, 10, "bold"))
    style.configure("TNotebook", background=BG, bordercolor=LINE)
    style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(12, 5))
    style.map("TNotebook.Tab", background=[("selected", PANEL2)], foreground=[("selected", COPPER_HI)])
    style.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG, arrowcolor=MUTED, bordercolor=BG)
    style.configure("Horizontal.TScrollbar", background=PANEL2, troughcolor=BG, arrowcolor=MUTED, bordercolor=BG)


def text_widget(parent, height=10, mono=True) -> tk.Text:
    return tk.Text(parent, height=height, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat",
                   highlightthickness=1, highlightbackground=LINE, highlightcolor=COPPER,
                   font=(mono_family() if mono else base_family(), 9), wrap="word")
