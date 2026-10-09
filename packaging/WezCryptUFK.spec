# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec - builds a portable ONEDIR distribution with two launchers sharing one runtime:
#   WezCryptUFK.exe      windowed GUI (double-click)
#   WezCryptUFK-cli.exe  console CLI (scripting / remote shells)
# ONEDIR is deliberate: a ONEFILE build unpacks itself into %TEMP% on the examined host, writing to its disk.
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
ICON = os.path.join(ROOT, "wezcrypt_ufk", "assets", "wezcrypt.ico")

hidden = (collect_submodules("wezcrypt_ufk") + collect_submodules("reportlab.pdfbase")
          + collect_submodules("reportlab.graphics") + collect_submodules("bidi") + ["arabic_reshaper"])
datas = [(ICON, "assets")] + collect_data_files("reportlab") + collect_data_files("arabic_reshaper")

a = Analysis(
    [os.path.join(ROOT, "WezCryptUFK.py")],
    pathex=[ROOT],
    hiddenimports=hidden,
    datas=datas,
    excludes=["pytest", "_pytest", "IPython", "matplotlib", "numpy", "PIL.ImageQt"],
    noarchive=False,
)
pyz = PYZ(a.pure)

gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="WezCryptUFK", console=False, icon=ICON,
          version=os.path.join(ROOT, "packaging", "version_info.txt"), upx=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="WezCryptUFK-cli", console=True, icon=ICON,
          version=os.path.join(ROOT, "packaging", "version_info.txt"), upx=False)

coll = COLLECT(gui, cli, a.binaries, a.datas, strip=False, upx=False, name="WezCryptUFK")
