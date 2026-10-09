"""Portable (USB) operation: location detection, output layout, Unicode/Arabic and long paths."""

import os

from wezcrypt_ufk.core import paths, winapi
from wezcrypt_ufk.core.config import Config
from wezcrypt_ufk.core.session import Session, list_sessions


def test_run_location_removable_usb(monkeypatch, tmp_path):
    monkeypatch.setattr(winapi, "drive_type", lambda root: "removable")
    loc = paths.detect_run_location(str(tmp_path))
    assert loc.is_removable and loc.warnings() == []
    assert paths.default_output_root(str(tmp_path)) == os.path.join(str(tmp_path), "WezCrypt_Cases")


def test_run_location_warns_when_not_usb(monkeypatch, tmp_path):
    monkeypatch.setattr(winapi, "drive_type", lambda root: "fixed")
    monkeypatch.setenv("SystemDrive", "")
    loc = paths.detect_run_location(str(tmp_path))
    assert not loc.is_removable and "not a removable USB drive" in loc.warnings()[0]


def test_application_dir_when_frozen(monkeypatch, tmp_path):
    exe = tmp_path / "E" / "WezCryptUFK" / "WezCryptUFK.exe"
    monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths.sys, "executable", str(exe))
    assert paths.application_dir() == str(exe.parent)


def test_session_folder_per_collection(tmp_path):
    root = tmp_path / "USB" / "WezCrypt_Cases"
    s1 = Session.create(str(root), case_id="قضية-001", examiner="محقق")
    s2 = Session.create(str(root), case_id="قضية-001")
    assert s1.session_dir != s2.session_dir and s1.session_id != s2.session_id
    assert "قضية-001" in os.path.basename(s1.session_dir)
    for sub in ("evidence", "parsed", "analysis", "reports", "logs"):
        assert os.path.isdir(os.path.join(s1.session_dir, sub))
    assert Session.load(s1.session_dir).examiner == "محقق"
    assert len(list_sessions(str(root))) == 2


def test_safe_name_and_unique_path(tmp_path):
    assert paths.safe_name('a<b>:c"d/e\\f|g?h*') == "a_b_c_d_e_f_g_h_"
    assert paths.safe_name("CON") == "_CON" and paths.safe_name("lpt1") == "_lpt1"
    assert paths.safe_name("ملف عربي.txt") == "ملف عربي.txt"
    f = tmp_path / "x.txt"
    f.write_text("1")
    assert paths.unique_path(str(f)).endswith("x_1.txt")


def test_long_path_helpers():
    assert winapi.strip_long_prefix("\\\\?\\C:\\a") == "C:\\a"
    assert winapi.strip_long_prefix("\\\\?\\UNC\\srv\\s") == "\\\\srv\\s"
    if not winapi.IS_WINDOWS:
        assert winapi.long_path("/tmp/x") == "/tmp/x"


def test_acquire_deep_long_and_arabic_path(make_ctx, tmp_path):
    deep = tmp_path
    for i in range(12):
        deep = deep / f"مجلد_طويل_جدا_للاختبار_{i:02d}"
    deep.mkdir(parents=True)
    src = deep / "دليل.txt"
    src.write_text("بيانات اختبار", encoding="utf-8")
    assert len(str(src)) > 300
    ctx = make_ctx("long_paths")
    item = ctx.acquire(str(src))
    assert item is not None and item.size == len("بيانات اختبار".encode("utf-8"))
    assert item.evidence_path.endswith("دليل.txt")


def test_config_roundtrip_and_validation(tmp_path):
    cfg = Config()
    rejected = cfg.update({"max_workers": "99", "verify_signatures": "yes", "fs_scan_paths": "C:\\a\nD:\\b", "fs_max_files": -5})
    assert cfg.max_workers == 16 and cfg.fs_scan_paths == ["C:\\a", "D:\\b"]
    assert set(rejected) == {"verify_signatures", "fs_max_files"}
    path = cfg.save(str(tmp_path / "cfg.json"))
    assert Config.load(path).fs_scan_paths == ["C:\\a", "D:\\b"]
    (tmp_path / "broken.json").write_text("{not json")
    assert Config.load(str(tmp_path / "broken.json")).max_workers == 4
