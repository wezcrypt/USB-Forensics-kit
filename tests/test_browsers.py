"""Browser database parsing on synthetic profiles; cookie values must never be collected."""

import json
import os

from builders import build_chrome_profile, build_firefox_profile
from wezcrypt_ufk.analysis.data import SessionData
from wezcrypt_ufk.collectors.browsers import ChromeCollector, FirefoxCollector
from wezcrypt_ufk.parsers import browsers as bp


def test_chromium_parsers(tmp_path):
    prof = tmp_path / "Default"
    build_chrome_profile(str(prof))
    hist = list(bp.chromium_history(str(prof / "History"), 100))
    assert [h["url"] for h in hist][0] == "https://ar.example.org/صفحة"  # newest first
    assert hist[-1]["transition"] == "typed" and hist[-1]["visit_time"] == "2024-01-01T00:01:40.000000Z"
    dl = list(bp.chromium_downloads(str(prof / "History"), 100))[0]
    assert dl["source_url"] == "https://downloads.example.net/tool.exe" and dl["danger_type"] == "dangerous_file"
    assert dl["state"] == "complete" and dl["target_path"].endswith("tool.exe")
    cookies = list(bp.chromium_cookies_metadata(str(prof / "Cookies"), 100))
    assert cookies[0]["host"] == ".example.org" and cookies[0]["http_only"]
    assert "value" not in cookies[0] and "SECRET" not in json.dumps(cookies)
    marks = bp.chromium_bookmarks(str(prof / "Bookmarks"))
    assert {m["name"] for m in marks} == {"Example", "عربي"}
    assert any(m["folder"].endswith("مجلد") for m in marks)
    exts = bp.chromium_extensions(str(prof), json.load(open(prof / "Preferences")))
    assert exts[0]["name"] == "Test Extension" and exts[0]["permissions"] == ["tabs", "storage"]
    entry = bp.chromium_simple_cache_entry(str(prof / "Cache" / "Cache_Data" / "0123456789abcdef_0"))
    assert entry["key"] == "https://example.org/logo.png"


def test_firefox_parsers(tmp_path):
    prof = build_firefox_profile(str(tmp_path / "Roaming"))
    assert bp.firefox_profiles(str(tmp_path / "Roaming")) == [prof]
    hist = list(bp.firefox_history(os.path.join(prof, "places.sqlite"), 10))
    assert hist[0]["transition"] == "download" and hist[1]["visit_time"] == "2024-01-01T00:00:00.000000Z"
    dl = list(bp.firefox_downloads(os.path.join(prof, "places.sqlite"), 10))[0]
    assert dl["target_path"] == "C:\\Users\\analyst\\Downloads\\setup.msi" and dl["state"] == "complete"
    assert dl["total_bytes"] == 2048
    marks = bp.firefox_bookmarks(os.path.join(prof, "places.sqlite"))
    assert marks[0]["name"] == "Example bookmark" and marks[0]["folder"] == "toolbar"
    cookies = list(bp.firefox_cookies_metadata(os.path.join(prof, "cookies.sqlite"), 10))
    assert cookies[0]["expires"] == "2030-01-01T00:00:00.000000Z" and "SECRET" not in json.dumps(cookies)
    exts = bp.firefox_extensions(os.path.join(prof, "extensions.json"))
    assert [e["id"] for e in exts] == ["addon@example.com"]


def test_browser_collectors_end_to_end(fake_home, make_ctx, session):
    build_chrome_profile(str(fake_home / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"))
    build_firefox_profile(str(fake_home / "AppData" / "Roaming"))
    for cls in (ChromeCollector, FirefoxCollector):
        ctx = make_ctx(cls.name)
        cls().run(ctx)
        ctx.close()
    data = SessionData(session.session_dir)
    assert len(data.all("browser_chrome", "history")) == 3
    assert data.all("browser_chrome", "downloads")[0]["profile"] == "Default"
    assert len(data.all("browser_firefox", "history")) == 2
    # Evidence: History preserved; Cookies DB deliberately NOT preserved (encrypted values), only metadata parsed.
    ev = []
    for root, _, files in os.walk(session.path("evidence")):
        ev.extend(files)
    assert "History" in ev and "places.sqlite" in ev and "Cookies" not in ev and "cookies.sqlite" not in ev
    for root, _, files in os.walk(session.session_dir):
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                assert b"SECRET-VALUE-MUST-NOT-LEAK" not in fh.read(), f
    assert not os.path.exists(session.path("analysis", "tmp", "browser_chrome"))
    tl = open(os.path.join(session.path("parsed", "browser_chrome"), "_timeline.jsonl"), encoding="utf-8").read()
    assert "file_download" in tl and "web_visit" in tl
