import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wezcrypt_ufk.core.config import Config  # noqa: E402
from wezcrypt_ufk.core.context import CollectionContext, SharedState  # noqa: E402
from wezcrypt_ufk.core.session import Session  # noqa: E402


@pytest.fixture
def session(tmp_path):
    return Session.create(str(tmp_path / "cases"), case_id="TEST-CASE", examiner="Unit Tester")


@pytest.fixture
def config(tmp_path):
    cfg = Config()
    cfg.fs_scan_paths = []
    cfg.verify_signatures = False
    return cfg


@pytest.fixture
def make_ctx(session, config):
    shared = SharedState()

    def factory(module="test_module"):
        return CollectionContext(session, config, module, shared)

    factory.shared = shared
    return factory


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Synthetic user profile (Arabic folder name to exercise Unicode paths)."""
    home = tmp_path / "Users" / "محلل"
    for sub in ("AppData/Local", "AppData/Roaming", "Downloads", "Desktop"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("HOME", str(home))
    return home
