"""SHA-256 hashing, acquisition verification, manifest and chain of custody."""

import hashlib
import json
import os

import pytest

from wezcrypt_ufk.core.acquire import AcquisitionError, IntegrityError, classify_os_error, copy_with_hash
from wezcrypt_ufk.core.custody import CustodyLog
from wezcrypt_ufk.core.hashing import sha256_bytes, sha256_file, try_sha256_file
from wezcrypt_ufk.core.integrity import build_manifest, verify_manifest


def test_sha256_known_vectors(tmp_path):
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    p = tmp_path / "abc.bin"
    p.write_bytes(b"abc")
    assert sha256_file(str(p)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_large_file_streaming(tmp_path):
    p = tmp_path / "big.bin"
    block = os.urandom(1024 * 1024)
    with open(p, "wb") as fh:
        for _ in range(5):
            fh.write(block)
    assert sha256_file(str(p)) == hashlib.sha256(block * 5).hexdigest()
    assert try_sha256_file(str(p), max_size=1024) is None
    assert try_sha256_file(str(tmp_path / "missing")) is None


def test_copy_with_hash_preserves_source_and_never_overwrites(tmp_path):
    src = tmp_path / "source.dat"
    src.write_bytes(b"evidence-bytes" * 1000)
    before = (src.stat().st_mtime, sha256_file(str(src)))
    dest = tmp_path / "out" / "source.dat"
    p1, size, digest, method = copy_with_hash(str(src), str(dest))
    p2, _, digest2, _ = copy_with_hash(str(src), str(dest))
    assert p1 != p2 and os.path.basename(p2) == "source_1.dat"
    assert digest == digest2 == before[1] and size == 14000 and method == "read_only_copy"
    assert (src.stat().st_mtime, sha256_file(str(src))) == before


def test_copy_detects_post_copy_corruption(tmp_path, monkeypatch):
    src = tmp_path / "s.bin"
    src.write_bytes(b"abc")
    import wezcrypt_ufk.core.acquire as acq

    monkeypatch.setattr(acq, "sha256_file", lambda p: "0" * 64)
    with pytest.raises(IntegrityError):
        copy_with_hash(str(src), str(tmp_path / "d.bin"))


def test_locked_file_is_reported_not_crashing(tmp_path):
    class SharingViolation(OSError):
        winerror = 32

    exc = SharingViolation(13, "The process cannot access the file because it is being used by another process")
    assert classify_os_error(exc) == "locked"
    assert classify_os_error(PermissionError(13, "denied")) == "access_denied"
    assert classify_os_error(FileNotFoundError(2, "nope")) == "not_found"

    def opener(path):
        raise AcquisitionError("sharing violation", "locked", path)

    with pytest.raises(AcquisitionError) as info:
        copy_with_hash(str(tmp_path / "x"), str(tmp_path / "y"), opener=opener)
    assert info.value.kind == "locked"
    assert not (tmp_path / "y").exists()


def test_partial_copy_removed_on_cancel(tmp_path):
    src = tmp_path / "s.bin"
    src.write_bytes(os.urandom(3 * 1024 * 1024))

    calls = {"n": 0}

    def cancel():
        calls["n"] += 1
        if calls["n"] > 1:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        copy_with_hash(str(src), str(tmp_path / "d.bin"), cancel)
    assert not (tmp_path / "d.bin").exists()


def test_manifest_verification_detects_tampering(session):
    ev = session.path("evidence", "mod")
    os.makedirs(ev)
    for i in range(3):
        with open(os.path.join(ev, f"f{i}.txt"), "w") as fh:
            fh.write(f"file {i}")
    CustodyLog(session.path("chain_of_custody.jsonl")).append("created")
    manifest = build_manifest(session.session_dir, session.session_id, "1.0.0")
    assert manifest["file_count"] == 3
    assert verify_manifest(session.session_dir).passed

    with open(os.path.join(ev, "f0.txt"), "a") as fh:
        fh.write("tampered")
    os.remove(os.path.join(ev, "f1.txt"))
    with open(os.path.join(ev, "new.txt"), "w") as fh:
        fh.write("planted")
    res = verify_manifest(session.session_dir)
    assert not res.passed
    assert [m["path"] for m in res.modified] == ["evidence/mod/f0.txt"]
    assert res.missing == ["evidence/mod/f1.txt"]
    assert res.unexpected == ["evidence/mod/new.txt"]


def test_manifest_file_itself_protected(session):
    CustodyLog(session.path("chain_of_custody.jsonl")).append("created")
    build_manifest(session.session_dir, session.session_id, "1.0.0")
    with open(session.path("manifest.json"), "r+", encoding="utf-8") as fh:
        data = json.load(fh)
        data["tool_version"] = "forged"
        fh.seek(0)
        json.dump(data, fh)
        fh.truncate()
    res = verify_manifest(session.session_dir)
    assert not res.manifest_ok and not res.passed


def test_custody_chain_tamper_evident(tmp_path):
    log = CustodyLog(str(tmp_path / "coc.jsonl"))
    for a in ("created", "collected", "verified"):
        log.append(a, {"x": a}, examiner="E")
    assert log.verify() == []
    lines = (tmp_path / "coc.jsonl").read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["details"]["x"] = "rewritten"
    lines[1] = json.dumps(entry)
    (tmp_path / "coc.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems = CustodyLog(str(tmp_path / "coc.jsonl")).verify()
    assert any("entry 2" in p for p in problems)


def test_custody_entries_utc_and_chained(tmp_path):
    log = CustodyLog(str(tmp_path / "c.jsonl"))
    e1 = log.append("a")
    e2 = log.append("b")
    assert e1["utc"].endswith("Z") and e2["prev_hash"] == e1["entry_hash"] and e2["seq"] == 2
