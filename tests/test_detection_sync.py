"""Tests for pipeline/detection/sync.py — git dispatch and the tarball fetch
(ADR-0015 §5). No network: _download and _fetch_text are always monkeypatched."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.error
from pathlib import Path

import pipeline.detection.sync as sync_mod
from pipeline.detection.sync import (
    MANIFEST_NAME,
    _parse_md5,
    fetch_tarball,
    git_command,
    sync_corpus,
)


def _make_tar(tmp_path: Path, files: dict[str, str], *, name: str = "src.tar.gz") -> Path:
    """Build a .tar.gz under tmp_path from {member_name: text}; returns its path."""
    archive = tmp_path / name
    with tarfile.open(archive, "w:gz") as tar:
        for member_name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=member_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return archive


def _md5(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _patch_network(monkeypatch, archive: Path, sidecar: str | None) -> None:
    """_download copies `archive` to dest and returns its size; _fetch_text returns `sidecar`.

    Also bypasses `validate_url`'s live DNS resolution: these tests exercise
    tarball-extraction mechanics against fake hostnames like "x", which the
    SSRF guard (correctly) cannot resolve. The guard itself has its own tests
    below."""
    def fake_download(url: str, dest: Path, *, timeout: int) -> int:
        dest.write_bytes(archive.read_bytes())
        return archive.stat().st_size

    def fake_fetch_text(url: str, *, timeout: int) -> str | None:
        return sidecar

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", fake_fetch_text)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)


def test_git_command_clones_when_path_missing_and_pulls_when_present(tmp_path: Path) -> None:
    path = tmp_path / "corpus"
    corpus = {"name": "test", "path": str(path), "git": "https://example.com/repo.git"}
    cmd = git_command(corpus)
    assert cmd is not None
    assert cmd[:5] == ["git", "clone", "--depth", "1", "https://example.com/repo.git"]
    assert cmd[-1] == str(path)

    path.mkdir()
    cmd = git_command(corpus)
    assert cmd == ["git", "-C", str(path), "pull", "--ff-only"]

    corpus_no_git = {"name": "test", "path": str(path)}
    assert git_command(corpus_no_git) is None


def test_parse_md5_accepts_bare_hash_and_hash_filename_lines() -> None:
    assert _parse_md5("D50AE89D1A9296A0690D6622B9D91CBE") == "d50ae89d1a9296a0690d6622b9d91cbe"
    assert _parse_md5(
        "d50ae89d1a9296a0690d6622b9d91cbe  emerging.rules.tar.gz\n"
    ) == "d50ae89d1a9296a0690d6622b9d91cbe"
    assert _parse_md5("<html>404") is None
    assert _parse_md5(None) is None
    assert _parse_md5("") is None


def test_fetch_tarball_extracts_under_path_and_writes_manifest(tmp_path: Path, monkeypatch) -> None:
    archive = _make_tar(tmp_path, {"rules/a.rules": "alert ...", "rules/LICENSE": "BSD"})
    sidecar = _md5(archive)
    _patch_network(monkeypatch, archive, sidecar)

    dest = tmp_path / "et"
    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is True
    assert "2 files" in detail
    assert "verified against sidecar md5" in detail

    assert (dest / "rules" / "a.rules").read_text() == "alert ..."
    manifest = json.loads((dest / MANIFEST_NAME).read_text())
    assert manifest["url"] == "https://x/e.tar.gz"
    assert manifest["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert manifest["md5"] == sidecar
    assert manifest["sidecar_md5"] == sidecar
    assert manifest["size"] == archive.stat().st_size
    assert manifest["files"] == 2
    assert manifest["fetched_at"]


def test_fetch_tarball_without_sidecar_proceeds_and_says_so(tmp_path: Path, monkeypatch) -> None:
    archive = _make_tar(tmp_path, {"rules/a.rules": "alert ..."})
    _patch_network(monkeypatch, archive, None)

    dest = tmp_path / "et"
    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is True
    assert "no checksum published" in detail

    manifest = json.loads((dest / MANIFEST_NAME).read_text())
    assert manifest["sidecar_md5"] is None


def test_fetch_tarball_checksum_mismatch_keeps_previous_copy(tmp_path: Path, monkeypatch) -> None:
    archive = _make_tar(tmp_path, {"rules/a.rules": "alert ..."})
    _patch_network(monkeypatch, archive, "0" * 32)

    dest = tmp_path / "et"
    (dest / "rules").mkdir(parents=True)
    (dest / "rules" / "old.rules").write_text("old")

    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert "checksum mismatch" in detail

    assert (dest / "rules" / "old.rules").exists()
    assert not (dest.parent / f".{dest.name}.staging").exists()
    assert not list(dest.parent.glob("corpus-*.tar"))


def test_fetch_tarball_replaces_previous_copy(tmp_path: Path, monkeypatch) -> None:
    archive = _make_tar(tmp_path, {"rules/new.rules": "new"})
    sidecar = _md5(archive)
    _patch_network(monkeypatch, archive, sidecar)

    dest = tmp_path / "et"
    (dest / "rules").mkdir(parents=True)
    (dest / "rules" / "old.rules").write_text("old")

    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, _ = fetch_tarball(corpus)
    assert ok is True

    assert not (dest / "rules" / "old.rules").exists()
    assert (dest / "rules" / "new.rules").exists()


def test_fetch_tarball_skips_unsafe_members(tmp_path: Path, monkeypatch) -> None:
    archive = _make_tar(tmp_path, {
        "rules/ok.rules": "ok",
        "../evil.rules": "evil",
        "/abs.rules": "abs",
    })
    sidecar = _md5(archive)
    _patch_network(monkeypatch, archive, sidecar)

    dest = tmp_path / "et"
    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is True
    assert (dest / "rules" / "ok.rules").exists()
    assert not (dest.parent / "evil.rules").exists()
    assert "2 unsafe members skipped" in detail


def test_fetch_tarball_download_failure_leaves_path_untouched(tmp_path: Path, monkeypatch) -> None:
    def fake_download(url: str, dest: Path, *, timeout: int) -> int:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)

    dest = tmp_path / "et"
    (dest / "rules").mkdir(parents=True)
    (dest / "rules" / "old.rules").write_text("old")

    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert "download failed" in detail
    assert (dest / "rules" / "old.rules").exists()
    assert not (dest.parent / f".{dest.name}.staging").exists()
    assert not list(dest.parent.glob("corpus-*.tar"))


def test_fetch_tarball_rejects_non_archive(tmp_path: Path, monkeypatch) -> None:
    def fake_download(url: str, dest: Path, *, timeout: int) -> int:
        dest.write_bytes(b"not a tar")
        return 9

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)

    dest = tmp_path / "et"
    corpus = {"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert "not a tar archive" in detail


def test_fetch_tarball_requires_url_and_path() -> None:
    ok, detail = fetch_tarball({"name": "x", "path": "p"})
    assert ok is False
    assert detail == "no tarball URL"

    ok, detail = fetch_tarball({"name": "x", "tarball": "https://x/e.tar.gz"})
    assert ok is False
    assert detail == "no path configured"


def test_fetch_tarball_rejects_unsafe_scheme(tmp_path: Path) -> None:
    """A file:// (or ftp://, etc.) tarball URL must be rejected before any
    network activity -- urllib.request.urlopen would otherwise happily read a
    local file or use another non-http(s) transport (see ADR security fix
    'contain corpus path/subdir and reject git argument injection', which
    covers git remotes and paths but never the tarball fetch's own scheme)."""
    corpus = {"name": "x", "path": str(tmp_path / "et"), "tarball": "file:///etc/passwd"}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert "invalid tarball URL" in detail
    assert not (tmp_path / "et").exists()


def test_fetch_tarball_rejects_blocked_host(tmp_path: Path) -> None:
    """A tarball URL pointed at localhost (or another blocked/internal host)
    must be rejected -- this is the same SSRF surface pipeline/web_capture.py
    guards for URL captures, reused here since fetch_tarball is an equally
    server-side fetch of an operator-influenced URL."""
    corpus = {"name": "x", "path": str(tmp_path / "et"), "tarball": "http://localhost/e.tar.gz"}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert "invalid tarball URL" in detail
    assert not (tmp_path / "et").exists()


def test_sync_corpus_dispatches_tarball_git_and_manual(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sync_mod, "fetch_tarball", lambda corpus, timeout=900: (True, "tar"))
    assert sync_corpus({"tarball": "u", "path": "p"}) == (True, "tar")

    class FakeProc:
        returncode = 0
        stdout = "pulled"
        stderr = ""

    monkeypatch.setattr(sync_mod.subprocess, "run", lambda *a, **kw: FakeProc())
    assert sync_corpus({"git": "u", "path": str(tmp_path)}) == (True, "pulled")

    ok, detail = sync_corpus({"path": "p"})
    assert ok is False
    assert "managed manually" in detail
