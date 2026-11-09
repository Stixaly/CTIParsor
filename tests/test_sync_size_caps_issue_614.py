"""Size caps on tarball corpora (#614): CORPUS_TARBALL_MAX_BYTES bounds the download,
CORPUS_EXTRACT_MAX_BYTES bounds what the members add up to. No network: _SAFE_OPENER
serves a fake response, and validate_url's DNS lookup is bypassed."""
from __future__ import annotations

import io
import tarfile
import urllib.error
from pathlib import Path

import pytest

import pipeline.detection.sync as sync_mod
from pipeline.detection.sync import _download, fetch_tarball


class FakeResponse:
    """Serves `body` in reads; `headers` is what the server declared."""

    def __init__(self, body: bytes | None = None, *, headers: dict | None = None,
                 endless: bool = False) -> None:
        self.headers = headers or {}
        self._body = io.BytesIO(body or b"")
        self._endless = endless
        self.reads = 0

    def read(self, n: int = -1) -> bytes:
        self.reads += 1
        if self._endless:
            if self.reads > 1000:          # the test would otherwise run forever
                raise AssertionError("download was not stopped by the cap")
            return b"\0" * n
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


class FakeOpener:
    def __init__(self, resp: FakeResponse) -> None:
        self.resp = resp

    def open(self, req, timeout=None):
        return self.resp


def _serve(monkeypatch, resp: FakeResponse) -> None:
    monkeypatch.setattr(sync_mod, "_SAFE_OPENER", FakeOpener(resp))
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_download_refuses_a_declared_size_above_the_cap_before_reading(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORPUS_TARBALL_MAX_BYTES", "1000")
    resp = FakeResponse(b"x" * 10, headers={"Content-Length": "5000"})
    _serve(monkeypatch, resp)
    dest = tmp_path / "corpus.tar"

    with pytest.raises(urllib.error.URLError, match="CORPUS_TARBALL_MAX_BYTES"):
        _download("https://x/e.tar.gz", dest, timeout=5)
    assert resp.reads == 0            # nothing read from the server
    assert not dest.exists()


def test_download_stops_a_stream_past_the_cap_and_removes_the_partial_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORPUS_TARBALL_MAX_BYTES", str(3 << 20))   # 3 MiB; chunks are 1 MiB
    resp = FakeResponse(endless=True)                              # no Content-Length at all
    _serve(monkeypatch, resp)
    dest = tmp_path / "corpus.tar"

    with pytest.raises(urllib.error.URLError, match="exceeds CORPUS_TARBALL_MAX_BYTES"):
        _download("https://x/e.tar.gz", dest, timeout=5)
    assert resp.reads <= 5            # stopped near the cap, not drained
    assert not dest.exists()


def test_download_under_the_cap_returns_the_size(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORPUS_TARBALL_MAX_BYTES", "100")
    _serve(monkeypatch, FakeResponse(b"y" * 100))
    dest = tmp_path / "corpus.tar"
    assert _download("https://x/e.tar.gz", dest, timeout=5) == 100
    assert dest.read_bytes() == b"y" * 100


def test_default_tarball_cap_is_2_gib() -> None:
    assert sync_mod._TARBALL_MAX_BYTES_DEFAULT == 2 << 30
    assert sync_mod._EXTRACT_MAX_BYTES_DEFAULT == 8 << 30


def test_fetch_tarball_reports_a_clean_failure_and_leaves_the_path_untouched(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CORPUS_TARBALL_MAX_BYTES", str(2 << 20))
    _serve(monkeypatch, FakeResponse(endless=True))
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)

    dest = tmp_path / "et"
    (dest / "rules").mkdir(parents=True)
    (dest / "rules" / "old.rules").write_text("old")

    ok, detail = fetch_tarball({"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"})
    assert ok is False
    assert detail == "download failed (details in the server log)"
    assert (dest / "rules" / "old.rules").read_text() == "old"
    # no partial download left next to the corpus
    assert list(tmp_path.glob("corpus-*.tar")) == []


def test_fetch_tarball_refuses_an_archive_that_extracts_past_the_cap(tmp_path: Path, monkeypatch) -> None:
    # A small compressed archive whose members total 64 KiB of zeros: a tar bomb in miniature.
    archive = tmp_path / "bomb.tar"
    archive.write_bytes(_tar_bytes({"rules/a.rules": b"\0" * (32 << 10),
                                    "rules/b.rules": b"\0" * (32 << 10)}))
    monkeypatch.setenv("CORPUS_EXTRACT_MAX_BYTES", str(16 << 10))

    def fake_download(url, dest, *, timeout):
        dest.write_bytes(archive.read_bytes())
        return archive.stat().st_size

    def no_extract(self, *args, **kwargs):
        raise AssertionError("extractall must not run for an archive over the cap")

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)
    monkeypatch.setattr(tarfile.TarFile, "extractall", no_extract)

    dest = tmp_path / "et"
    ok, detail = fetch_tarball({"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"})
    assert ok is False
    assert detail == "archive too large when extracted (details in the server log)"
    assert not dest.exists()
    assert not (tmp_path / ".et.staging").exists()


def test_fetch_tarball_extracts_an_archive_under_the_extract_cap(tmp_path: Path, monkeypatch) -> None:
    archive = tmp_path / "ok.tar"
    archive.write_bytes(_tar_bytes({"rules/a.rules": b"alert\n" * 100}))
    monkeypatch.setenv("CORPUS_EXTRACT_MAX_BYTES", str(1 << 20))

    def fake_download(url, dest, *, timeout):
        dest.write_bytes(archive.read_bytes())
        return archive.stat().st_size

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)

    dest = tmp_path / "et"
    ok, detail = fetch_tarball({"name": "et", "path": str(dest), "tarball": "https://x/e.tar.gz"})
    assert ok is True
    assert (dest / "rules" / "a.rules").read_bytes() == b"alert\n" * 100
