"""Issue #433: a tarball cut off or damaged in transit must be a failed sync, not an
uncaught exception (the API answered 500). The download is served from a local
file and the host lookup bypassed, as in tests/test_detection_sync.py: no network."""
from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

import pipeline.detection.sync as sync_mod
from pipeline import web_capture

_PUBLIC_IP = "93.184.216.34"
_CORRUPT = "archive is truncated or corrupt (details in the server log)"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: [_PUBLIC_IP])


def _tar_gz_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for member_name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=member_name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _big_archive() -> bytes:
    # Large enough that a cut in the middle is past the first gzip block.
    return _tar_gz_bytes({f"rules/r{i}.rules": f"rule {i} " * 2000 for i in range(200)})


def _serve(monkeypatch, archive: bytes) -> None:
    """_download writes `archive` to dest; no sidecar; validate_url accepts the URL."""
    def fake_download(url: str, dest: Path, *, timeout: int) -> int:
        dest.write_bytes(archive)
        return len(archive)

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    monkeypatch.setattr(sync_mod, "validate_url", lambda url: url)


def _corpus(tmp_path: Path) -> dict:
    return {"name": "et", "path": str(tmp_path / "et"), "tarball": "https://x/e.tar.gz"}


def _assert_nothing_left(dest: Path) -> None:
    assert not (dest.parent / f".{dest.name}.staging").exists()
    assert not list(dest.parent.glob("corpus-*.tar"))


def test_truncated_archive_is_a_failed_sync_issue_433(tmp_path: Path, monkeypatch) -> None:
    archive = _big_archive()
    _serve(monkeypatch, archive[: len(archive) // 2])

    dest = tmp_path / "et"
    (dest / "rules").mkdir(parents=True)
    (dest / "rules" / "old.rules").write_text("old")

    ok, detail = sync_mod.fetch_tarball(_corpus(tmp_path))
    assert (ok, detail) == (False, _CORRUPT)
    # The previous copy is still there, and nothing half-extracted was swapped in.
    assert sorted(p.name for p in (dest / "rules").iterdir()) == ["old.rules"]
    assert not (dest / sync_mod.MANIFEST_NAME).exists()
    _assert_nothing_left(dest)


def test_truncated_archive_names_the_reason_in_the_server_log_issue_433(
        tmp_path: Path, monkeypatch, caplog) -> None:
    archive = _big_archive()
    _serve(monkeypatch, archive[: len(archive) // 2])

    with caplog.at_level("WARNING"):
        sync_mod.fetch_tarball(_corpus(tmp_path))
    [record] = [r for r in caplog.records if "archive is truncated" in r.getMessage()]
    assert "end-of-stream" in record.getMessage()   # what gzip said, one log line


def test_tiny_truncated_archive_is_a_failed_sync_issue_433(tmp_path: Path, monkeypatch) -> None:
    # Cut inside the gzip header: whatever open() says, the sync fails cleanly.
    _serve(monkeypatch, _big_archive()[:40])

    ok, detail = sync_mod.fetch_tarball(_corpus(tmp_path))
    assert ok is False
    assert detail.endswith("(details in the server log)")
    _assert_nothing_left(tmp_path / "et")


def test_damaged_archive_is_a_failed_sync_issue_433(tmp_path: Path, monkeypatch) -> None:
    # The first deflate block overwritten with garbage (after the 10-byte gzip header):
    # zlib refuses the stream. tarfile.open() wraps that as a ReadError, so the label
    # is "not a tar archive"; the point is a failed sync with nothing left behind.
    # Damage further in is not always seen by tarfile, which stops reading at the
    # end-of-archive blocks and never reaches the gzip trailer.
    archive = bytearray(_big_archive())
    for i in range(10, 40):
        archive[i] = 0xFF
    _serve(monkeypatch, bytes(archive))

    ok, detail = sync_mod.fetch_tarball(_corpus(tmp_path))
    assert ok is False
    assert detail.endswith("(details in the server log)")
    _assert_nothing_left(tmp_path / "et")


def test_intact_archive_still_extracts_issue_433(tmp_path: Path, monkeypatch) -> None:
    # Control: the same fetch path with a whole archive is still a success.
    _serve(monkeypatch, _big_archive())

    dest = tmp_path / "et"
    ok, detail = sync_mod.fetch_tarball(_corpus(tmp_path))
    assert ok is True
    assert "200 files" in detail
    assert (dest / "rules" / "r0.rules").exists()
    assert (dest / sync_mod.MANIFEST_NAME).exists()
    _assert_nothing_left(dest)
