"""Uploads and ingest are refused with 507 when the disk is nearly full (ADR-0097 item 20).

`shutil.disk_usage` is patched: the check reads the free space under
uploads_dir() before a byte is written, and UPLOAD_MIN_FREE_MB (default 1024)
is the minimum.
"""
from __future__ import annotations

import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from api import disk_space
from api.paths import uploads_dir

_MIB = 1024 * 1024
_REPORT = "APT29 deployed SUNBURST and contacted 185.220.101.45 for command and control."


def _free(monkeypatch, free_mb: int) -> None:
    def fake_disk_usage(path):
        return SimpleNamespace(total=10 * 1024 * _MIB, used=0, free=free_mb * _MIB)

    monkeypatch.setattr(disk_space.shutil, "disk_usage", fake_disk_usage)


@pytest.fixture()
def client(temp_db_client):
    import api.main

    api.main.limiter.reset()
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        temp_db_client.spawn = spawn        # type: ignore[attr-defined]
        yield temp_db_client


def _upload(client):
    return client.post("/api/upload", files={"file": ("r.txt", io.BytesIO(_REPORT.encode()), "text/plain")})


def test_upload_is_refused_with_507_below_the_minimum_and_writes_nothing(client, monkeypatch):
    monkeypatch.setenv("UPLOAD_MIN_FREE_MB", "1024")
    _free(monkeypatch, 1023)

    resp = _upload(client)

    assert resp.status_code == 507
    assert "Insufficient Storage" in resp.json()["detail"]
    assert "UPLOAD_MIN_FREE_MB" in resp.json()["detail"]
    assert not uploads_dir().exists() or list(uploads_dir().iterdir()) == []
    assert client.spawn.call_count == 0


def test_upload_passes_at_the_minimum(client, monkeypatch):
    monkeypatch.setenv("UPLOAD_MIN_FREE_MB", "1024")
    _free(monkeypatch, 1024)

    assert _upload(client).status_code == 200


def test_the_default_minimum_is_1024_mb(client, monkeypatch):
    monkeypatch.delenv("UPLOAD_MIN_FREE_MB", raising=False)
    _free(monkeypatch, 1000)

    assert _upload(client).status_code == 507


def test_a_minimum_of_zero_turns_the_check_off(client, monkeypatch):
    monkeypatch.setenv("UPLOAD_MIN_FREE_MB", "0")
    _free(monkeypatch, 0)

    assert _upload(client).status_code == 200


def test_pasted_text_is_refused_with_507_and_nothing_is_written(client, monkeypatch):
    monkeypatch.setenv("UPLOAD_MIN_FREE_MB", "1024")
    _free(monkeypatch, 5)

    resp = client.post("/api/ingest/text", json={"text": _REPORT})

    assert resp.status_code == 507
    assert not uploads_dir().exists() or list(uploads_dir().iterdir()) == []
    assert client.spawn.call_count == 0


def test_a_missing_uploads_directory_is_checked_through_its_parent(monkeypatch, tmp_path):
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(tmp_path / "not" / "yet" / "there"))
    seen: list = []

    def fake_disk_usage(path):
        seen.append(path)
        return SimpleNamespace(total=1, used=0, free=2000 * _MIB)

    monkeypatch.setattr(disk_space.shutil, "disk_usage", fake_disk_usage)

    disk_space.refuse_if_disk_is_short()

    assert seen == [tmp_path]
