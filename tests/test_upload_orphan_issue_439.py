"""A report that never reaches a job leaves no file in uploads/ (issue #439).

Before the fix, an exception from `start_job` other than the 503 queue refusal
left the stored file behind: the job never existed, so nothing would ever
delete it.
"""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from api import paths
from pipeline import web_capture

_REPORT = b"APT29 deployed SUNBURST and contacted 185.220.101.45 for C2.\n"
_PAGE = "APT29 contacted 185.220.101.45 for command and control, then exfiltrated data."


@pytest.fixture(autouse=True)
def _capture_direct_allowed(monkeypatch):
    """The URL capture is refused without its egress proxy; these tests run it without one."""
    monkeypatch.setenv("CTIPARSOR_CAPTURE_ALLOW_DIRECT", "1")


@pytest.fixture()
def client(temp_db_client):
    import api.main

    api.main.limiter.reset()
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        temp_db_client.spawn = spawn          # type: ignore[attr-defined]
        yield temp_db_client


def _files() -> list:
    folder = paths.uploads_dir()
    return sorted(p.name for p in folder.rglob("*") if p.is_file()) if folder.exists() else []


def _upload(client):
    return client.post("/api/upload", files={"file": ("r.txt", io.BytesIO(_REPORT), "application/octet-stream")})


def test_a_start_job_failure_leaves_no_uploaded_file_issue_439(client, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("start_job exploded")

    monkeypatch.setattr("api.routes.upload.start_job", broken)
    with pytest.raises(RuntimeError, match="start_job exploded"):
        _upload(client)
    assert _files() == []


def test_control_a_started_upload_keeps_its_file_issue_439(client):
    resp = _upload(client)
    assert resp.status_code == 200
    assert _files() == [f"{resp.json()['job_id']}.txt"]


def test_a_queue_refusal_still_leaves_no_file_issue_439(client):
    client.spawn.return_value = "rejected"
    assert _upload(client).status_code == 503
    assert _files() == []


def test_a_pasted_text_whose_start_job_fails_leaves_no_file_issue_439(client, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("start_job exploded")

    monkeypatch.setattr("api.routes.ingest.start_job", broken)
    with pytest.raises(RuntimeError, match="start_job exploded"):
        client.post("/api/ingest/text", json={"text": "APT29 contacted 185.220.101.45 for command and control."})
    assert _files() == []


def test_a_capture_whose_start_job_fails_leaves_no_archive_text_or_meta_issue_439(client, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def _fake(url, dest, **kwargs):
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(
            pdf_path=dest,
            final_url="https://example.com/a/",
            title="Report",
            bytes_written=13,
            js_enabled=False,
            blocked_requests=0,
            rendered_chars=len(_PAGE),
            dom_text=_PAGE,
            publication=[{"value": "2026-01-01", "source": "publication_meta", "kind": "published", "detail": "date"}],
        )

    def broken(*args, **kwargs):
        raise RuntimeError("start_job exploded")

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fake)
    monkeypatch.setattr("api.routes.ingest.start_job", broken)
    with pytest.raises(RuntimeError, match="start_job exploded"):
        client.post("/api/ingest/url", json={"url": "https://example.com/a/"})
    assert _files() == []
