"""POST /api/upload — extension, marking, MIME and write-path checks.

The worker is stubbed (start_job imports run_pipeline_async from api.worker on
each call) and uploads land in tmp_path, so nothing is processed for real.
"""
from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import patch

import pytest

_REPORT = b"APT29 deployed SUNBURST and contacted 185.220.101.45 for C2.\n"
_PDF = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj << >> endobj\n"
_PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32


@pytest.fixture()
def client(temp_db_client, tmp_path, monkeypatch):
    import api.main

    api.main.limiter.reset()                  # 10/minute is shared by every test
    monkeypatch.setattr("api.routes.upload.UPLOADS_DIR", tmp_path)
    with patch("api.worker.run_pipeline_async", return_value="started") as spawn:
        temp_db_client.spawn = spawn          # type: ignore[attr-defined]
        yield temp_db_client


@pytest.fixture()
def no_libmagic(monkeypatch):
    """python-magic missing or broken: the route falls back to `filetype`."""
    def broken(*a, **kw):
        raise RuntimeError("libmagic not found")

    monkeypatch.setattr("api.routes.upload.magic.from_buffer", broken)


def _upload(client, filename: str, content: bytes, **form):
    return client.post("/api/upload", files={"file": (filename, io.BytesIO(content), "application/octet-stream")},
                       data=form)


def _job(temp_db, job_id: str) -> dict:
    with temp_db.get_conn() as conn:
        return dict(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())


def test_a_text_report_is_stored_and_handed_to_the_pipeline(client, temp_db, tmp_path):
    resp = _upload(client, "report.TXT", _REPORT, tlp_level=" amber ", pap_level="green")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "processing" and body["filename"] == "report.TXT"
    dest = tmp_path / f"{body['job_id']}.txt"
    assert dest.read_bytes() == _REPORT
    job = _job(temp_db, body["job_id"])
    assert (job["tlp_level"], job["pap_level"], job["status"]) == ("AMBER", "GREEN", "uploaded")
    client.spawn.assert_called_once_with(body["job_id"], str(dest), "report.TXT")


def test_blank_markings_mean_no_marking(client, temp_db):
    resp = _upload(client, "r.md", b"# Title\n\nSome text.\n", tlp_level="  ", pap_level="")
    assert resp.status_code == 200
    job = _job(temp_db, resp.json()["job_id"])
    assert job["tlp_level"] is None and job["pap_level"] is None


@pytest.mark.parametrize("field", ["tlp_level", "pap_level"])
def test_an_unknown_marking_is_refused(client, field):
    resp = _upload(client, "r.txt", _REPORT, **{field: "PURPLE"})
    assert resp.status_code == 400
    assert "AMBER, GREEN, RED, WHITE" in resp.json()["detail"]
    client.spawn.assert_not_called()


def test_an_unsupported_extension_is_refused(client):
    resp = _upload(client, "evil.exe", b"MZ\x90\x00")
    assert resp.status_code == 400 and "Unsupported format '.exe'" in resp.json()["detail"]


def test_a_file_whose_content_contradicts_its_extension_is_refused(client, tmp_path):
    resp = _upload(client, "report.pdf", _REPORT)
    assert resp.status_code == 415
    assert "text/plain" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []


def test_a_real_pdf_is_accepted(client):
    assert _upload(client, "report.pdf", _PDF).status_code == 200


def test_a_request_larger_than_the_limit_is_refused_before_reading(client, monkeypatch, tmp_path):
    monkeypatch.setattr("api.routes.upload._MAX_BYTES", 64)
    resp = _upload(client, "r.txt", _REPORT * 4)
    assert resp.status_code == 413 and "File too large" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []


def test_a_full_queue_answers_503(client):
    client.spawn.return_value = "rejected"
    resp = _upload(client, "r.txt", _REPORT)
    assert resp.status_code == 503 and "queue is full" in resp.json()["detail"]


def test_a_queued_job_is_reported_as_queued(client):
    client.spawn.return_value = "queued"
    assert _upload(client, "r.txt", _REPORT).json()["status"] == "queued"


def test_a_disk_error_is_a_500_and_leaves_no_file(client, monkeypatch, tmp_path):
    real_open = Path.open

    def failing_open(self, mode="r", *a, **kw):
        if "w" in mode:
            raise OSError("No space left on device")
        return real_open(self, mode, *a, **kw)

    monkeypatch.setattr(Path, "open", failing_open)
    resp = _upload(client, "r.txt", _REPORT)
    assert resp.status_code == 500 and "disk write error" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []


# ── Without libmagic: the `filetype` fallback ────────────────────────────────

def test_fallback_accepts_utf8_text(client, no_libmagic):
    assert _upload(client, "r.txt", "Rapport é\n".encode()).status_code == 200


def test_fallback_refuses_text_that_is_not_utf8(client, no_libmagic):
    resp = _upload(client, "r.txt", b"\xff\xfe\x00bad")
    assert resp.status_code == 400 and "not valid UTF-8" in resp.json()["detail"]


def test_fallback_refuses_an_unrecognisable_binary(client, no_libmagic):
    resp = _upload(client, "r.pdf", b"just some text")
    assert resp.status_code == 400 and "Could not determine file type" in resp.json()["detail"]


def test_fallback_refuses_a_binary_of_the_wrong_kind(client, no_libmagic):
    resp = _upload(client, "r.pdf", _PNG)
    assert resp.status_code == 415 and "image/png" in resp.json()["detail"]


def test_fallback_accepts_a_real_pdf(client, no_libmagic):
    assert _upload(client, "r.pdf", _PDF).status_code == 200


def test_an_empty_file_is_refused(client, no_libmagic, tmp_path):
    resp = _upload(client, "r.txt", b"")
    assert resp.status_code == 500 and "empty file" in resp.json()["detail"]
    assert list(tmp_path.iterdir()) == []
