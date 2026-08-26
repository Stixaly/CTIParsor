from __future__ import annotations

from unittest.mock import patch

import pytest

from pipeline import web_capture


@pytest.fixture()
def client(temp_db_client, tmp_path, monkeypatch):
    """
    TestClient with uploads redirected to tmp_path and the worker stubbed out.

    The rate limiter is reset per test: every request in the suite comes from
    the same "testclient" address, so the 5/minute cap on /ingest/url is shared
    across tests and the sixth one in the file would 429 on whichever test
    happened to run last.
    """
    import api.main

    api.main.limiter.reset()
    monkeypatch.setattr("api.routes.ingest.UPLOADS_DIR", tmp_path)
    with patch("api.routes.ingest.run_pipeline_async") as spawn:
        temp_db_client.spawn = spawn        # type: ignore[attr-defined]
        yield temp_db_client


_PLAIN = (
    "APT29 deployed SUNBURST against SolarWinds targets and contacted "
    "185.220.101.45 for command and control."
)
_MARKDOWN = (
    "# Volt Typhoon\n\n"
    "## Initial access\n\n"
    "- exploited a Fortinet appliance\n"
    "- used `netsh` for port forwarding\n\n"
    "See [the advisory](https://example.com/a) for details.\n"
)


def test_text_creates_job_and_spawns_pipeline(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "processing"
    assert body["job_id"]
    assert client.spawn.call_count == 1


def test_text_is_written_to_uploads(client, tmp_path):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    f = tmp_path / f"{job_id}.txt"
    assert f.exists()
    assert f.read_text(encoding="utf-8") == _PLAIN


def test_markdown_paste_gets_md_suffix(client, tmp_path):
    resp = client.post("/api/ingest/text", json={"text": _MARKDOWN})
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"].endswith(".md")
    assert (tmp_path / f"{body['job_id']}.md").exists()


def test_plain_paste_gets_txt_suffix(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN})
    assert resp.status_code == 200
    assert resp.json()["filename"].endswith(".txt")


def test_title_becomes_filename(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN, "title": "Volt Typhoon : 2023 Report"})
    assert resp.status_code == 200
    assert resp.json()["filename"] == "volt-typhoon-2023-report.txt"


def test_untitled_paste_gets_timestamp_name(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN})
    assert resp.status_code == 200
    assert resp.json()["filename"].startswith("pasted-")


def test_short_text_rejected(client):
    resp = client.post("/api/ingest/text", json={"text": "hi"})
    assert resp.status_code == 400


def test_whitespace_only_text_rejected(client):
    resp = client.post("/api/ingest/text", json={"text": "     \n\n   "})
    assert resp.status_code == 400


def test_crlf_is_normalised(client, tmp_path):
    text = _PLAIN.replace(" ", "\r\n", 1)
    resp = client.post("/api/ingest/text", json={"text": text})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    content = (tmp_path / f"{job_id}.txt").read_text(encoding="utf-8")
    assert "\r" not in content


def test_invalid_tlp_rejected(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN, "tlp_level": "PURPLE"})
    assert resp.status_code == 400


def test_tlp_is_stored_uppercased(client):
    resp = client.post("/api/ingest/text", json={"text": _PLAIN, "tlp_level": "amber"})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    from api.db import get_conn
    with get_conn() as conn:
        row = conn.execute("SELECT tlp_level FROM jobs WHERE id = ?", (job_id,)).fetchone()
    assert row is not None
    assert row[0] == "AMBER"


def test_url_rejected_when_playwright_missing(client, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", False)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/"})
    assert resp.status_code == 503


def test_url_validation_failure_is_400(client, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)

    def _raise(url):
        raise web_capture.CaptureError("Address 10.0.0.1 is not a public address")

    monkeypatch.setattr(web_capture, "validate_url", _raise)
    resp = client.post("/api/ingest/url", json={"url": "https://10.0.0.1/"})
    assert resp.status_code == 400
    assert "not a public address" in resp.json()["detail"]


def test_capture_failure_is_502(client, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def _fail(url, dest, **kwargs):
        raise web_capture.CaptureError("returned HTTP 403")

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fail)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/"})
    assert resp.status_code == 502
    assert client.spawn.call_count == 0


def test_capture_timeout_is_504(client, monkeypatch):
    import time
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)
    monkeypatch.setattr("api.routes.ingest._CAPTURE_DEADLINE_S", 0.2)

    def _slow(url, dest, **kwargs):
        time.sleep(2)

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _slow)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/"})
    assert resp.status_code == 504


def test_successful_capture_creates_job(client, tmp_path, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def _fake(url, dest, **kwargs):
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(
            pdf_path=dest,
            final_url="https://thedfirreport.com/a/",
            title="Threat Actor Toolkit",
            bytes_written=13,
            js_enabled=False,
            blocked_requests=7,
            rendered_chars=42,
            dom_text="APT29 contacted 185.220.101.45 for command and control.",
        )

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fake)
    resp = client.post("/api/ingest/url", json={"url": "https://thedfirreport.com/a/"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] == "threat-actor-toolkit.pdf"
    assert body["source_url"] == "https://thedfirreport.com/a/"
    assert body["blocked_requests"] == 7
    assert client.spawn.call_count == 1
    assert (tmp_path / f"{body['job_id']}.pdf").exists()


def test_capture_writes_both_artefacts_and_ingests_the_text(client, tmp_path, monkeypatch):
    """
    The PDF is the archive; the DOM text is what the pipeline reads.

    Ingesting the PDF instead keeps 99.6% of the characters and only 72.2% of
    the observables — a hash in a narrow table column wraps into fragments the
    text layer interleaves with its neighbours (ADR-0029).  So the path handed
    to the worker must be the .txt, while `original_filename` stays .pdf so the
    source viewer still renders the archive.
    """
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    dom = "APT29 dropped 02ce477a07681ee1671c7164c9cc847b01c2e1cd50e709f7e861eaab89c69b6f"

    def _fake(url, dest, **kwargs):
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(
            pdf_path=dest,
            final_url="https://example.com/a/",
            title="Report",
            bytes_written=13,
            js_enabled=False,
            blocked_requests=0,
            rendered_chars=len(dom),
            dom_text=dom,
        )

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fake)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/a/"})
    assert resp.status_code == 200
    body = resp.json()
    job_id = body["job_id"]

    pdf = tmp_path / f"{job_id}.pdf"
    txt = tmp_path / f"{job_id}.txt"
    assert pdf.exists(), "the archive must be kept for the source viewer"
    assert txt.exists(), "the DOM text must be written for the pipeline"
    assert txt.read_text(encoding="utf-8") == dom

    # The worker is handed the text, not the PDF.
    ingested_path = client.spawn.call_args[0][1]
    assert ingested_path.endswith(".txt"), f"pipeline was given {ingested_path}"
    # But the job is still named after the archive, so the viewer renders it.
    assert body["filename"].endswith(".pdf")
    assert body["rendered_chars"] == len(dom)


def test_enable_js_is_forwarded(client, monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    captured = {}

    def _fake(url, dest, **kwargs):
        captured.update(kwargs)
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(
            pdf_path=dest,
            final_url="https://example.com/",
            title="Test",
            bytes_written=13,
            js_enabled=True,
            blocked_requests=0,
        )

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _fake)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/", "enable_js": True})
    assert resp.status_code == 200
    assert captured.get("enable_js") is True


def test_browser_that_cannot_start_is_503_not_a_500(client, monkeypatch):
    """
    A browser that will not launch must not escape as an ASGI 500.

    Locks the real failure: the API ran as root while `playwright install` had
    written the browser under a user's HOME, so `p.chromium.launch()` raised
    inside the worker thread and the analyst got a stack trace instead of the
    one sentence that says what to run.  `_PLAYWRIGHT_AVAILABLE` cannot catch
    this — the Python package imports fine; it is the binary that is missing.
    """
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def _no_browser(url, dest, **kwargs):
        raise web_capture.CaptureUnavailable(
            "Chromium could not start on this server. It is usually not "
            "installed for the account running the API, or is missing system "
            "libraries."
        )

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _no_browser)
    resp = client.post("/api/ingest/url", json={"url": "https://example.com/"})

    assert resp.status_code == 503, f"got {resp.status_code}: {resp.text}"
    assert "could not start" in resp.json()["detail"]
    assert client.spawn.call_count == 0
