# tests/test_ingest_capture_timeout_issue_480.py
"""
A capture that outlives its deadline does not leave a staging PDF behind (#480).

asyncio cannot stop the thread a capture runs in, so the thread keeps going
after the 504 and writes to `<uuid>.pdf.part`.  The route has already unlinked
that name by then: the thread's own cleanup has to remove what it writes last.
"""
from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from pipeline import web_capture


@pytest.fixture(autouse=True)
def _capture_direct_allowed(monkeypatch):
    """The URL capture is refused without its egress proxy; these tests run it without one."""
    monkeypatch.setenv("CTIPARSOR_CAPTURE_ALLOW_DIRECT", "1")


@pytest.fixture()
def client(temp_db_client, tmp_path, monkeypatch):
    """TestClient with uploads redirected to tmp_path and the worker stubbed out."""
    import api.main

    api.main.limiter.reset()
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(tmp_path))
    with patch("api.worker.run_pipeline_async") as spawn:
        temp_db_client.spawn = spawn        # type: ignore[attr-defined]
        yield temp_db_client


def test_a_capture_that_finishes_after_the_deadline_leaves_no_part_file(client, tmp_path, monkeypatch):
    """The late render writes its staging PDF after the 504; that file must be removed (#480)."""
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)
    monkeypatch.setattr("api.routes.ingest._CAPTURE_DEADLINE_S", 0.2)

    release = threading.Event()
    written = threading.Event()
    seen: dict[str, object] = {}

    def _late(url, dest, **kwargs):
        seen["dest"] = dest
        release.wait(10)
        dest.write_bytes(b"%PDF-1.4 late")
        written.set()

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _late)

    resp = client.post("/api/ingest/url", json={"url": "https://example.com/a/"})
    assert resp.status_code == 504

    release.set()
    assert written.wait(5), "the late capture never wrote its file"
    deadline = time.monotonic() + 5
    while seen["dest"].exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    leftovers = sorted(p.name for p in tmp_path.rglob("*.pdf*") if p.is_file())
    assert not seen["dest"].exists(), f"staging PDF left behind after a 504 (#480): {leftovers}"
    assert leftovers == [], f"PDF files left in uploads after a 504 (#480): {leftovers}"
