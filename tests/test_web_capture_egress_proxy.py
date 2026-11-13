# tests/test_web_capture_egress_proxy.py
"""
A URL capture is refused without its egress proxy (#801).

The proxy is what closes DNS rebinding for the requests a capture makes, so a
capture with no CTIPARSOR_CAPTURE_PROXY is refused before anything else: no
browser starts, no name is resolved, no request is made.  The one exception is
CTIPARSOR_CAPTURE_ALLOW_DIRECT=1, for development and tests, which logs a warning
on every capture.  Every test here makes its own environment explicit.
"""
from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from pipeline import web_capture
from pipeline.web_capture import CaptureUnavailable, capture_url_to_pdf

PROXY = "CTIPARSOR_CAPTURE_PROXY"
ALLOW_DIRECT = "CTIPARSOR_CAPTURE_ALLOW_DIRECT"


def _forbidden(*args, **kwargs):
    raise AssertionError("the capture reached a browser, a DNS lookup or a request it must not make")


@pytest.fixture
def no_egress_anything(monkeypatch):
    """Fail the test if the capture starts a browser, resolves a name or validates a URL."""
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "sync_playwright", _forbidden, raising=False)
    monkeypatch.setattr(web_capture, "validate_url", _forbidden)
    monkeypatch.setattr(web_capture, "_resolve_all", _forbidden)
    monkeypatch.delenv(PROXY, raising=False)
    monkeypatch.delenv(ALLOW_DIRECT, raising=False)


def test_a_capture_without_the_proxy_is_refused_before_any_browser_or_lookup(
    no_egress_anything, tmp_path
):
    """Refused with no browser, no DNS lookup and no request; the message names the variable and its docs (#801)."""
    with pytest.raises(CaptureUnavailable) as info:
        capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")

    message = str(info.value)
    assert PROXY in message
    assert "docs/configuration.md" in message
    assert ALLOW_DIRECT in message
    assert not (tmp_path / "o.pdf").exists()


def test_an_empty_proxy_value_counts_as_unset(no_egress_anything, monkeypatch, tmp_path):
    """`CTIPARSOR_CAPTURE_PROXY=` (blank) is the same as unset (#801)."""
    monkeypatch.setenv(PROXY, "   ")
    with pytest.raises(CaptureUnavailable):
        capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")


def test_the_escape_hatch_is_read_as_a_boolean(no_egress_anything, monkeypatch, tmp_path):
    """Only a true value opens the hatch; `0` and an unrecognised value keep it shut (#801)."""
    for value in ("0", "maybe"):
        monkeypatch.setenv(ALLOW_DIRECT, value)
        with pytest.raises(CaptureUnavailable):
            capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")


class _Recorder:
    """A fake Playwright that records the launch options and renders a page with enough text."""

    def __init__(self):
        self.launch_kwargs: dict = {}

    def install(self, monkeypatch):
        recorder = self

        class _Response:
            url = "https://example.com/"
            status = 200

        class _Page:
            def goto(self, url, **kw):
                return _Response()

            def wait_for_load_state(self, *a, **kw):
                return None

            def emulate_media(self, **kw):
                return None

            def title(self):
                return "Example"

            def inner_text(self, selector):
                return "x" * 500

            def evaluate(self, script):
                if "data-src" in script or "CODEISH" in script or "position" in script:
                    return 0
                return 5000

            def pdf(self, **kw):
                Path(kw["path"]).write_bytes(b"%PDF-1.4 fake\n")

        class _Context:
            def set_default_timeout(self, *a):
                return None

            def route(self, pattern, handler):
                return None

            def new_page(self):
                return _Page()

        class _Browser:
            version = "1.0"

            def new_context(self, **kw):
                return _Context()

            def close(self):
                return None

        class _Chromium:
            def launch(self, **kw):
                recorder.launch_kwargs = kw
                return _Browser()

        class _Playwright:
            chromium = _Chromium()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
        monkeypatch.setattr(web_capture, "sync_playwright", lambda: _Playwright(), raising=False)
        monkeypatch.setattr(web_capture, "validate_url", lambda u: u)
        monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34"])


def test_the_escape_hatch_lets_the_capture_run_and_warns_once(monkeypatch, tmp_path, caplog):
    """With the hatch and no proxy the capture runs, direct, and logs one DNS-rebinding warning (#801)."""
    monkeypatch.delenv(PROXY, raising=False)
    monkeypatch.setenv(ALLOW_DIRECT, "1")
    recorder = _Recorder()
    recorder.install(monkeypatch)

    with caplog.at_level(logging.WARNING):
        result = capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")

    assert result.pdf_path.exists()
    assert "proxy" not in recorder.launch_kwargs
    warnings = [r for r in caplog.records if "DNS-rebinding" in r.getMessage()]
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]


def test_with_the_proxy_the_capture_runs_without_the_hatch_and_without_a_warning(
    monkeypatch, tmp_path, caplog
):
    """With the proxy set the capture needs no hatch; the browser is launched through the proxy (#801)."""
    monkeypatch.setenv(PROXY, "http://capture-proxy:3128")
    monkeypatch.delenv(ALLOW_DIRECT, raising=False)
    recorder = _Recorder()
    recorder.install(monkeypatch)

    with caplog.at_level(logging.WARNING):
        capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")

    assert recorder.launch_kwargs["proxy"] == {"server": "http://capture-proxy:3128"}
    assert not [r for r in caplog.records if "DNS-rebinding" in r.getMessage()]


@pytest.fixture()
def client(temp_db_client, tmp_path, monkeypatch):
    """TestClient with uploads redirected to tmp_path and the worker stubbed out."""
    import api.main

    api.main.limiter.reset()
    monkeypatch.setenv("CTIPARSOR_UPLOADS_DIR", str(tmp_path))
    with patch("api.worker.run_pipeline_async") as spawn:
        temp_db_client.spawn = spawn        # type: ignore[attr-defined]
        yield temp_db_client


def test_the_ingest_route_answers_503_without_the_proxy_before_resolving_the_host(
    client, monkeypatch
):
    """POST /api/ingest/url answers 503 with no proxy and no DNS lookup, as the capture does (#801)."""
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", _forbidden)
    monkeypatch.setattr(web_capture, "capture_url_to_pdf", _forbidden)
    monkeypatch.delenv(PROXY, raising=False)
    monkeypatch.delenv(ALLOW_DIRECT, raising=False)

    resp = client.post("/api/ingest/url", json={"url": "https://example.com/a/"})

    assert resp.status_code == 503
    assert PROXY in resp.json()["detail"]
