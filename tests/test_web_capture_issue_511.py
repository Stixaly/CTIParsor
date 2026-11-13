# tests/test_web_capture_issue_511.py
"""
The capture request filter lets inline `data:` images and fonts through (#511).

A `data:` URL is the page's own bytes: it never reaches the network, so
`validate_url` has nothing to protect it from.  Every other block stays.
"""
from pathlib import Path

import pytest

from pipeline import web_capture


@pytest.fixture(autouse=True)
def _capture_direct_allowed(monkeypatch):
    """The URL capture is refused without its egress proxy; these tests run it without one."""
    monkeypatch.setenv("CTIPARSOR_CAPTURE_ALLOW_DIRECT", "1")


class _FakeRoute:
    def __init__(self):
        self.calls: list[str] = []

    def abort(self):
        self.calls.append("abort")

    def continue_(self):
        self.calls.append("continue")


class _FakeRequest:
    def __init__(self, url, resource_type):
        self.url = url
        self.resource_type = resource_type


def _request_filter(monkeypatch, tmp_path, *, enable_js=False):
    """Run a capture with fakes and return the request filter it installed on the context."""
    installed: dict[str, object] = {}

    class _FakeResponse:
        url = "https://example.com/"
        status = 200

    class _FakePage:
        def goto(self, url, **kw):
            return _FakeResponse()

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

    class _FakeContext:
        def set_default_timeout(self, *a):
            return None

        def route(self, pattern, handler):
            installed["handler"] = handler

        def new_page(self):
            return _FakePage()

    class _FakeBrowser:
        version = "1.0"

        def new_context(self, **kw):
            return _FakeContext()

        def close(self):
            return None

    class _FakePlaywright:
        def __init__(self):
            self.chromium = self

        def launch(self, **kw):
            return _FakeBrowser()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "sync_playwright", lambda: _FakePlaywright(), raising=False)
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: ["93.184.216.34"])

    web_capture.capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf", enable_js=enable_js)
    return installed["handler"]


@pytest.mark.parametrize("resource_type", ["image", "font"])
def test_inline_data_url_is_let_through(monkeypatch, tmp_path, resource_type):
    """Inline images and fonts reach the page (#511): data: never touches the network."""
    request_filter = _request_filter(monkeypatch, tmp_path)
    route = _FakeRoute()
    request_filter(route, _FakeRequest("data:image/png;base64,iVBORw0KGgo=", resource_type))
    assert route.calls == ["continue"], "inline data: URL was blocked (#511)"


def test_data_url_scheme_is_matched_case_insensitively(monkeypatch, tmp_path):
    """The scheme is case-insensitive per RFC 3986, so `DATA:` is let through too (#511)."""
    request_filter = _request_filter(monkeypatch, tmp_path)
    route = _FakeRoute()
    request_filter(route, _FakeRequest("DATA:image/gif;base64,R0lGOD", "image"))
    assert route.calls == ["continue"], "upper-case DATA: URL was blocked (#511)"


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/logo.png",
        "http://10.0.0.5/font.woff2",
        "http://169.254.169.254/latest/meta-data/",
    ],
)
def test_private_address_is_still_blocked_next_to_data_urls(monkeypatch, tmp_path, url):
    """Allowing data: must not reopen the SSRF guard for http(s) subresources (#511)."""
    request_filter = _request_filter(monkeypatch, tmp_path)
    route = _FakeRoute()
    request_filter(route, _FakeRequest(url, "image"))
    assert route.calls == ["abort"], f"{url} was not blocked by the request filter (#511)"


def test_data_url_keeps_the_resource_type_policy(monkeypatch, tmp_path):
    """A data: URL requested as a script, with JavaScript off, is still refused (#511)."""
    request_filter = _request_filter(monkeypatch, tmp_path, enable_js=False)
    route = _FakeRoute()
    request_filter(route, _FakeRequest("data:text/javascript,alert(1)", "script"))
    assert route.calls == ["abort"], "data: script was allowed with JavaScript off (#511)"
