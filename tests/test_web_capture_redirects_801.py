# tests/test_web_capture_redirects_801.py
"""
A redirect answered by a public server cannot carry a capture to an internal
address (#801).

These run a real headless Chromium.  Two loopback HTTP servers stand in for the
two sides of the policy: 127.0.0.1 is the "public" host and 127.0.0.2 the
"internal" one.  Both addresses are loopback on Linux, so nothing leaves the
machine, but `validate_url` is replaced so that only 127.0.0.1 counts as public.
The internal server records every request it receives: a single hit is the
bypass.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from pipeline import web_capture
from pipeline.web_capture import CaptureError, capture_url_to_pdf

_CHROMIUM_PROBLEM = web_capture.check_chromium_installed()
pytestmark = pytest.mark.skipif(
    _CHROMIUM_PROBLEM is not None,
    reason=f"needs a real Chromium: {_CHROMIUM_PROBLEM}",
)

INTERNAL_MARKER = "INTERNAL-ONLY-MARKER"
# Long enough that the rendered text clears the capture's minimum (200 characters).
ARTICLE = "Public article text about a threat actor campaign. " * 8


@pytest.fixture(autouse=True)
def _capture_direct_allowed(monkeypatch):
    """The URL capture is refused without its egress proxy; these tests run it without one."""
    monkeypatch.setenv("CTIPARSOR_CAPTURE_ALLOW_DIRECT", "1")


def _html(text: str, extra: str = ""):
    body = f"<html><head><title>t</title></head><body><p>{text}</p>{extra}</body></html>"
    return 200, {"Content-Type": "text/html; charset=utf-8"}, body.encode()


def _redirect(location: str, status: int = 302):
    return status, {"Location": location}, b""


def _png():
    return 200, {"Content-Type": "image/png"}, b"PNG"


class _Server:
    """A loopback HTTP server that answers from `routes` and records each path asked for."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.hits: list[str] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                owner.hits.append(self.path)
                status, headers, body = owner.routes.get(self.path, (404, {}, b""))
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        # Bound to every address so that 127.0.0.2 reaches the same server.
        self._httpd = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        self.port = self._httpd.server_address[1]
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def close(self):
        self._httpd.shutdown()
        self._httpd.server_close()


@pytest.fixture
def make_server():
    servers: list[_Server] = []

    def make(routes: dict) -> _Server:
        server = _Server(routes)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.fixture
def only_127_0_0_1_is_public(monkeypatch):
    """Replace the URL policy: 127.0.0.1 is public, every other host is refused."""

    def fake_validate(raw_url):
        host = urlsplit(raw_url).hostname
        if host != "127.0.0.1":
            raise CaptureError(f"test policy refuses {host}")
        return raw_url

    monkeypatch.setattr(web_capture, "validate_url", fake_validate)
    monkeypatch.delenv(web_capture._CAPTURE_PROXY_ENV, raising=False)


def _capture(url: str, tmp_path: Path, timeout_ms: int = 15_000):
    return capture_url_to_pdf(url, tmp_path / "out.pdf", timeout_ms=timeout_ms)


def test_a_document_redirect_to_a_refused_host_is_not_followed(
    make_server, only_127_0_0_1_is_public, tmp_path
):
    """A public 302 to 127.0.0.2 must not bring the internal page into the capture (#801)."""
    internal = make_server({"/secret": _html(INTERNAL_MARKER + " " + ARTICLE)})
    public = make_server({
        "/start": _redirect(f"http://127.0.0.2:{internal.port}/secret"),
    })

    with pytest.raises(CaptureError):
        _capture(f"http://127.0.0.1:{public.port}/start", tmp_path)

    assert internal.hits == [], "the refused internal host was reached through a redirect"
    assert not (tmp_path / "out.pdf").exists()


def test_a_redirect_chain_inside_the_policy_is_still_followed(
    make_server, only_127_0_0_1_is_public, tmp_path
):
    """Allowed hops keep working, and the capture reports the final URL and the image on it (#801)."""
    public = make_server({
        "/start": _redirect("/news"),
        "/news": _redirect("/news/", status=301),
        "/news/": _html(ARTICLE, '<img src="pic.png">'),
        "/news/pic.png": _png(),
    })

    result = _capture(f"http://127.0.0.1:{public.port}/start", tmp_path)

    assert result.final_url == f"http://127.0.0.1:{public.port}/news/"
    assert result.blocked_requests == 0
    assert "Public article text" in result.dom_text
    # The image is requested relative to the final URL, as a browser would do.
    assert "/news/pic.png" in public.hits


def test_a_subresource_redirect_to_a_refused_host_is_blocked_and_counted(
    make_server, only_127_0_0_1_is_public, tmp_path
):
    """An image that redirects to the internal host is refused and counted as blocked (#801)."""
    internal = make_server({"/secret.png": _png()})
    public = make_server({
        "/page": _html(ARTICLE, '<img src="/img-redirect">'),
        "/img-redirect": _redirect(f"http://127.0.0.2:{internal.port}/secret.png"),
    })

    result = _capture(f"http://127.0.0.1:{public.port}/page", tmp_path)

    assert internal.hits == [], "a subresource redirect reached the refused host"
    assert result.blocked_requests >= 1


def test_a_redirect_loop_stops_at_the_hop_limit(make_server, only_127_0_0_1_is_public, tmp_path):
    """A redirect that points at itself is refused after the first request and ten followed hops (#801)."""
    public = make_server({"/loop": _redirect("/loop")})

    with pytest.raises(CaptureError):
        _capture(f"http://127.0.0.1:{public.port}/loop", tmp_path)

    assert len(public.hits) <= 11, f"the loop was followed {len(public.hits)} times"


def test_a_relative_location_is_resolved_against_the_answering_url(
    make_server, only_127_0_0_1_is_public, tmp_path
):
    """`Location: news2/index.html` from /dir/start resolves to /dir/news2/index.html (#801)."""
    public = make_server({
        "/dir/start": _redirect("news2/index.html"),
        "/dir/news2/index.html": _html(ARTICLE),
    })

    result = _capture(f"http://127.0.0.1:{public.port}/dir/start", tmp_path)

    assert result.final_url == f"http://127.0.0.1:{public.port}/dir/news2/index.html"
    assert result.blocked_requests == 0
    assert "/dir/news2/index.html" in public.hits
