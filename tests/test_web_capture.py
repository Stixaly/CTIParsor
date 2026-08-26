# tests/test_web_capture.py
from pathlib import Path

import pytest

from pipeline import web_capture
from pipeline.web_capture import CaptureError, CaptureResult, suggest_filename, validate_url


def test_bare_domain_gets_https_prefix(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34"])
    assert validate_url("example.com/a") == "https://example.com/a"


def test_fragment_is_stripped(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34"])
    assert validate_url("https://example.com/a#frag") == "https://example.com/a"


def test_empty_path_becomes_slash(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34"])
    assert validate_url("https://example.com") == "https://example.com/"


def test_rejects_file_scheme():
    with pytest.raises(CaptureError, match="scheme"):
        validate_url("file:///etc/passwd")


def test_rejects_javascript_scheme():
    with pytest.raises(CaptureError):
        validate_url("javascript:alert(1)")


def test_rejects_credentials_in_url():
    with pytest.raises(CaptureError, match="Credentials"):
        validate_url("https://user:pw@example.com/")


def test_rejects_localhost():
    with pytest.raises(CaptureError):
        validate_url("http://localhost:8000/")


def test_rejects_dot_internal_host():
    with pytest.raises(CaptureError):
        validate_url("https://api.internal/")


def test_rejects_loopback_literal():
    with pytest.raises(CaptureError):
        validate_url("http://127.0.0.1/")


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/",
        "http://[::1]/",
    ],
)
def test_rejects_private_literal(url):
    with pytest.raises(CaptureError):
        validate_url(url)


def test_rejects_disallowed_port():
    with pytest.raises(CaptureError, match="Port"):
        validate_url("https://example.com:11434/")


def test_rejects_when_any_resolved_ip_is_private(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34", "10.1.2.3"])
    with pytest.raises(CaptureError):
        validate_url("https://evil.example/")


def test_rejects_ipv4_mapped_private_v6():
    with pytest.raises(CaptureError):
        validate_url("http://[::ffff:10.0.0.1]/")


def test_accepts_public_host(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda h: ["93.184.216.34"])
    url = "https://thedfirreport.com/2024/08/12/x/"
    assert validate_url(url) == url


def test_unresolvable_host_raises(monkeypatch):
    def fake_resolve(h):
        raise CaptureError("Cannot resolve host: nope")
    monkeypatch.setattr(web_capture, "_resolve_all", fake_resolve)
    with pytest.raises(CaptureError):
        validate_url("https://nope.invalid/")


def test_slugify_strips_accents_and_punctuation():
    assert (
        web_capture._slugify("Volt Typhoon : Living off the Land (2023) — Microsoft")
        == "volt-typhoon-living-off-the-land-2023-microsoft"
    )


def test_slugify_truncates():
    assert len(web_capture._slugify("a" * 200)) == 80


def test_slugify_empty_input():
    assert web_capture._slugify("···") == ""


def test_suggest_filename_falls_back_to_host():
    result = CaptureResult(
        pdf_path=Path("x.pdf"),
        final_url="https://thedfirreport.com/a/",
        title="",
        bytes_written=1,
        js_enabled=False,
        blocked_requests=0,
    )
    assert suggest_filename(result) == "thedfirreport-com.pdf"


def test_capture_without_playwright_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", False)
    with pytest.raises(CaptureError, match="Playwright"):
        web_capture.capture_url_to_pdf("https://example.com/", tmp_path / "o.pdf")


def test_blank_render_is_rejected_with_a_javascript_hint(monkeypatch, tmp_path):
    """
    A client-rendered page yields a valid PDF that is a blank sheet.

    Locks the cert.gov.ua case: 200 OK, a 944-byte PDF, and zero extractable
    text. Only a zero-byte guard existed, so the job was created and five
    pipeline stages ran to build an empty bundle.
    """
    captured: dict[str, object] = {}

    class _FakePage:
        def goto(self, url, **kw):
            return _FakeResponse(url)

        def wait_for_load_state(self, *a, **kw):
            return None

        def emulate_media(self, **kw):
            return None

        def title(self):
            return "CERT-UA"

        def inner_text(self, selector):
            return "   "  # a nav shell and nothing else

        def pdf(self, **kw):
            captured["pdf_written"] = True

    class _FakeResponse:
        def __init__(self, url):
            self.url = url
            self.status = 200

    class _FakeContext:
        def set_default_timeout(self, *a):
            return None

        def route(self, *a):
            return None

        def new_page(self):
            return _FakePage()

    class _FakeBrowser:
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

    with pytest.raises(CaptureError) as exc:
        web_capture.capture_url_to_pdf("https://cert.example/article/1", tmp_path / "o.pdf")

    assert "rendered 3 characters" in str(exc.value)
    assert "JavaScript" in str(exc.value)
    # The blank page must be rejected before a PDF is ever written.
    assert "pdf_written" not in captured


def test_launch_hint_names_the_root_sandbox_conflict(monkeypatch):
    """
    Running as root with the sandbox on is its own failure, and its own fix.

    Chromium refuses to run as root while sandboxed.  Reported as a generic
    "could not start" it sends the reader to reinstall a browser that is already
    there, which is what happened in practice.
    """
    monkeypatch.setattr(web_capture.os, "geteuid", lambda: 0, raising=False)
    msg = web_capture._launch_hint(Exception("Failed to launch"), sandboxed=True)
    assert "running as root" in msg
    assert web_capture._UNSANDBOXED_ENV in msg
    assert "Underlying error: Failed to launch" in msg


def test_launch_hint_names_a_missing_browser(monkeypatch):
    monkeypatch.setattr(web_capture.os, "geteuid", lambda: 1000, raising=False)
    msg = web_capture._launch_hint(
        Exception("Executable doesn't exist at /root/.cache/ms-playwright/..."),
        sandboxed=True,
    )
    assert "not installed for the account" in msg
    assert "playwright install chromium" in msg


def test_launch_hint_always_carries_the_underlying_reason(monkeypatch):
    """The first version swallowed it, which is what made the report unactionable."""
    monkeypatch.setattr(web_capture.os, "geteuid", lambda: 1000, raising=False)
    msg = web_capture._launch_hint(Exception("libasound.so.2: cannot open"), sandboxed=False)
    assert "libasound.so.2" in msg
    assert "install-deps" in msg
class _FakePage:
    """Records what _render_pdf asks for, without a browser."""

    def __init__(self, height, *, evaluate_fails=False, unclip_fails=False,
                 eager_count=32, image_wait_fails=False):
        self._height = height
        self._evaluate_fails = evaluate_fails
        self._unclip_fails = unclip_fails
        self._eager_count = eager_count
        self._image_wait_fails = image_wait_fails
        self.pdf_kwargs = None
        self.unstick_calls = 0
        self.unclip_calls = 0
        self.eager_calls = 0
        self.waited_for_images = False

    def evaluate(self, script):
        if self._evaluate_fails:
            raise web_capture.PlaywrightError("evaluate blew up")
        # The three preparation scripts are told apart by what they look for.
        if "data-src" in script:
            self.eager_calls += 1
            return self._eager_count
        if "CODEISH" in script:
            if self._unclip_fails:
                raise web_capture.PlaywrightError("unclip blew up")
            self.unclip_calls += 1
            return 108
        if "position" in script:
            self.unstick_calls += 1
            return 12
        return self._height

    def wait_for_function(self, script, **kwargs):
        self.waited_for_images = True
        if self._image_wait_fails:
            raise web_capture.PlaywrightError("an image never completed")

    def pdf(self, **kwargs):
        self.pdf_kwargs = kwargs


def test_render_pdf_uses_one_tall_page_for_a_normal_document(tmp_path):
    page = _FakePage(5000)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.pdf_kwargs["height"] == "5000px"
    assert page.pdf_kwargs["width"] == "1280px"
    assert "format" not in page.pdf_kwargs
    assert page.pdf_kwargs["margin"]["top"] == "0"
    assert page.pdf_kwargs["margin"]["bottom"] == "0"
    assert page.pdf_kwargs["margin"]["left"] == "0"
    assert page.pdf_kwargs["margin"]["right"] == "0"


def test_render_pdf_caps_the_page_at_the_pdf_limit(tmp_path):
    page = _FakePage(20636)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    # 19,200px = 14,400pt = 200in, the largest page Acrobat reads.
    assert page.pdf_kwargs["height"] == "19200px"


def test_render_pdf_neutralises_pinned_elements_first(tmp_path):
    page = _FakePage(5000)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.unstick_calls == 1


def test_render_pdf_falls_back_to_a4_when_height_is_unmeasurable(tmp_path):
    page = _FakePage(0)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.pdf_kwargs["format"] == "A4"
    assert "height" not in page.pdf_kwargs


def test_render_pdf_falls_back_to_a4_when_evaluate_raises(tmp_path):
    page = _FakePage(5000, evaluate_fails=True)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.pdf_kwargs["format"] == "A4"


def test_render_pdf_expands_scrollers_before_printing(tmp_path):
    """
    A container that scrolls on screen is a container that is cut on paper.

    Locks the Google Cloud Threat Intelligence case: two <pre> blocks 952px and
    1071px wide inside a 739px column lost 22% and 31% of two command listings.
    Expanding them recovered 530 characters of code.
    """
    page = _FakePage(5000)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.unclip_calls == 1


def test_render_pdf_survives_an_unclip_that_throws(tmp_path):
    """A page that refuses the expansion still gets captured, just clipped."""
    page = _FakePage(5000, unclip_fails=True)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.pdf_kwargs is not None
    assert page.pdf_kwargs["height"] == "5000px"


def test_render_pdf_eager_loads_javascript_lazy_images(tmp_path):
    """
    Lazy-loaders park the real URL in data-src; with page scripts off nothing
    ever copies it into src, and the figure is absent from the archive.

    Locks the unit42 Aeternum report, which uses lozad.js: 31 of its 98 images
    had no src at all, and the capture embedded 11 distinct images, every one an
    icon or a logo. Making that copy here takes it to 32 distinct images, every
    one a figure of the report.
    """
    page = _FakePage(5000)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.eager_calls == 1
    # And they have to be waited for, or the sheet prints before they arrive.
    assert page.waited_for_images is True


def test_render_pdf_does_not_wait_when_there_is_nothing_to_eager_load(tmp_path):
    """A page with no lazy images must not pay the settle timeout."""
    page = _FakePage(5000, eager_count=0)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.waited_for_images is False
    assert page.pdf_kwargs is not None


def test_render_pdf_prints_even_if_an_image_never_completes(tmp_path):
    """One straggler must not cost the whole capture."""
    page = _FakePage(5000, image_wait_fails=True)
    web_capture._render_pdf(page, tmp_path / "o.pdf")
    assert page.pdf_kwargs is not None
    assert page.pdf_kwargs["height"] == "5000px"
