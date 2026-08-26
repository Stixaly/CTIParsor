"""
Render an arbitrary web page to PDF, safely enough to point at a URL found in a
report.

The page is hostile until proven otherwise: it is chosen by whoever wrote the
report, not by the analyst.  Three boundaries stand between it and the host —
the URL policy in `validate_url` (scheme, port, and every IP the host resolves
to), the request filter installed on the browser context (resource types, and
the same URL policy re-applied to every subresource), and the Chromium renderer
sandbox, which `capture_url_to_pdf` turns back ON because Playwright ships it
off by default.

JavaScript is disabled unless the caller asks for it, which removes the entire
script attack surface and the beacons with it.  See ADR-0029.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from api.logging_config import get_logger

if TYPE_CHECKING:
    # Type-only: `new_context(viewport=…)` wants the ViewportSize TypedDict, and
    # a plain dict[str, int] does not satisfy it.  Imported under TYPE_CHECKING
    # so the module still loads when Playwright is not installed.
    from playwright.sync_api import Page, ViewportSize

logger = get_logger(__name__)

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright
    _PLAYWRIGHT_AVAILABLE = True
except Exception:  # ImportError, or a broken native install
    _PLAYWRIGHT_AVAILABLE = False

    class PlaywrightError(Exception):  # type: ignore[no-redef]
        """Stand-in so except clauses stay valid when Playwright is absent."""


class CaptureError(Exception):
    """A URL could not be captured — invalid, blocked, unreachable, or too large."""


class CaptureUnavailable(CaptureError):
    """
    The capability itself is not usable — the browser is missing or cannot start.

    Separate from CaptureError so the API can answer 503 (this server cannot do
    captures) rather than 502 (this page could not be captured) without parsing
    an exception message to tell them apart.
    """


# ── SSRF policy ───────────────────────────────────────────────────────────────
# A capture request is attacker-influenced by construction: the analyst pastes a
# URL found in a report.  Everything below exists to keep that URL from reaching
# the machine the analyst is sitting on, or its network.

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Only the ports a public site actually serves on.  Anything else is far more
# likely to be an internal service (5432, 6379, 9200, 11434…) than a CTI blog.
_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})

# Hostnames that never resolve to a public host, blocked before DNS so a
# resolver that answers them cannot be used as the bypass.
_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".home.arpa",
)

# Metadata endpoints of the major clouds — public-looking names that hand out
# credentials.  169.254.169.254 is already caught by the link-local rule; listed
# again so the intent survives a refactor of the IP checks.
_BLOCKED_LITERAL_HOSTS = frozenset({
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "fd00:ec2::254",
})

# Resource types Chromium may fetch while rendering.  `script` is added only
# when JavaScript is explicitly enabled by the caller.
_ALLOWED_RESOURCE_TYPES = frozenset({
    "document",
    "stylesheet",
    "image",
    "font",
})

# Chromium flags.  Note what is NOT here: `--no-sandbox`.  The renderer sandbox
# is the single most important boundary between a hostile page and the host, and
# disabling it is the usual "fix" for running as root in a container — do not.
_CHROMIUM_ARGS = (
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--disable-client-side-phishing-detection",
    "--no-first-run",
    "--no-default-browser-check",
    "--mute-audio",
)

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

# Playwright's launch() defaults `chromium_sandbox` to False — it appends
# --no-sandbox itself, so writing careful args above is not enough.  The sandbox
# is what keeps a renderer exploit from becoming host code execution, so it is
# forced back on.  It needs unprivileged user namespaces; a container that
# cannot grant them can set this variable, and gets a loud warning for it.
_UNSANDBOXED_ENV = "CTIPARSOR_CAPTURE_UNSANDBOXED"

_DEFAULT_TIMEOUT_MS = 30_000
_MAX_PDF_BYTES = 50 * 1024 * 1024
_VIEWPORT: ViewportSize = {"width": 1280, "height": 1696}

# A client-rendered page yields a PDF that is a valid file and a blank sheet.
# cert.gov.ua is one: with JavaScript off its body is 0 characters, and the
# capture produced a 944-byte PDF from which Stage 1 extracts nothing.  Checking
# only for a zero-byte file lets that through, and the pipeline then runs five
# stages to build an empty bundle.  Measured against the rendered DOM rather
# than the PDF, because that is where the emptiness actually is.
_MIN_RENDERED_CHARS = 200

# A PDF page may not exceed 14,400 points — 200 inches — and stay readable by
# Acrobat.  At 96 dpi that is 19,200 CSS pixels.  Rendering the whole document
# on one sheet is the goal, because every page boundary is a place an image or a
# paragraph gets cut in half; the cap is what keeps that sheet a legal PDF.
# Measured: a 20,636px article becomes 2 pages of exactly 14,400pt instead of 25
# A4 pages, so 24 cut boundaries become 1.
_MAX_PDF_PAGE_PX = 19_200

# Elements pinned to the viewport are repainted onto every printed page, landing
# on top of the text.  Page 9 of an uncorrected capture reads "Cloud BloSgleep
# Prior tCoo InEtCac-1t 0s4ales" — a sticky nav bar interleaved with the article
# character by character.  Neutralising position before printing is the fix;
# emulate_media("print") is not, and was measured to change nothing at all.
#
# This runs through page.evaluate(), which works even when the context has
# java_script_enabled=False: that flag stops the page's own scripts, not
# Playwright's injected evaluation.
_UNSTICK_JS = """
(() => {
  let n = 0;
  for (const el of document.querySelectorAll('*')) {
    const pos = getComputedStyle(el).position;
    if (pos === 'fixed' || pos === 'sticky') {
      el.style.setProperty('position', 'static', 'important');
      n += 1;
    }
  }
  return n;
})()
"""


@dataclass(frozen=True)
class CaptureResult:
    pdf_path: Path
    final_url: str          # after redirects
    title: str              # page <title>, stripped; "" when the page has none
    bytes_written: int
    js_enabled: bool
    blocked_requests: int   # subresource requests refused by the route filter
    rendered_chars: int = 0  # visible DOM text at render time — see _MIN_RENDERED_CHARS
    # The visible DOM text.  This, not the PDF, is what the pipeline ingests:
    # the PDF is the archive the analyst reviews, but its text layer destroys
    # 28% of the observables (ADR-0029).
    dom_text: str = ""


def _host_is_blocked(host: str) -> bool:
    """Check if a hostname is explicitly blocked by policy."""
    if host in _BLOCKED_LITERAL_HOSTS:
        return True
    for suffix in _BLOCKED_HOST_SUFFIXES:
        if host.endswith(suffix):
            return True
    return False


def _ip_is_public(ip: str) -> bool:
    """Check if an IP address is public and not in a reserved range."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if isinstance(obj, ipaddress.IPv6Address) and obj.ipv4_mapped is not None:
        return _ip_is_public(str(obj.ipv4_mapped))

    if (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_reserved
        or obj.is_multicast
        or obj.is_unspecified
    ):
        return False

    return True


@lru_cache(maxsize=512)
def _resolve_all(host: str) -> list[str]:
    """
    Resolve a hostname to every address it answers with.

    Cached because the request filter re-validates every subresource, and a page
    with sixty images would otherwise pay sixty resolutions for one host.  The
    cache also pins a host to the answer it first gave, so a DNS record that
    flips to a private address mid-render cannot be used to walk past the check
    that already passed.
    """
    try:
        results = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise CaptureError(f"Cannot resolve host: {host}") from e

    seen: set[str] = set()
    unique_ips: list[str] = []
    for entry in results:
        # sockaddr is (host, port) for AF_INET and a 4-tuple for AF_INET6, so
        # typeshed widens element 0 to `str | int`.  It is always the address
        # string for the two families asked for here; str() makes that explicit
        # rather than leaving the list typed `list[str | int]`.
        ip = str(entry[4][0])
        if ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)
    return unique_ips


def _render_pdf(page: "Page", dest: Path) -> None:
    """
    Print the page to `dest` as one tall sheet, with viewport-pinned elements
    neutralised first.

    Falls back to A4 pagination if the document height cannot be measured — a
    wrong height would produce a blank or clipped sheet, and A4 at least yields
    something readable.
    """
    try:
        unstuck = page.evaluate(_UNSTICK_JS)
    except PlaywrightError:
        unstuck = 0

    try:
        height = int(page.evaluate(
            "Math.ceil(Math.max("
            "document.documentElement.scrollHeight,"
            "document.body ? document.body.scrollHeight : 0))"
        ))
    except (PlaywrightError, TypeError, ValueError):
        height = 0

    if height <= 0:
        logger.warning("Document height could not be measured; falling back to A4 pagination")
        page.pdf(
            path=str(dest),
            format="A4",
            print_background=True,
            margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
        )
        return

    page_height = min(height, _MAX_PDF_PAGE_PX)
    page.pdf(
        path=str(dest),
        print_background=True,
        width=f"{_VIEWPORT['width']}px",
        height=f"{page_height}px",
        margin={"top": "0", "bottom": "0", "left": "0", "right": "0"},
    )
    logger.debug("Unstuck %d elements; document height %dpx; page height %dpx", unstuck, height, page_height)


def _launch_hint(exc: Exception, *, sandboxed: bool) -> str:
    """
    Turn a Chromium launch failure into the one sentence that fixes it.

    Three causes look identical from the outside and need opposite fixes, so the
    underlying Playwright reason is always included rather than swallowed — the
    first version of this message said only "could not start" and sent the
    reader looking in the wrong place.
    """
    reason = str(exc).strip().splitlines()[0][:200]
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    if is_root and sandboxed:
        return (
            "Chromium cannot start: this API is running as root, and Chromium "
            "refuses to run as root with its sandbox enabled. Either run the API "
            "as a normal user (recommended — the sandbox is what contains a "
            f"malicious page), or set {_UNSANDBOXED_ENV}=1 to render without it "
            f"and accept that risk. Underlying error: {reason}"
        )
    if "Executable doesn't exist" in reason or "playwright install" in reason:
        return (
            "Chromium is not installed for the account running this API "
            "(browsers live under that account's HOME, so an install done as a "
            "different user is invisible here). Run, as that account: "
            "python -m playwright install chromium. "
            f"Underlying error: {reason}"
        )
    return (
        "Chromium could not start. If this mentions a missing shared library, "
        "run: sudo python -m playwright install-deps chromium. "
        f"Underlying error: {reason}"
    )


def _slugify(text: str, *, max_len: int = 80) -> str:
    """Convert a string to a URL-safe slug."""
    # 1. Normalize and strip accents
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii")

    # 2. Replace non-alphanumeric sequences with a single hyphen
    slug = re.sub(r"[^A-Za-z0-9]+", "-", ascii_text)

    # 3. Strip leading/trailing hyphens
    slug = slug.strip("-")

    # 4. Truncate and strip trailing hyphens again
    slug = slug[:max_len].rstrip("-")

    # 5. Lowercase
    return slug.lower()


def validate_url(raw_url: str) -> str:
    """Validate and normalize a URL for safe capture."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise CaptureError("Empty URL")

    url = raw_url.strip()
    if "://" not in url:
        url = f"https://{url}"

    try:
        parsed = urlsplit(url)
    except ValueError:
        raise CaptureError("Malformed URL")

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise CaptureError(f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed.")

    if parsed.username or parsed.password:
        raise CaptureError("Credentials in URL are not allowed")

    host = parsed.hostname
    if not host:
        raise CaptureError("URL has no host")

    try:
        port = parsed.port
    except ValueError:
        raise CaptureError("Invalid port")

    if port is not None and port not in _ALLOWED_PORTS:
        raise CaptureError(f"Port {port} is not allowed. Allowed: 80, 443, 8080, 8443.")

    host_lower = host.lower()
    if _host_is_blocked(host_lower):
        raise CaptureError(f"Host '{host}' is not reachable from this service")

    # Check if it's a literal IP
    is_literal_ip = False
    try:
        ipaddress.ip_address(host)
        is_literal_ip = True
    except ValueError:
        pass

    if is_literal_ip:
        if not _ip_is_public(host):
            raise CaptureError(f"Address {host} is not a public address")
    else:
        resolved_ips = _resolve_all(host)
        if not resolved_ips:
            raise CaptureError(f"Host '{host}' resolves to a non-public address")
        for ip in resolved_ips:
            if not _ip_is_public(ip):
                raise CaptureError(f"Host '{host}' resolves to a non-public address")

    return urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def capture_url_to_pdf(
    url: str,
    dest: Path,
    *,
    enable_js: bool = False,
    timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    max_bytes: int = _MAX_PDF_BYTES,
) -> CaptureResult:
    """Capture a URL to a PDF file using Playwright."""
    if not _PLAYWRIGHT_AVAILABLE:
        raise CaptureError(
            "Web capture is unavailable — Playwright is not installed. "
            "Run: pip install playwright && python -m playwright install chromium"
        )

    safe_url = validate_url(url)
    dest.parent.mkdir(parents=True, exist_ok=True)

    blocked = [0]

    def _route_filter(route, request):
        try:
            allowed = set(_ALLOWED_RESOURCE_TYPES)
            if enable_js:
                allowed.update({"script", "xhr", "fetch"})

            if request.resource_type not in allowed:
                blocked[0] += 1
                route.abort()
                return

            try:
                validate_url(request.url)
            except CaptureError:
                blocked[0] += 1
                route.abort()
                return

            route.continue_()
        except Exception:
            try:
                route.abort()
            except Exception:
                pass

    sandboxed = os.environ.get(_UNSANDBOXED_ENV, "").strip().lower() not in {"1", "true", "yes"}
    if not sandboxed:
        logger.warning(
            "%s is set — Chromium will render %s WITHOUT its sandbox. A renderer "
            "exploit on that page becomes code execution on this host.",
            _UNSANDBOXED_ENV,
            safe_url,
        )

    with sync_playwright() as p:
        # The launch is the one call that fails for environment reasons rather
        # than page reasons: a browser that was never downloaded, downloaded
        # under a different HOME than the server runs as (uvicorn as root reads
        # /root/.cache, `playwright install` as a user writes ~/.cache), or
        # missing a system library.  Left unguarded it escapes as a 500 with an
        # ASGI traceback, which tells the analyst nothing — so it is converted
        # here into the same actionable message the 503 path already uses.
        try:
            browser = p.chromium.launch(
                headless=True,
                chromium_sandbox=sandboxed,
                args=list(_CHROMIUM_ARGS),
            )
        except PlaywrightError as exc:
            raise CaptureUnavailable(_launch_hint(exc, sandboxed=sandboxed)) from exc
        # Everything past the launch goes through this try/finally: a page that
        # 404s or times out must not leave an orphaned Chromium behind, and the
        # early raises below all sit inside it.
        try:
            context = browser.new_context(
                java_script_enabled=enable_js,
                accept_downloads=False,
                ignore_https_errors=False,
                bypass_csp=False,
                service_workers="block",
                user_agent=_USER_AGENT,
                viewport=_VIEWPORT,
                locale="en-US",
                extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
            )
            context.set_default_timeout(timeout_ms)
            context.route("**/*", _route_filter)

            page = context.new_page()

            try:
                response = page.goto(safe_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightError as exc:
                raise CaptureError(f"Could not load {safe_url}: {exc}") from exc

            if response is None:
                raise CaptureError(f"No response from {safe_url}")

            if response.status >= 400:
                raise CaptureError(f"{safe_url} returned HTTP {response.status}")

            try:
                page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 10_000))
            except PlaywrightError:
                pass

            page.emulate_media(media="screen")

            try:
                title = (page.title() or "").strip()
            except PlaywrightError:
                title = ""

            # Read the rendered text before printing.  Two jobs: a page that
            # renders nothing still produces a perfectly valid, perfectly blank
            # PDF, and this text — not the PDF's — is what the pipeline ingests.
            # Measured over 6 CTI pages, the PDF keeps 99.6% of the characters
            # and only 72.2% of the observables: a 64-char hash in a narrow
            # table column wraps into 24-char fragments the text layer then
            # interleaves with the neighbouring cells.  The DOM has no columns.
            try:
                dom_text = page.inner_text("body")
            except PlaywrightError:
                dom_text = ""
            rendered_chars = len(dom_text)

            if rendered_chars < _MIN_RENDERED_CHARS:
                raise CaptureError(
                    f"{safe_url} rendered {rendered_chars} characters of text"
                    + ("" if enable_js else " — it needs JavaScript. Retry with "
                                            "'Run page JavaScript' enabled, or paste the report text.")
                )

            final_url = response.url or safe_url

            # No `page_ranges` cap: Chromium errors when the range runs past the
            # document, which would fail every capture shorter than the cap.
            # `max_bytes` below is the bound that actually holds.
            try:
                _render_pdf(page, dest)
            except PlaywrightError as exc:
                raise CaptureError(f"PDF rendering failed: {exc}") from exc
        finally:
            try:
                browser.close()
            except Exception:
                pass

    if not dest.exists() or dest.stat().st_size == 0:
        dest.unlink(missing_ok=True)
        raise CaptureError("PDF rendering produced an empty file")

    size = dest.stat().st_size
    if size > max_bytes:
        dest.unlink(missing_ok=True)
        raise CaptureError(f"Captured page is too large ({size} bytes, limit {max_bytes})")

    logger.info(
        "Captured %s -> %s (%d bytes, %d blocked requests, JS: %s)",
        final_url,
        dest,
        size,
        blocked[0],
        enable_js,
    )

    return CaptureResult(
        pdf_path=dest,
        final_url=final_url,
        title=title,
        bytes_written=size,
        js_enabled=enable_js,
        blocked_requests=blocked[0],
        rendered_chars=rendered_chars,
        dom_text=dom_text,
    )


def suggest_filename(result: CaptureResult) -> str:
    """Suggest a filename for a captured PDF based on title or host."""
    slug = _slugify(result.title)
    if not slug:
        host = urlsplit(result.final_url).hostname or ""
        slug = _slugify(host)
    if not slug:
        slug = "captured-page"
    return f"{slug}.pdf"
