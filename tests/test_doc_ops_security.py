"""The HTTP-header and log-tag sections of the docs match the code.

SECURITY.md ("HTTP security headers") names each security header the application
or the nginx proxy sends. docs/operations.md ("Log tags") has one row per tag the
API and the pipeline log. These tests read the code and fail when a header or a
tag appears in the code without a line in the docs, or a row names a tag the code
no longer writes.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECURITY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
)

# A log message starts with its tag: `"[tag] ...` or `f"[tag] ...`. The space after the
# bracket keeps the defang spellings such as `"[at]",` out of the match.
LOG_TAG = re.compile(r"""["']f?\[([a-z_]+)\] """)


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end == -1 else text[start:end]


def _code_files(*folders: str) -> list[Path]:
    return sorted(p for folder in folders for p in (ROOT / folder).rglob("*.py"))


def test_every_security_header_the_code_sends_is_documented():
    sent: set[str] = set()
    for path in _code_files("api"):
        text = path.read_text(encoding="utf-8")
        sent.update(h for h in SECURITY_HEADERS if h in text)
    nginx = (ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
    sent.update(h for h in SECURITY_HEADERS if h in nginx)
    assert {"X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy"} <= sent, (
        "the scan no longer finds the headers the docs describe; update SECURITY_HEADERS or the scan"
    )
    security = _section((ROOT / "SECURITY.md").read_text(encoding="utf-8"), "## HTTP security headers")
    missing = sorted(h for h in sent if h not in security)
    assert not missing, f"a security header is sent but not named in SECURITY.md (HTTP security headers): {missing}"


def test_every_log_tag_the_code_writes_is_in_the_operations_table():
    written: set[str] = set()
    for path in _code_files("api", "pipeline"):
        written.update(LOG_TAG.findall(path.read_text(encoding="utf-8")))
    assert {"startup", "queue", "finalize", "auth", "admin", "audit", "health", "metrics"} <= written, (
        "the scan no longer finds the tags the docs describe; update LOG_TAG or the scan"
    )
    table = _section((ROOT / "docs" / "operations.md").read_text(encoding="utf-8"), "### Log tags")
    listed = set(re.findall(r"^\| `\[([a-z_]+)\]`", table, flags=re.M))
    missing = sorted(written - listed)
    assert not missing, f"a log tag is written but has no row in docs/operations.md (Log tags): {missing}"
    stale = sorted(listed - written)
    assert not stale, f"docs/operations.md (Log tags) lists a tag the code no longer writes: {stale}"
