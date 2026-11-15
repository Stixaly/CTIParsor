"""The client address the app sees behind the `proxy` profile cannot be forged.

With `FORWARDED_ALLOW_IPS=*` uvicorn takes the first address of X-Forwarded-For.
nginx must therefore replace that header with the address it received from the
client, not append to what the client sent: appended, a request carrying
`X-Forwarded-For: 9.9.9.9` reaches the app as `9.9.9.9, <real address>`, and the
per-IP limits (slowapi, get_remote_address) can be dodged by changing the header.
The first test reads docker/nginx/default.conf; the second is uvicorn alone.
"""
from __future__ import annotations

from pathlib import Path

from uvicorn.middleware.proxy_headers import _TrustedHosts

_ROOT = Path(__file__).resolve().parent.parent


def _forwarded_for_settings() -> list[str]:
    conf = (_ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
    return [
        line.strip()
        for line in conf.splitlines()
        if line.strip().startswith("proxy_set_header") and "x-forwarded-for" in line.lower()
    ]


def test_nginx_replaces_x_forwarded_for_with_the_peer_address():
    settings = _forwarded_for_settings()
    assert settings, "docker/nginx/default.conf sets no X-Forwarded-For: the scan is wrong or the header is gone"
    # $proxy_add_x_forwarded_for appends the client's own value: a forged header survives it.
    assert not any("$proxy_add_x_forwarded_for" in line for line in settings), settings
    assert all(line.endswith("$remote_addr;") for line in settings), settings


def test_uvicorn_trusting_every_peer_takes_the_header_nginx_wrote():
    # What nginx sends after the fix: the address it received, nothing else.
    assert _TrustedHosts("*").get_trusted_client_address("203.0.113.50") == ("203.0.113.50", 0)


def test_a_forged_header_wins_only_if_nginx_appends_to_it():
    # Documents the limit of `*`: the first entry is believed. Behind nginx this
    # header is never forwarded as sent, because nginx replaces it (first test).
    forged_then_appended = "9.9.9.9, 203.0.113.50"
    assert _TrustedHosts("*").get_trusted_client_address(forged_then_appended) == ("9.9.9.9", 0)
