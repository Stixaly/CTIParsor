"""AUTH_MODE, the session lifetime and the start guard (ADR-0097, Network posture)."""
from __future__ import annotations

import ipaddress
import os

AUTH_MODES = ("off", "local", "oidc", "both")
ROLES = ("reader", "analyst", "admin")        # each contains the ones before it
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}
DEFAULT_SESSION_TTL_HOURS = 12
DEFAULT_TOKEN_DAYS = 90


class AuthConfigError(RuntimeError):
    """The authentication settings are refused; the process does not start."""


def auth_mode() -> str:
    """AUTH_MODE, read at each call (tests set it).  Anything but one of the four
    names is refused: a typo must not leave a service open."""
    raw = (os.getenv("AUTH_MODE") or "").strip().lower() or "off"
    if raw not in AUTH_MODES:
        raise AuthConfigError(f"AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {raw!r}")
    return raw


def enabled() -> bool:
    return auth_mode() != "off"


def local_enabled() -> bool:
    return auth_mode() in ("local", "both")


def oidc_configured() -> bool:
    """Part B (OIDC) reads these two; until it exists they only decide whether
    `oidc` and `both` may start."""
    return all((os.getenv(name) or "").strip() for name in ("OIDC_ISSUER_URL", "OIDC_CLIENT_ID"))


def session_ttl_hours() -> float:
    raw = (os.getenv("SESSION_TTL_HOURS") or "").strip()
    if not raw:
        return float(DEFAULT_SESSION_TTL_HOURS)
    try:
        hours = float(raw)
    except ValueError:
        raise AuthConfigError(f"SESSION_TTL_HOURS must be a number above 0, got: {raw!r}") from None
    if not hours > 0 or hours == float("inf"):
        raise AuthConfigError(f"SESSION_TTL_HOURS must be a number above 0, got: {raw!r}")
    return hours


def is_loopback_host(host: str) -> bool:
    """Is `host` a name or address that only this machine reaches: `localhost`,
    127.0.0.0/8, `::1`?  The wildcards `0.0.0.0` and `::` are not."""
    h = host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def api_host() -> str:
    return (os.getenv("API_HOST") or "").strip() or "127.0.0.1"


def published_host() -> str | None:
    """API_PUBLISHED_HOST: the address a port published for the API listens on, set by
    compose from CTI_BIND.  In a container the API always binds 0.0.0.0; this address
    says who can reach it."""
    return (os.getenv("API_PUBLISHED_HOST") or "").strip() or None


def check_startup(host: str | None = None) -> None:
    """Refuse a configuration that leaves the API open or half configured.

    Raises AuthConfigError when AUTH_MODE is not valid, when it is `off` and
    the address that decides exposure is not loopback, and when it is `oidc` or
    `both` and no OIDC configuration exists.  That address is API_PUBLISHED_HOST
    when set (the API runs behind a published port), else `host` (API_HOST).
    The message names the settings to change.
    """
    mode = auth_mode()
    published = published_host()
    host = published or (api_host() if host is None else host.strip())
    if mode == "off" and not is_loopback_host(host):
        if published:
            where = (f"CTI_BIND={published!r} publishes the API beyond this machine (API_PUBLISHED_HOST); "
                     "set CTI_BIND=127.0.0.1")
        else:
            where = f"API_HOST={host!r} is not loopback; set API_HOST=127.0.0.1"
        raise AuthConfigError(
            f"AUTH_MODE=off: the API would be reachable from other machines with no authentication. {where}, "
            "or set AUTH_MODE=local (or oidc, both) and create the first admin with "
            "`python -m api.admin create-admin`.")
    if mode in ("oidc", "both") and not oidc_configured():
        raise AuthConfigError(
            f"AUTH_MODE={mode} needs OIDC_ISSUER_URL and OIDC_CLIENT_ID. Set them, or use AUTH_MODE=local.")
    session_ttl_hours()
