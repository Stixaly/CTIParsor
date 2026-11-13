"""AUTH_MODE, the session lifetime and the start guard (ADR-0097, Network posture)."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

AUTH_MODES = ("off", "local", "oidc", "both")
ROLES = ("reader", "analyst", "admin")        # each contains the ones before it
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}
DEFAULT_SESSION_TTL_HOURS = 12
DEFAULT_TOKEN_DAYS = 90


class AuthConfigError(RuntimeError):
    """An authentication setting is refused (AUTH_MODE, the OIDC_* variables, the client secret file,
    SESSION_TTL_HOURS, OIDC_ROLE_MAP).  At start-up api/main.py logs it and re-raises, so the process
    does not start.  In the OIDC routes (api/routes/auth.py) it answers 302 to /login?error=config."""


def auth_mode() -> str:
    """AUTH_MODE, read at each call (tests set it).  Anything but one of the four
    names is refused: a typo must not leave a service open."""
    raw = (os.getenv("AUTH_MODE") or "").strip().lower() or "off"
    if raw not in AUTH_MODES:
        raise AuthConfigError(f"AUTH_MODE must be one of {', '.join(AUTH_MODES)}, got: {raw!r}")
    return raw


def enabled() -> bool:
    """True when authentication is on, that is when AUTH_MODE is not off."""
    return auth_mode() != "off"


def local_enabled() -> bool:
    """True when local accounts can sign in: AUTH_MODE is local or both."""
    return auth_mode() in ("local", "both")


def oidc_enabled() -> bool:
    """True when OIDC sign-in is on: AUTH_MODE is oidc or both."""
    return auth_mode() in ("oidc", "both")


@dataclass(frozen=True)
class OidcSettings:
    """The OIDC_* settings, validated.  The client secret is not here: it is read from
    `secret_file` each time it is used (`read_client_secret`)."""
    issuer: str
    client_id: str
    secret_file: str
    redirect_uri: str
    scopes: tuple[str, ...]
    groups_claim: str
    role_map: dict[str, str]
    username_claim: str


def _secure_url(name: str, value: str) -> str:
    """`value` if it is an absolute https URL, or an http one for this machine (a test IdP).
    Raises AuthConfigError."""
    parts = urlsplit(value)
    if parts.scheme == "https" and parts.hostname:
        return value
    if parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"):
        return value
    raise AuthConfigError(f"{name} must be an https URL (http only for localhost), got: {value!r}")


def is_secure_url(value: str) -> bool:
    """True when the value is an https URL, or an http URL for localhost; False otherwise."""
    try:
        _secure_url("url", value)
    except AuthConfigError:
        return False
    return True


def parse_role_map(raw: str) -> dict[str, str]:
    """`group=role,group=role` -> {group: role}.  Raises AuthConfigError for an empty map,
    an entry without `=`, an empty group, or a role outside ROLES.  A group name has no comma."""
    mapping: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        group, sep, role = item.rpartition("=")
        group, role = group.strip(), role.strip().lower()
        if not sep or not group:
            raise AuthConfigError(f"OIDC_ROLE_MAP: {item!r} is not group=role")
        if role not in ROLES:
            raise AuthConfigError(f"OIDC_ROLE_MAP: {role!r} is not a role ({', '.join(ROLES)})")
        mapping[group] = role
    if not mapping:
        raise AuthConfigError("OIDC_ROLE_MAP is empty; it needs at least one group=role")
    return mapping


def oidc_settings() -> OidcSettings:
    """The OIDC settings, read at each call.  Raises AuthConfigError, naming every missing
    one in one message, for a missing or malformed value."""
    def env(name: str) -> str:
        """The value of an environment variable, stripped; an empty string when it is unset."""
        return (os.getenv(name) or "").strip()

    required = ("OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET_FILE", "OIDC_REDIRECT_URI",
                "OIDC_ROLE_MAP")
    missing = [name for name in required if not env(name)]
    if missing:
        raise AuthConfigError(f"AUTH_MODE={auth_mode()} needs {', '.join(missing)}. Set them, or use "
                              "AUTH_MODE=local.")
    issuer = _secure_url("OIDC_ISSUER_URL", env("OIDC_ISSUER_URL"))
    redirect_uri = _secure_url("OIDC_REDIRECT_URI", env("OIDC_REDIRECT_URI"))
    if urlsplit(redirect_uri).fragment:
        raise AuthConfigError("OIDC_REDIRECT_URI must have no fragment")
    return OidcSettings(
        issuer=issuer, client_id=env("OIDC_CLIENT_ID"), secret_file=env("OIDC_CLIENT_SECRET_FILE"),
        redirect_uri=redirect_uri, scopes=tuple((env("OIDC_SCOPES") or "openid profile email").split()),
        groups_claim=env("OIDC_GROUPS_CLAIM") or "groups", role_map=parse_role_map(env("OIDC_ROLE_MAP")),
        username_claim=env("OIDC_USERNAME_CLAIM") or "preferred_username")


def read_client_secret(settings: OidcSettings) -> str:
    """The client secret, read from its file.  Raises AuthConfigError when the file cannot be
    read or is empty.  The secret is not logged or kept."""
    try:
        with open(settings.secret_file, encoding="utf-8") as handle:
            secret = handle.read().strip()
    except OSError as exc:
        raise AuthConfigError(f"OIDC_CLIENT_SECRET_FILE cannot be read: {exc.strerror or 'error'}") from None
    if not secret:
        raise AuthConfigError("OIDC_CLIENT_SECRET_FILE is empty")
    return secret


def session_ttl_hours() -> float:
    """The session lifetime in hours, from SESSION_TTL_HOURS (DEFAULT_SESSION_TTL_HOURS when unset). Raise
    AuthConfigError when the value is not a number above 0."""
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
    """The address the API listens on: API_HOST, or 127.0.0.1 when it is unset."""
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
    if mode in ("oidc", "both"):
        settings = oidc_settings()
        if "openid" not in settings.scopes:
            raise AuthConfigError("OIDC_SCOPES must include openid")
        read_client_secret(settings)
    session_ttl_hours()
