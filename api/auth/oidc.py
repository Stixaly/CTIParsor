"""Sign-in with an OpenID Connect identity provider (ADR-0097 item 14, part B).

Authorization code flow with PKCE (S256), `state` and `nonce`, as a confidential client.

  * `begin_login` builds the authorization request from the issuer's discovery document,
    keeps `state`, `nonce`, the PKCE verifier and the page to return to in the database
    (api/auth/store.py: 10 minutes, read once) and returns the URL to send the browser to.
  * `complete_login` checks `state`, exchanges the code, validates the ID token and
    returns the local account to sign in.  Every refusal is an `OidcError` whose `code` is
    a fixed short word for the sign-in page; the identity provider's own text is never
    passed on, and no token, code or secret is logged.

The identity provider decides who the person is; the role comes from the groups claim
through OIDC_ROLE_MAP and is recomputed at every sign-in.  An account is found by
`(auth_source='oidc', oidc_subject='<iss>|<sub>')`, never by name, so an OIDC identity
cannot take over a local account that has the same username.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode

import httpx
from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, import_key

from api.auth import config, store
from api.logging_config import get_logger

logger = get_logger(__name__)

CACHE_SECONDS = 3600                  # the discovery document and the JWKS
LEEWAY_SECONDS = 60                   # clock difference allowed on exp, iat and nbf
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_RESPONSE_BYTES = 1_000_000
# Asymmetric algorithms only: a shared-secret or `none` token is never accepted.
ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]

# Tests set this to an httpx transport that answers for the identity provider.
_TRANSPORT: httpx.BaseTransport | None = None
_cache: dict[str, tuple[float, Any]] = {}


class OidcError(Exception):
    """A sign-in that is refused.  `code` goes to the sign-in page (`/login?error=<code>`);
    the message is for the log and holds no token."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reset_cache() -> None:
    _cache.clear()


# ── The identity provider over HTTP ──────────────────────────────────────────

def _client() -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False, transport=_TRANSPORT)


def _json(response: httpx.Response, what: str) -> dict:
    if response.status_code != 200:
        raise OidcError("idp", f"{what}: HTTP {response.status_code}")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise OidcError("idp", f"{what}: the answer is too large")
    try:
        body = response.json()
    except ValueError:
        raise OidcError("idp", f"{what}: the answer is not JSON") from None
    if not isinstance(body, dict):
        raise OidcError("idp", f"{what}: the answer is not an object")
    return body


def _get_json(url: str, what: str) -> dict:
    try:
        with _client() as client:
            return _json(client.get(url, headers={"Accept": "application/json"}), what)
    except httpx.HTTPError as exc:
        raise OidcError("idp", f"{what}: {type(exc).__name__}") from None


def _cached(key: str, load) -> Any:
    hit = _cache.get(key)
    now = time.monotonic()
    if hit is not None and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    value = load()
    _cache[key] = (now, value)
    return value


def discovery(settings: config.OidcSettings) -> dict:
    """The issuer's discovery document, cached for an hour.  Its `issuer` must be the
    configured one, and the endpoints used must be https (http for localhost)."""
    def load() -> dict:
        url = settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
        doc = _get_json(url, "discovery")
        if doc.get("issuer") != settings.issuer:
            raise OidcError("idp", "discovery: the issuer of the document is not the configured one")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = doc.get(name)
            if not isinstance(value, str) or not config.is_secure_url(value):
                raise OidcError("idp", f"discovery: {name} is missing or not https")
        return doc

    return _cached("discovery:" + settings.issuer, load)


def _key_set(settings: config.OidcSettings, *, refresh: bool = False) -> KeySet:
    key = "jwks:" + settings.issuer
    if refresh:
        _cache.pop(key, None)

    def load() -> KeySet:
        document = _get_json(discovery(settings)["jwks_uri"], "jwks")
        keys = []
        for item in document.get("keys") or []:
            if not isinstance(item, dict) or item.get("use") == "enc":
                continue
            try:
                keys.append(import_key(item))
            except (JoseError, ValueError, TypeError, KeyError):
                continue                  # a key of a kind this library does not read: the others still serve
        if not keys:
            raise OidcError("idp", "jwks: no usable key")
        return KeySet(keys)

    return _cached(key, load)


# ── The request ──────────────────────────────────────────────────────────────

def safe_next(value: str | None) -> str:
    """The page to return to after sign-in: a local path, else `/`.  Anything that a browser
    could read as another site (`//host`, `/\\host`, a scheme, a control character) is `/`."""
    if not value or len(value) > 512 or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return "/"
    return value


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def begin_login(next_path: str | None) -> tuple[str, str]:
    """Store a pending request and return (the identity provider's authorization URL, the
    binding value for the browser's cookie).
    Raises OidcError (`idp` when discovery fails, `busy` when too many are pending)."""
    settings = config.oidc_settings()
    endpoint = discovery(settings)["authorization_endpoint"]
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    binding = secrets.token_urlsafe(32)
    if not store.begin_oidc_login(state, nonce, verifier, safe_next(next_path), binding):
        raise OidcError("busy", "too many sign-ins are pending")
    query = urlencode({
        "response_type": "code", "client_id": settings.client_id, "redirect_uri": settings.redirect_uri,
        "scope": " ".join(settings.scopes), "state": state, "nonce": nonce,
        "code_challenge": _b64url(hashlib.sha256(verifier.encode("ascii")).digest()),
        "code_challenge_method": "S256"}, quote_via=quote)
    return endpoint + ("&" if "?" in endpoint else "?") + query, binding


# ── The answer ───────────────────────────────────────────────────────────────

def _exchange(settings: config.OidcSettings, code: str, verifier: str) -> str:
    """Trade the authorization code for the ID token."""
    secret = config.read_client_secret(settings)
    doc = discovery(settings)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": settings.redirect_uri,
            "code_verifier": verifier}
    methods = doc.get("token_endpoint_auth_methods_supported")
    if isinstance(methods, list) and "client_secret_basic" not in methods and "client_secret_post" in methods:
        form.update(client_id=settings.client_id, client_secret=secret)
        auth: httpx.Auth = httpx.Auth()
    else:
        auth = httpx.BasicAuth(quote(settings.client_id, safe=""), quote(secret, safe=""))
    try:
        with _client() as client:
            body = _json(client.post(doc["token_endpoint"], data=form, auth=auth,
                                     headers={"Accept": "application/json"}), "token")
    except httpx.HTTPError as exc:
        raise OidcError("idp", f"token: {type(exc).__name__}") from None
    token = body.get("id_token")
    if not isinstance(token, str) or not token:
        raise OidcError("token", "token: the answer has no id_token")
    return token


def _header_kid(token: str) -> str | None:
    try:
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=" * 3))
    except (ValueError, binascii.Error, IndexError):
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    return kid if isinstance(kid, str) else None


def _verify(settings: config.OidcSettings, token: str) -> dict:
    """The claims of an ID token whose signature, issuer, audience, authorized party and
    times hold.  (The nonce is the caller's.)  An unknown `kid` fetches the JWKS once more."""
    keys = _key_set(settings)
    kid = _header_kid(token)
    if kid is not None and kid not in {key.kid for key in keys.keys}:
        keys = _key_set(settings, refresh=True)
    try:
        signed = jws.deserialize_compact(token, keys, algorithms=ALGORITHMS)
        claims = json.loads(signed.payload)
    except (JoseError, ValueError, TypeError, KeyError, binascii.Error) as exc:
        raise OidcError("token", f"id_token: not verified ({type(exc).__name__})") from None
    if not isinstance(claims, dict):
        raise OidcError("token", "id_token: the payload is not an object")
    if claims.get("iss") != settings.issuer:
        raise OidcError("token", "id_token: wrong issuer")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    if not isinstance(audiences, list) or settings.client_id not in audiences:
        raise OidcError("token", "id_token: wrong audience")
    azp = claims.get("azp")
    if (azp is not None or len(audiences) > 1) and azp != settings.client_id:
        raise OidcError("token", "id_token: wrong authorized party")
    now = time.time()
    for name in ("exp", "iat"):
        value = claims.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OidcError("token", f"id_token: {name} is missing")
    if now > claims["exp"] + LEEWAY_SECONDS:
        raise OidcError("token", "id_token: expired")
    if claims["iat"] > now + LEEWAY_SECONDS:
        raise OidcError("token", "id_token: issued in the future")
    nbf = claims.get("nbf")
    if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, (int, float))
                            or nbf > now + LEEWAY_SECONDS):
        raise OidcError("token", "id_token: not yet valid")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OidcError("token", "id_token: no subject")
    return claims


def role_for(settings: config.OidcSettings, claims: dict) -> str | None:
    """The highest role among the mapped groups of the groups claim, or None.  The claim is
    a list of names (a lone string counts as one group); anything else holds no group."""
    raw = claims.get(settings.groups_claim)
    groups = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    roles = [settings.role_map[g] for g in groups if isinstance(g, str) and g in settings.role_map]
    return max(roles, key=config.ROLE_RANK.__getitem__) if roles else None


_UNSAFE = re.compile(r"[^a-z0-9._@-]")


def username_for(settings: config.OidcSettings, claims: dict, subject: str) -> str:
    """A username for a new account: the configured claim, else `email`, else `sub`,
    cut to the characters a username may hold; a free one (a `-2` suffix on a clash)."""
    for name in (settings.username_claim, "email", "sub"):
        value = claims.get(name)
        if not isinstance(value, str):
            continue
        base = _UNSAFE.sub("-", value.strip().lower()).lstrip("._@-")[:60]
        if base:
            break
    else:
        base = "oidc-" + hashlib.sha256(subject.encode()).hexdigest()[:12]
    candidate, n = base, 1
    while store.find_user(candidate) is not None:
        n += 1
        candidate = f"{base[:60]}-{n}"
    return candidate


def _account(settings: config.OidcSettings, claims: dict) -> store.User:
    subject = f"{settings.issuer}|{claims['sub']}"
    role = role_for(settings, claims)
    user = store.find_oidc_user(subject)
    if user is not None and user.disabled:
        raise OidcError("disabled", f"account {user.username!r} is disabled")
    if role is None:
        if user is not None:
            store.end_sessions(user.id)              # no group any more: the open sessions go too
        raise OidcError("no_role", "no group of the token is in OIDC_ROLE_MAP")
    if user is not None:
        if user.role != role:
            store.set_role(user.id, role)
            logger.info("[auth] OIDC account %r: role %s -> %s", user.username, user.role, role)
            user = store.get_user(user.id) or user
        return user
    name = claims.get("name")
    display = name.strip()[:128] if isinstance(name, str) else ""
    for _ in range(3):
        try:
            user = store.create_user(username_for(settings, claims, subject), role, auth_source="oidc",
                                     oidc_subject=subject, display_name=display)
        except store.AuthError:
            continue                                  # the name was taken between the check and the insert
        except Exception:                             # noqa: BLE001 - a concurrent first sign-in of the same person
            user = store.find_oidc_user(subject)
            if user is None:
                raise
            return user
        logger.info("[auth] OIDC account %r created with role %s", user.username, role)
        return user
    raise OidcError("account", "no free username")


def complete_login(code: str | None, state: str | None, binding: str | None) -> tuple[store.User, str]:
    """Finish a sign-in: (the user, the page to return to).  `binding` is the cookie of the
    browser that comes back; it must be the one the request started with (a sign-in that
    someone else started cannot be finished in this browser).  Raises OidcError."""
    settings = config.oidc_settings()
    pending = store.consume_oidc_login(state, binding) if state else None
    if pending is None:
        raise OidcError("state", "unknown, used or expired state, or not the browser that started it")
    if not code:
        raise OidcError("state", "no authorization code")
    claims = _verify(settings, _exchange(settings, code, pending["code_verifier"]))
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(nonce.encode(), pending["nonce"].encode()):
        raise OidcError("token", "id_token: wrong nonce")
    user = _account(settings, claims)
    store.mark_login(user.id)
    return user, pending["next_path"]
