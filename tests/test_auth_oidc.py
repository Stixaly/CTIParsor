"""Sign-in with an OpenID Connect identity provider (ADR-0097 item 14, part B).

No network: a fake identity provider answers through an httpx mock transport.  It
publishes a discovery document and a JWKS for an RSA key made by the test, and signs
the ID tokens the test asks for.  Every refusal of api/auth/oidc.py has a test here;
the settings and their start guard are in test_auth_guard.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jws
from joserfc.jwk import RSAKey

from api.auth import config, oidc, store

ISSUER = "https://idp.example/realms/cti"
CLIENT_ID = "ctiparsor"
CLIENT_SECRET = "s3cret-value"                          # noqa: S105 - a test value
REDIRECT_URI = "https://cti.example/api/auth/oidc/callback"
ROLE_MAP = "cti-admins=admin,cti-analysts=analyst,cti-readers=reader"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeIdp:
    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, parameters={"kid": "k1", "use": "sig"})
        self.extra_keys: list[RSAKey] = []
        self.id_token = ""
        self.discovery_hits = 0
        self.jwks_hits = 0
        self.token_requests: list[httpx.Request] = []
        self.token_status = 200
        self.token_body: dict | str | None = None
        self.issuer_in_document = ISSUER

    # What the IdP serves.
    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == ISSUER + "/.well-known/openid-configuration":
            self.discovery_hits += 1
            return httpx.Response(200, json={
                "issuer": self.issuer_in_document, "authorization_endpoint": ISSUER + "/protocol/auth",
                "token_endpoint": ISSUER + "/protocol/token", "jwks_uri": ISSUER + "/protocol/certs"})
        if url == ISSUER + "/protocol/certs":
            self.jwks_hits += 1
            return httpx.Response(200, json={"keys": [k.as_dict(private=False)
                                                      for k in (self.key, *self.extra_keys)]})
        if url == ISSUER + "/protocol/token" and request.method == "POST":
            self.token_requests.append(request)
            if self.token_body is not None:
                if isinstance(self.token_body, str):
                    return httpx.Response(self.token_status, content=self.token_body)
                return httpx.Response(self.token_status, json=self.token_body)
            return httpx.Response(self.token_status, json={"access_token": "at", "token_type": "Bearer",
                                                           "id_token": self.id_token})
        return httpx.Response(404)

    # Tokens.
    def claims(self, nonce: str, /, **override) -> dict:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "sub-1", "nonce": nonce, "iat": now, "exp": now + 300,
                  "preferred_username": "alice", "name": "Alice A.", "groups": ["cti-analysts"]}
        claims.update(override)
        return {k: v for k, v in claims.items() if v is not None}

    def sign(self, claims: dict, key: RSAKey | None = None, alg: str = "RS256", kid: str | None = None) -> str:
        key = key or self.key
        header = {"alg": alg, "kid": kid or key.kid}
        return jws.serialize_compact(header, json.dumps(claims).encode(), key)


@pytest.fixture()
def idp(monkeypatch, tmp_path):
    fake = FakeIdp()
    secret = tmp_path / "oidc-secret"
    secret.write_text(CLIENT_SECRET + "\n")
    for name, value in {"OIDC_ISSUER_URL": ISSUER, "OIDC_CLIENT_ID": CLIENT_ID,
                        "OIDC_CLIENT_SECRET_FILE": str(secret), "OIDC_REDIRECT_URI": REDIRECT_URI,
                        "OIDC_ROLE_MAP": ROLE_MAP}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(oidc, "_TRANSPORT", httpx.MockTransport(fake.handle))
    oidc.reset_cache()
    yield fake
    oidc.reset_cache()


@pytest.fixture()
def client(auth_client, idp, monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "both")
    return auth_client


def start(client, next_path: str | None = None) -> dict[str, str]:
    """GET /api/auth/oidc/login; the query of the authorization URL it redirects to."""
    params = {} if next_path is None else {"next": next_path}
    response = client.get("/api/auth/oidc/login", params=params, follow_redirects=False)
    assert response.status_code == 302, response.text
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == ISSUER + "/protocol/auth"
    return {k: v[0] for k, v in parse_qs(location.query).items()}


def sign_in(client, idp, *, next_path: str | None = None, token_claims: dict | None = None,
            token: str | None = None, state: str | None = None):
    """A whole sign-in: the login redirect, then the callback with an ID token for that request."""
    query = start(client, next_path)
    idp.id_token = token if token is not None else idp.sign(idp.claims(query["nonce"], **(token_claims or {})))
    return client.get("/api/auth/oidc/callback", params={"code": "abc", "state": state or query["state"]},
                      follow_redirects=False)


def refused(response, code: str) -> None:
    assert response.status_code == 302 and response.headers["location"] == f"/login?error={code}", (
        response.status_code, response.headers.get("location"))
    cookies = response.headers.get_list("set-cookie")
    assert not any(c.startswith("ctiparsor_session=") for c in cookies)       # no session
    if response.request.url.path.endswith("/callback"):
        assert_binding_cleared(cookies)


def assert_binding_cleared(cookies: list[str]) -> None:
    (cleared,) = [c for c in cookies if c.startswith("ctiparsor_oidc=")]
    flags = {part.strip().lower() for part in cleared.split(";")}
    assert {"max-age=0", "path=/api/auth/oidc", "httponly", "samesite=lax", "secure"} <= flags
    assert cleared.startswith('ctiparsor_oidc=""') or cleared.startswith("ctiparsor_oidc=;")


def users() -> list[dict]:
    return store.list_users()


# ── The request ──────────────────────────────────────────────────────────────

def test_the_login_redirects_to_the_authorization_endpoint_with_pkce_state_and_nonce(client, idp):
    query = start(client)
    assert query["response_type"] == "code" and query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == REDIRECT_URI
    assert query["scope"] == "openid profile email"
    assert query["code_challenge_method"] == "S256" and len(query["code_challenge"]) == 43
    assert len(query["state"]) >= 32 and len(query["nonce"]) >= 32 and query["state"] != query["nonce"]
    response = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert response.headers["cache-control"] == "no-store"
    assert not any(c.startswith("ctiparsor_session=") for c in response.headers.get_list("set-cookie"))


def test_the_login_binds_the_request_to_the_browser_with_a_cookie(client, temp_db):
    response = client.get("/api/auth/oidc/login", follow_redirects=False)
    (cookie,) = response.headers.get_list("set-cookie")
    assert cookie.startswith("ctiparsor_oidc=")
    flags = {part.strip().lower() for part in cookie.split(";")}
    assert {"httponly", "secure", "samesite=lax", "path=/api/auth/oidc", "max-age=600"} <= flags
    value = cookie.split(";")[0].split("=", 1)[1]
    assert len(value) >= 32
    with temp_db.get_conn() as conn:
        stored = conn.execute("SELECT binding_hash FROM oidc_logins").fetchone()["binding_hash"]
    assert stored == hashlib.sha256(value.encode()).hexdigest() and value not in stored


def test_the_binding_cookie_is_secure_only_over_https(client, idp, temp_db):
    from fastapi.testclient import TestClient

    import api.main

    with TestClient(api.main.app, base_url="http://testserver", client=("127.0.0.1", 50000)) as plain:
        cookie = plain.get("/api/auth/oidc/login", follow_redirects=False).headers["set-cookie"]
    assert "secure" not in {part.strip().lower() for part in cookie.split(";")}


def test_each_login_has_its_own_state_nonce_and_challenge(client):
    a, b = start(client), start(client)
    assert {a["state"], a["nonce"], a["code_challenge"]}.isdisjoint({b["state"], b["nonce"], b["code_challenge"]})


def test_the_pending_request_is_stored_hashed_and_only_there(client, temp_db):
    query = start(client, "/jobs")
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT * FROM oidc_logins").fetchone()
    assert row["state_hash"] == hashlib.sha256(query["state"].encode()).hexdigest()
    assert row["nonce"] == query["nonce"] and row["next_path"] == "/jobs"
    assert query["state"] not in tuple(row)


def test_the_discovery_document_is_fetched_once_for_several_logins(client, idp):
    start(client)
    start(client)
    assert idp.discovery_hits == 1


def test_the_oidc_routes_need_no_session(client):
    assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 302
    assert client.get("/api/auth/oidc/callback", follow_redirects=False).status_code == 302
    assert client.get("/api/jobs").status_code == 401                    # the rest stays closed


@pytest.mark.parametrize("mode, status", [("off", 404), ("local", 403)])
def test_the_routes_are_unavailable_unless_the_mode_has_oidc(client, monkeypatch, mode, status):
    monkeypatch.setenv("AUTH_MODE", mode)
    for path in ("/api/auth/oidc/login", "/api/auth/oidc/callback"):
        assert client.get(path, follow_redirects=False).status_code == status


@pytest.mark.parametrize("mode", ["oidc", "both"])
def test_the_routes_work_in_both_oidc_modes(client, monkeypatch, mode):
    monkeypatch.setenv("AUTH_MODE", mode)
    assert client.get("/api/auth/oidc/login", follow_redirects=False).status_code == 302


# ── Success ──────────────────────────────────────────────────────────────────

def test_a_full_sign_in_creates_the_user_with_the_mapped_role_and_a_session(client, idp):
    response = sign_in(client, idp)
    assert response.status_code == 302 and response.headers["location"] == "/"
    cookies = response.headers.get_list("set-cookie")
    (cookie,) = [c for c in cookies if c.startswith("ctiparsor_session=")]
    flags = {part.strip().lower() for part in cookie.split(";")}
    assert {"httponly", "secure", "samesite=strict", "path=/"} <= flags
    assert_binding_cleared(cookies)                                      # the sign-in cookie is spent
    me = client.get("/api/auth/me").json()
    assert (me["username"], me["role"], me["auth_source"], me["display_name"]) == ("alice", "analyst", "oidc",
                                                                                   "Alice A.")
    row = next(u for u in users() if u["username"] == "alice")
    assert row["last_login_at"] is not None
    assert store.check_credentials("alice", "anything") is None          # an OIDC account has no password


def test_the_code_is_exchanged_with_the_verifier_the_challenge_came_from(client, idp):
    query = start(client)
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    client.get("/api/auth/oidc/callback", params={"code": "the-code", "state": query["state"]},
               follow_redirects=False)
    (request,) = idp.token_requests
    form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
    assert form["grant_type"] == "authorization_code" and form["code"] == "the-code"
    assert form["redirect_uri"] == REDIRECT_URI
    assert _b64(hashlib.sha256(form["code_verifier"].encode()).digest()) == query["code_challenge"]
    assert "client_secret" not in form
    assert request.headers["authorization"] == "Basic " + base64.b64encode(
        f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()


def test_the_client_secret_is_read_from_its_file_at_each_use(client, idp, tmp_path, monkeypatch):
    secret = tmp_path / "rotated"
    secret.write_text("rotated-secret")
    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", str(secret))
    sign_in(client, idp)
    auth = idp.token_requests[0].headers["authorization"]
    assert base64.b64decode(auth.split()[1]).decode() == f"{CLIENT_ID}:rotated-secret"


def test_the_page_asked_for_is_where_the_sign_in_ends(client, idp):
    response = sign_in(client, idp, next_path="/jobs/abc?tab=graph")
    assert response.headers["location"] == "/jobs/abc?tab=graph"


def test_a_second_sign_in_updates_the_role_without_a_second_account(client, idp, make_user):
    sign_in(client, idp)
    assert client.get("/api/auth/me").json()["role"] == "analyst"
    sign_in(client, idp, token_claims={"groups": ["cti-admins"]})
    assert client.get("/api/auth/me").json()["role"] == "admin"
    make_user("admin", "bob")                    # alice is not the last enabled admin, so her role can change
    sign_in(client, idp, token_claims={"groups": ["cti-readers"]})
    assert client.get("/api/auth/me").json()["role"] == "reader"
    assert [u["username"] for u in users()] == ["alice", "bob"]          # still one account per person


def test_the_last_enabled_admin_keeps_the_admin_role_when_its_groups_map_to_less(client, idp, caplog):
    caplog.set_level(logging.WARNING)
    sign_in(client, idp, token_claims={"groups": ["cti-admins"]})
    response = sign_in(client, idp, token_claims={"groups": ["cti-readers"]})
    assert response.status_code == 302 and response.headers["location"] == "/"      # the sign-in succeeds
    assert client.get("/api/auth/me").json()["role"] == "admin"
    assert next(u for u in users() if u["username"] == "alice")["role"] == "admin"
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "[auth]" in r.getMessage()]
    assert len(warnings) == 1 and "'alice'" in warnings[0] and "last enabled admin" in warnings[0]
    assert "reader" in warnings[0] and ISSUER not in warnings[0]


@pytest.mark.parametrize("other_is_enabled", [True, False])
def test_an_admin_is_demoted_by_a_sign_in_only_when_another_enabled_admin_remains(client, idp, make_user,
                                                                                  other_is_enabled):
    sign_in(client, idp, token_claims={"groups": ["cti-admins"]})
    make_user("admin", "bob")
    if not other_is_enabled:
        store.set_disabled("bob")                                  # a disabled admin is no safety net
    sign_in(client, idp, token_claims={"groups": ["cti-readers"]})
    expected = "reader" if other_is_enabled else "admin"
    assert client.get("/api/auth/me").json()["role"] == expected


def test_the_highest_mapped_role_wins_and_unmapped_groups_count_for_nothing(client, idp):
    sign_in(client, idp, token_claims={"groups": ["other", "cti-readers", "cti-admins", "cti-analysts"]})
    assert client.get("/api/auth/me").json()["role"] == "admin"


def test_a_groups_claim_that_is_one_string_is_one_group(client, idp):
    sign_in(client, idp, token_claims={"groups": "cti-readers"})
    assert client.get("/api/auth/me").json()["role"] == "reader"


def test_the_groups_claim_name_is_a_setting(client, idp, monkeypatch):
    monkeypatch.setenv("OIDC_GROUPS_CLAIM", "roles")
    refused(sign_in(client, idp), "no_role")                             # the default `groups` is not read now
    sign_in(client, idp, token_claims={"roles": ["cti-admins"]})
    assert client.get("/api/auth/me").json()["role"] == "admin"


def test_the_account_is_found_by_issuer_and_subject_not_by_name(client, idp, temp_db):
    sign_in(client, idp)
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT oidc_subject FROM users").fetchone()["oidc_subject"] == f"{ISSUER}|sub-1"
    sign_in(client, idp, token_claims={"preferred_username": "renamed"})  # the same person, another claim
    assert [u["username"] for u in users()] == ["alice"]
    sign_in(client, idp, token_claims={"sub": "sub-2", "preferred_username": "alice"})
    assert sorted(u["username"] for u in users()) == ["alice", "alice-2"]


@pytest.mark.parametrize("claims, username", [
    ({"preferred_username": "Alice.Smith@Corp.com"}, "alice.smith@corp.com"),
    ({"preferred_username": None, "email": "bob+x@corp.com"}, "bob-x@corp.com"),
    ({"preferred_username": None, "sub": "Zed Q"}, "zed-q"),
    ({"preferred_username": "a" * 90}, "a" * 60),
    ({"preferred_username": "...", "email": "ok@corp.com"}, "ok@corp.com"),
])
def test_the_username_comes_from_the_claim_cleaned_to_the_allowed_characters(client, idp, claims, username):
    sign_in(client, idp, token_claims=claims)
    assert client.get("/api/auth/me").json()["username"] == username


def test_a_local_account_with_the_same_username_is_not_taken_over(client, idp, make_user):
    local = make_user("admin", "alice")
    response = sign_in(client, idp)
    assert response.status_code == 302 and response.headers["location"] == "/"
    me = client.get("/api/auth/me").json()
    assert me["username"] == "alice-2" and me["auth_source"] == "oidc" and me["role"] == "analyst"
    kept = store.find_user("alice")
    assert kept is not None and kept.id == local.id and kept.auth_source == "local" and kept.role == "admin"


def test_both_modes_keep_the_local_sign_in(client, make_user):
    from .conftest import AUTH_TEST_PASSWORD

    user = make_user("reader")
    response = client.post("/api/auth/login", json={"username": user.username, "password": AUTH_TEST_PASSWORD})
    assert response.status_code == 200 and response.json()["auth_source"] == "local"


# ── Where the browser goes next ──────────────────────────────────────────────

@pytest.mark.parametrize("value", ["//evil.example", "https://evil.example", "/\\evil.example", "\\\\evil.example",
                                   "javascript:alert(1)", "evil", "", "/a\\b", "/a\nb", "/a\x00b", "/" + "a" * 600,
                                   "http:/evil.example", "///evil"])
def test_a_page_that_is_not_a_local_path_becomes_the_root(value):
    assert oidc.safe_next(value) == "/"


@pytest.mark.parametrize("value", ["/", "/jobs", "/jobs/1?tab=x#frag", "/a/b%2Fc"])
def test_a_local_path_is_kept(value):
    assert oidc.safe_next(value) == value


@pytest.mark.parametrize("value", ["//evil.example", "https://evil.example", "/\\evil.example"])
def test_an_open_redirect_attempt_ends_at_the_root(client, idp, value):
    response = sign_in(client, idp, next_path=value)
    assert response.status_code == 302 and response.headers["location"] == "/"


# ── The binding to the browser ───────────────────────────────────────────────

def test_a_callback_without_the_binding_cookie_is_refused(client, idp):
    query = start(client)
    client.cookies.clear()                                               # the browser that comes back never started it
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "state")
    assert idp.token_requests == [] and users() == []


def test_a_callback_with_another_browsers_cookie_is_refused(client, idp):
    victim = start(client)                                               # a state started by one login ...
    client.cookies.clear()
    start(client)                                                        # ... a cookie from a different one
    idp.id_token = idp.sign(idp.claims(victim["nonce"]))
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": victim["state"]},
                       follow_redirects=False), "state")
    assert idp.token_requests == [] and users() == []


def test_a_made_up_binding_cookie_is_refused(client, idp):
    query = start(client)
    client.cookies.clear()
    client.cookies.set("ctiparsor_oidc", "x" * 43, domain="testserver", path="/api/auth/oidc")
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "state")


def test_a_state_started_in_one_browser_is_spent_by_a_refused_attempt(client, idp):
    query = start(client)
    good = dict(client.cookies)
    client.cookies.clear()
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "state")
    for name, value in good.items():
        client.cookies.set(name, value, domain="testserver", path="/api/auth/oidc")
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "state")


# ── The state ────────────────────────────────────────────────────────────────

def test_a_state_the_server_never_issued_is_refused(client, idp):
    refused(sign_in(client, idp, state="x" * 43), "state")
    assert idp.token_requests == []                                      # the code was not even sent on


def test_a_callback_without_state_or_code_is_refused(client, idp):
    refused(client.get("/api/auth/oidc/callback", follow_redirects=False), "state")
    query = start(client)
    refused(client.get("/api/auth/oidc/callback", params={"state": query["state"]}, follow_redirects=False), "state")
    assert idp.token_requests == []


def test_a_state_is_good_once(client, idp):
    query = start(client)
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    params = {"code": "abc", "state": query["state"]}
    first = client.get("/api/auth/oidc/callback", params=params, follow_redirects=False)
    assert first.status_code == 302 and first.headers["location"] == "/" and "set-cookie" in first.headers
    client.cookies.clear()
    refused(client.get("/api/auth/oidc/callback", params=params, follow_redirects=False), "state")
    assert len(idp.token_requests) == 1


def test_a_state_is_good_for_ten_minutes(client, idp, temp_db):
    query = start(client)
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT created_at, expires_at FROM oidc_logins").fetchone()
        assert store._parse(row["expires_at"]) - store._parse(row["created_at"]) == store.OIDC_LOGIN_TTL
        conn.execute("UPDATE oidc_logins SET expires_at=?", (store._ts(store._now() - timedelta(seconds=1)),))
    idp.id_token = idp.sign(idp.claims(query["nonce"]))
    refused(client.get("/api/auth/oidc/callback", params={"code": "abc", "state": query["state"]},
                       follow_redirects=False), "state")
    assert idp.token_requests == []


def test_expired_requests_are_swept_and_the_table_is_capped(client, temp_db, monkeypatch):
    start(client)
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE oidc_logins SET expires_at=?", (store._ts(store._now() - timedelta(minutes=1)),))
    start(client)
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM oidc_logins").fetchone()["n"] == 1
    monkeypatch.setattr(store, "OIDC_LOGIN_CAP", 1)
    refused(client.get("/api/auth/oidc/login", follow_redirects=False), "busy")


def test_the_identity_provider_saying_no_ends_at_the_login_page_without_its_text(client, idp, temp_db):
    query = start(client)
    response = client.get("/api/auth/oidc/callback", follow_redirects=False,
                          params={"error": "access_denied", "error_description": "<script>x</script>",
                                  "state": query["state"]})
    refused(response, "denied")
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM oidc_logins").fetchone()["n"] == 0


# ── The ID token ─────────────────────────────────────────────────────────────

def test_a_token_signed_by_another_key_is_refused(client, idp):
    other = RSAKey.generate_key(2048, parameters={"kid": "k1"})          # same kid, not the published key
    query = start(client)
    idp.id_token = idp.sign(idp.claims(query["nonce"]), key=other)
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "token")
    assert users() == []


def test_a_tampered_payload_is_refused(client, idp):
    query = start(client)
    head, _, sig = idp.sign(idp.claims(query["nonce"])).split(".")
    forged = _b64(json.dumps(idp.claims(query["nonce"], groups=["cti-admins"])).encode())
    idp.id_token = ".".join((head, forged, sig))
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                       follow_redirects=False), "token")


def test_tokens_with_no_signature_or_a_shared_secret_are_refused(client, idp):
    query = start(client)
    payload = _b64(json.dumps(idp.claims(query["nonce"])).encode())
    none_token = f"{_b64(json.dumps({'alg': 'none', 'kid': 'k1'}).encode())}.{payload}."
    hs_head = _b64(json.dumps({"alg": "HS256", "kid": "k1"}).encode())
    hs_token = f"{hs_head}.{payload}.{_b64(b'x' * 32)}"
    for token in (none_token, hs_token, "not-a-jwt", "a.b.c", ""):
        idp.id_token = token
        state = start(client)
        again = client.get("/api/auth/oidc/callback", params={"code": "c", "state": state["state"]},
                           follow_redirects=False)
        refused(again, "token")
    assert users() == []


@pytest.mark.parametrize("override", [
    {"iss": "https://evil.example/realms/cti"},
    {"iss": None},
    {"aud": "someone-else"},
    {"aud": ["someone-else", "another"]},
    {"aud": [CLIENT_ID, "other"]},                                      # several audiences and no azp
    {"aud": [CLIENT_ID, "other"], "azp": "other"},
    {"aud": CLIENT_ID, "azp": "other"},
    {"aud": None},
    {"exp": int(time.time()) - 3600},
    {"exp": int(time.time()) - 120},
    {"exp": None},
    {"exp": "tomorrow"},
    {"iat": int(time.time()) + 3600},
    {"iat": None},
    {"nbf": int(time.time()) + 3600},
    {"nonce": "someone-elses-nonce"},
    {"nonce": None},
    {"sub": None},
    {"sub": ""},
])
def test_a_token_whose_claims_do_not_hold_is_refused(client, idp, override):
    refused(sign_in(client, idp, token_claims=override), "token")
    assert users() == []


@pytest.mark.parametrize("nonce", ["\ud800", "a\x00b", "\udfff\ud800"])
def test_a_nonce_with_a_lone_surrogate_or_a_nul_byte_is_refused_not_a_500(client, idp, nonce):
    # json.dumps escapes the surrogate, so the signed payload carries "\ud800" as JSON text, as an IdP would send it.
    refused(sign_in(client, idp, token_claims={"nonce": nonce}), "token")
    assert users() == []


def test_a_nonce_from_another_request_is_refused(client, idp):
    first, second = start(client), start(client)
    idp.id_token = idp.sign(idp.claims(first["nonce"]))                  # for the first request ...
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": second["state"]},
                       follow_redirects=False), "token")                  # ... used on the second


@pytest.mark.parametrize("override", [
    {"exp": -30},                                                        # inside the 60 s leeway
    {"iat": 30},
    {"aud": [CLIENT_ID, "other"], "azp": CLIENT_ID},
    {"aud": [CLIENT_ID], "azp": CLIENT_ID},
])
def test_a_token_inside_the_leeway_and_a_valid_azp_are_accepted(client, idp, override):
    now = int(time.time())
    override = {k: now + v if k in ("exp", "iat") else v for k, v in override.items()}
    response = sign_in(client, idp, token_claims=override)
    assert response.headers["location"] == "/" and "set-cookie" in response.headers


def test_an_unknown_kid_fetches_the_keys_once_more(client, idp):
    sign_in(client, idp)                                                 # the keys are cached with k1 only
    assert idp.jwks_hits == 1
    rotated = RSAKey.generate_key(2048, parameters={"kid": "k2", "use": "sig"})
    idp.extra_keys.append(rotated)
    query = start(client)
    idp.id_token = idp.sign(idp.claims(query["nonce"]), key=rotated)
    response = client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"]},
                          follow_redirects=False)
    assert response.headers["location"] == "/" and idp.jwks_hits == 2


def test_a_kid_that_is_still_unknown_is_refused_after_one_fetch(client, idp):
    sign_in(client, idp)
    stranger = RSAKey.generate_key(2048, parameters={"kid": "nobody"})
    refused(sign_in(client, idp, token=idp.sign(idp.claims("n"), key=stranger)), "token")
    assert idp.jwks_hits == 2


def test_the_keys_are_cached_for_an_hour(client, idp, monkeypatch):
    sign_in(client, idp)
    sign_in(client, idp)
    assert idp.jwks_hits == 1
    real = time.monotonic()
    monkeypatch.setattr(oidc.time, "monotonic", lambda: real + oidc.CACHE_SECONDS + 1)
    sign_in(client, idp)
    assert idp.jwks_hits == 2 and idp.discovery_hits == 2


# ── The identity provider misbehaving ────────────────────────────────────────

def test_a_token_endpoint_error_is_refused_without_its_text(client, idp):
    idp.token_status = 500
    idp.token_body = {"error": "server_error", "error_description": "SECRET-DETAIL"}
    response = sign_in(client, idp)
    refused(response, "idp")
    assert "SECRET-DETAIL" not in response.headers["location"]


@pytest.mark.parametrize("body", ["<html>oops</html>", {"access_token": "at"}, {"id_token": ""}, '"just a string"'])
def test_a_token_answer_without_an_id_token_is_refused(client, idp, body):
    idp.token_body = body
    refused(sign_in(client, idp), "idp" if isinstance(body, str) else "token")


def test_a_discovery_document_for_another_issuer_is_refused(client, idp):
    idp.issuer_in_document = "https://evil.example/realms/cti"
    refused(client.get("/api/auth/oidc/login", follow_redirects=False), "idp")


def test_an_unreachable_identity_provider_is_refused(client, idp, monkeypatch):
    def down(request):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(oidc, "_TRANSPORT", httpx.MockTransport(down))
    refused(client.get("/api/auth/oidc/login", follow_redirects=False), "idp")


def test_requests_to_the_identity_provider_have_timeouts_and_follow_no_redirect():
    client = oidc._client()
    assert client.timeout.read is not None and client.timeout.connect is not None
    assert client.follow_redirects is False
    client.close()


# ── Who may sign in ──────────────────────────────────────────────────────────

def test_no_mapped_group_creates_no_account_and_no_session(client, idp):
    for groups in (["some-other-group"], [], None, "unmapped", [7, None]):
        refused(sign_in(client, idp, token_claims={"groups": groups}), "no_role")
    assert users() == []
    assert client.get("/api/auth/me").status_code == 401


def test_an_oidc_user_who_lost_every_group_is_refused_and_loses_open_sessions(client, idp):
    sign_in(client, idp)
    assert client.get("/api/auth/me").status_code == 200
    refused(sign_in(client, idp, token_claims={"groups": ["unmapped"]}), "no_role")
    assert client.get("/api/auth/me").status_code == 401                 # the earlier session is gone too


def test_a_disabled_user_is_refused(client, idp):
    sign_in(client, idp)
    store.set_disabled("alice")
    client.cookies.clear()
    refused(sign_in(client, idp), "disabled")
    assert client.get("/api/auth/me").status_code == 401


def test_a_disabled_user_is_refused_even_with_no_group(client, idp):
    sign_in(client, idp)
    store.set_disabled("alice")
    refused(sign_in(client, idp, token_claims={"groups": []}), "disabled")


# ── What the log may hold ────────────────────────────────────────────────────

def test_a_refusal_is_logged_without_a_token_a_code_or_the_secret(client, idp, caplog):
    caplog.set_level(logging.DEBUG)
    query = start(client)
    idp.id_token = idp.sign(idp.claims(query["nonce"], aud="someone-else"))
    client.get("/api/auth/oidc/callback", params={"code": "the-secret-code", "state": query["state"]},
               follow_redirects=False)
    # httpx2 is the test client's own logger, not the server's.
    text = "\n".join(record.getMessage() for record in caplog.records if record.name != "httpx2")
    assert "OIDC sign-in refused (token)" in text
    for secret in (idp.id_token, "the-secret-code", CLIENT_SECRET, query["state"], query["nonce"]):
        assert secret not in text


def test_a_login_refused_for_a_bad_configuration_goes_to_the_login_page(client, monkeypatch):
    monkeypatch.setenv("OIDC_CLIENT_SECRET_FILE", "/nonexistent/secret")
    start_response = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert start_response.status_code == 302                             # the secret is read at the callback
    query = parse_qs(urlsplit(start_response.headers["location"]).query)
    refused(client.get("/api/auth/oidc/callback", params={"code": "c", "state": query["state"][0]},
                       follow_redirects=False), "config")


def test_the_settings_are_read_when_used_so_a_bad_value_does_not_crash_a_request(client, monkeypatch):
    monkeypatch.setenv("OIDC_ROLE_MAP", "x=root")
    refused(client.get("/api/auth/oidc/login", follow_redirects=False), "config")
    assert isinstance(config.AuthConfigError("x"), RuntimeError)
