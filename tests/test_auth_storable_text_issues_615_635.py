"""NUL bytes and lone UTF-16 surrogates in the auth and admin inputs answer 4xx, never 500 (#615, #616, #633,
#634, #635).  PostgreSQL refuses both in a text field; the routes refuse them before the database sees them."""
# ruff: noqa: F811 - client and idp are the fixtures of tests/test_auth_oidc.py, used as arguments here
from __future__ import annotations

import pytest

from api.auth import config, oidc, store

from .conftest import AUTH_TEST_PASSWORD
from .test_auth_oidc import client, idp, refused  # noqa: F401 - pytest fixtures, used as arguments below
from .test_auth_oidc import sign_in as oidc_sign_in

GOOD = "another good password"
NUL = r"a\u0000b"            # the JSON escapes, sent as text: a NUL byte, a lone surrogate
SURROGATE = r"a\ud800b"


def _post(client_, url: str, body: str, headers: dict | None = None):
    return client_.post(url, content=("{" + body + "}").encode("ascii"),
                        headers={**(headers or {}), "content-type": "application/json"})


def _send(client_, method: str, url: str, body: str, headers: dict):
    return client_.request(method, url, content=("{" + body + "}").encode("ascii"),
                           headers={**headers, "content-type": "application/json"})


def _admin(make_user, sign_in):
    admin = make_user("admin", "root")
    return sign_in(admin)


# ── #615 Sign-in ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("body", [
    f'"username": "{NUL}", "password": "x"',                   # a NUL in the username
    f'"username": "{SURROGATE}", "password": "x"',             # a lone surrogate in the username
    f'"username": "root", "password": "{SURROGATE}"',          # a lone surrogate in the password
    f'"username": "{NUL}", "password": "{SURROGATE}"',
])
def test_a_sign_in_with_a_nul_or_a_surrogate_is_a_401_not_a_500(auth_client, make_user, body):
    make_user("admin", "root")
    response = _post(auth_client, "/api/auth/login", body)
    assert response.status_code == 401, response.text
    assert response.json() == {"detail": "Invalid username or password"}


def test_the_answer_to_a_bad_username_is_the_one_for_a_wrong_password(auth_client, make_user):
    make_user("admin", "root")
    wrong = auth_client.post("/api/auth/login", json={"username": "root", "password": "not the one"})
    bad_name = _post(auth_client, "/api/auth/login", f'"username": "{SURROGATE}", "password": "x"')
    assert (wrong.status_code, wrong.json()) == (bad_name.status_code, bad_name.json())


def test_a_nul_in_the_password_is_still_a_plain_wrong_password(auth_client, make_user):
    make_user("admin", "root")
    response = _post(auth_client, "/api/auth/login", f'"username": "root", "password": "{NUL}"')
    assert response.status_code == 401 and response.json()["detail"] == "Invalid username or password"


def test_a_surrogate_password_counts_as_a_failure_for_the_lockout(auth_client, make_user):
    make_user("admin", "root")
    for _ in range(store.LOCK_FAILURES):
        response = _post(auth_client, "/api/auth/login", f'"username": "root", "password": "{SURROGATE}"')
        assert response.status_code == 401
    assert store.locked_until("root") is not None
    locked = auth_client.post("/api/auth/login", json={"username": "root", "password": AUTH_TEST_PASSWORD})
    assert locked.status_code == 429 and "Retry-After" in locked.headers


def test_a_good_sign_in_still_works_after_the_refusals(auth_client, make_user):
    make_user("admin", "root")
    _post(auth_client, "/api/auth/login", f'"username": "{SURROGATE}", "password": "x"')
    response = auth_client.post("/api/auth/login", json={"username": "root", "password": AUTH_TEST_PASSWORD})
    assert response.status_code == 200 and response.json()["username"] == "root"


# ── #616 / #633 / #634 Own and admin tokens, users ───────────────────────────

@pytest.mark.parametrize("name", [NUL, SURROGATE])
def test_an_own_token_with_a_bad_name_is_a_422(auth_client, make_user, sign_in, name):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/auth/tokens", f'"name": "{name}", "days": 5', headers)
    assert response.status_code == 422, response.text
    assert store.list_tokens() == []


@pytest.mark.parametrize("name", [NUL, SURROGATE])
def test_an_admin_token_with_a_bad_name_is_a_422(auth_client, make_user, sign_in, name):
    headers = _admin(make_user, sign_in)
    target = make_user("reader", "rita")
    response = _post(auth_client, "/api/admin/tokens", f'"user_id": "{target.id}", "name": "{name}", "days": 5',
                     headers)
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("user_id", [NUL, SURROGATE])
def test_an_admin_token_for_a_bad_user_id_is_a_422_not_a_500(auth_client, make_user, sign_in, user_id):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/admin/tokens", f'"user_id": "{user_id}", "name": "tok", "days": 5', headers)
    assert response.status_code == 422, response.text
    assert store.list_tokens() == []


def test_a_good_token_name_still_makes_a_token(auth_client, make_user, sign_in):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/auth/tokens", '"name": "ci-run", "days": 5', headers)
    assert response.status_code == 201 and response.json()["token"].startswith("ctp_")


@pytest.mark.parametrize("username", [NUL, SURROGATE])
def test_an_admin_creates_no_user_with_a_bad_username(auth_client, make_user, sign_in, username):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/admin/users", f'"username": "{username}", "role": "reader", '
                     '"password": "xxxxxxxxxxxx"', headers)
    assert response.status_code == 400, response.text
    assert [u["username"] for u in store.list_users()] == ["root"]


@pytest.mark.parametrize("display", [NUL, SURROGATE])
def test_an_admin_creates_no_user_with_a_bad_display_name(auth_client, make_user, sign_in, display):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/admin/users", f'"username": "newanalyst", "role": "analyst", '
                     f'"password": "{GOOD}", "display_name": "Test{display}"', headers)
    assert response.status_code == 422, response.text
    assert [u["username"] for u in store.list_users()] == ["root"]


@pytest.mark.parametrize("display", [NUL, SURROGATE])
def test_an_admin_patch_with_a_bad_display_name_is_a_422(auth_client, make_user, sign_in, display):
    headers = _admin(make_user, sign_in)
    target = make_user("reader", "rita")
    response = _send(auth_client, "PATCH", f"/api/admin/users/{target.id}", f'"display_name": "{display}"', headers)
    assert response.status_code == 422, response.text
    assert store.get_user(target.id).display_name == "rita"


def test_a_surrogate_password_for_a_new_user_is_a_400(auth_client, make_user, sign_in):
    headers = _admin(make_user, sign_in)
    response = _post(auth_client, "/api/admin/users", f'"username": "newy", "role": "reader", '
                     f'"password": "xxxxxxxx{SURROGATE}xxxx"', headers)
    assert response.status_code == 400, response.text


def test_a_surrogate_password_for_an_existing_user_is_a_400(auth_client, make_user, sign_in):
    headers = _admin(make_user, sign_in)
    target = make_user("reader", "rita")
    response = _send(auth_client, "POST", f"/api/admin/users/{target.id}/password",
                     f'"password": "xxxxxxxx{SURROGATE}xxxx"', headers)
    assert response.status_code == 400, response.text


# ── #635 OIDC account ────────────────────────────────────────────────────────

def _settings() -> config.OidcSettings:
    return config.oidc_settings()


def test_a_nul_in_the_name_claim_is_dropped_from_the_display_name(client, idp):
    response = oidc_sign_in(client, idp, token_claims={"name": "Al\x00ice"})
    assert response.status_code == 302 and response.headers["location"] == "/"
    assert store.find_user("alice").display_name == "Alice"


def test_a_lone_surrogate_in_the_name_claim_is_dropped_from_the_display_name(client, idp):
    oidc_sign_in(client, idp, token_claims={"name": "Bob\ud800"})
    assert store.find_user("alice").display_name == "Bob"


def test_account_provisioning_does_not_raise_on_a_nul_or_surrogate_name(client, idp, temp_db):
    claims = {"sub": "user1", "groups": ["cti-analysts"], "name": "User\x00Name"}
    user = oidc._account(_settings(), claims)
    assert user.display_name == "UserName"


def test_an_unexpected_failure_to_create_the_account_is_an_account_refusal(client, idp, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("the database said no")

    monkeypatch.setattr(store, "create_user", broken)
    response = oidc_sign_in(client, idp)
    refused(response, "account")


def test_a_nul_in_the_subject_is_refused_as_a_token_problem(client, idp):
    response = oidc_sign_in(client, idp, token_claims={"sub": "sub\x00-1"})
    refused(response, "token")
