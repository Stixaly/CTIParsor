"""Users and tokens from the web interface: api/routes/admin.py (ADR-0097 items 14 and 15, part D),
and the store functions behind them."""
from __future__ import annotations

import pytest

from api.auth import store

from .conftest import AUTH_TEST_PASSWORD

GOOD = "another good password"


def _admin(make_user, sign_in, name: str = "root"):
    user = make_user("admin", name)
    return user, sign_in(user)


def _body(response):
    assert response.status_code < 300, response.text
    return response.json()


# ── Users ────────────────────────────────────────────────────────────────────

def test_the_user_list_has_no_hash_and_needs_an_admin(auth_client, make_user, sign_in):
    analyst = make_user("analyst", "ana")
    headers = sign_in(analyst)
    assert auth_client.get("/api/admin/users", headers=headers).status_code == 403
    _, headers = _admin(make_user, sign_in)
    users = _body(auth_client.get("/api/admin/users", headers=headers))
    assert {u["username"] for u in users} == {"ana", "root"}
    assert all("id" in u and u["auth_source"] == "local" for u in users)
    text = auth_client.get("/api/admin/users", headers=headers).text
    assert "hash" not in text and "argon2" not in text and AUTH_TEST_PASSWORD not in text


def test_create_a_user_who_can_then_sign_in(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    created = auth_client.post("/api/admin/users", headers=headers, json={
        "username": "Bob", "role": "analyst", "display_name": "Bob B.", "password": GOOD})
    assert created.status_code == 201
    body = created.json()
    assert body["username"] == "bob" and body["role"] == "analyst" and body["display_name"] == "Bob B."
    assert "password" not in created.text and GOOD not in created.text
    auth_client.cookies.clear()
    assert auth_client.post("/api/auth/login", json={"username": "bob", "password": GOOD}).status_code == 200


def test_create_refuses_a_taken_name_a_weak_password_a_bad_name_and_a_bad_role(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    ok = {"username": "carol", "role": "reader", "password": GOOD}
    assert auth_client.post("/api/admin/users", headers=headers, json=ok).status_code == 201
    assert auth_client.post("/api/admin/users", headers=headers, json=ok).status_code == 409
    assert auth_client.post("/api/admin/users", headers=headers, json={**ok, "username": "ROOT"}).status_code == 409
    weak = auth_client.post("/api/admin/users", headers=headers, json={**ok, "username": "dan", "password": "short"})
    assert weak.status_code == 400 and "at least" in weak.json()["detail"]
    assert "short" not in weak.text.replace("at least", "")
    assert auth_client.post("/api/admin/users", headers=headers, json={**ok, "username": "a b"}).status_code == 400
    assert auth_client.post("/api/admin/users", headers=headers, json={**ok, "username": "eve", "role": "root"}).status_code == 422  # noqa: E501


def test_create_is_refused_when_local_accounts_are_off(auth_client, make_user, sign_in, monkeypatch):
    _, headers = _admin(make_user, sign_in)
    monkeypatch.setenv("AUTH_MODE", "oidc")
    response = auth_client.post("/api/admin/users", headers=headers,
                                json={"username": "frank", "role": "reader", "password": GOOD})
    assert response.status_code == 400 and "Local accounts" in response.json()["detail"]


def test_change_a_role_and_a_display_name(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("reader", "rita")
    changed = _body(auth_client.patch(f"/api/admin/users/{target.id}", headers=headers,
                                      json={"role": "analyst", "display_name": "Rita R."}))
    assert changed["role"] == "analyst" and changed["display_name"] == "Rita R."
    assert store.get_user(target.id).role == "analyst"
    assert auth_client.patch(f"/api/admin/users/{target.id}", headers=headers, json={"role": "boss"}).status_code == 422
    assert auth_client.patch("/api/admin/users/nobody", headers=headers, json={"role": "reader"}).status_code == 404


def test_disabling_ends_the_sessions_and_revokes_no_token(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("analyst", "tina")
    token, token_id = store.create_token(target.id, "ci")
    store.create_session(target.id)                                       # a live session of tina's
    assert _body(auth_client.patch(f"/api/admin/users/{target.id}", headers=headers, json={"disabled": True}))["disabled"]  # noqa: E501
    with store.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_id=?", (target.id,)).fetchone()["n"] == 0
    assert store.find_token_user(token) is None                           # refused while disabled ...
    assert store.get_token(token_id)["revoked_at"] is None                # ... but not revoked
    _body(auth_client.patch(f"/api/admin/users/{target.id}", headers=headers, json={"disabled": False}))
    assert store.find_token_user(token) is not None                       # and good again


def test_an_admin_cannot_disable_or_demote_themself(auth_client, make_user, sign_in):
    me, headers = _admin(make_user, sign_in)
    make_user("admin", "second")
    for patch in ({"disabled": True}, {"role": "analyst"}):
        response = auth_client.patch(f"/api/admin/users/{me.id}", headers=headers, json=patch)
        assert response.status_code == 409, patch
    assert auth_client.patch(f"/api/admin/users/{me.id}", headers=headers,
                             json={"role": "admin", "display_name": "Me"}).status_code == 200


def test_the_last_enabled_admin_cannot_be_disabled_or_demoted(auth_client, make_user, sign_in):
    me, headers = _admin(make_user, sign_in)
    other = make_user("admin", "other")
    # `other` is not the caller: allowed while `me` stays, and then the last one cannot go.
    assert auth_client.patch(f"/api/admin/users/{other.id}", headers=headers, json={"disabled": True}).status_code == 200  # noqa: E501
    assert auth_client.patch(f"/api/admin/users/{other.id}", headers=headers, json={"disabled": False}).status_code == 200  # noqa: E501
    # Two admins signed in; the second removes the first's rights, then cannot be removed by itself.
    store.update_user(me.id, role="analyst")                              # the store leaves `other` as the only admin
    with pytest.raises(store.LastAdminError):
        store.update_user(other.id, disabled=True)
    with pytest.raises(store.LastAdminError):
        store.update_user(other.id, role="reader")
    assert store.update_user(other.id, display_name="Only admin").role == "admin"


def test_the_last_admin_rule_holds_in_the_route_for_another_caller(auth_client, make_user, sign_in):
    me, headers = _admin(make_user, sign_in)
    victim = make_user("admin", "victim")
    store.set_disabled(me.username)                                       # `me` is disabled behind the session: ...
    # ... the session is gone, so sign `victim` in and try to remove the only other admin.
    headers = sign_in(victim)
    assert auth_client.patch(f"/api/admin/users/{me.id}", headers=headers, json={"role": "reader"}).status_code == 200
    # `victim` is now the only enabled admin; the route refuses the self rule first, and the store the last-admin one.
    assert auth_client.patch(f"/api/admin/users/{victim.id}", headers=headers, json={"disabled": True}).status_code == 409  # noqa: E501


def test_set_a_password_ends_the_sessions_and_clears_the_lock(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("reader", "pat")
    store.create_session(target.id)
    for _ in range(store.LOCK_FAILURES):
        store.begin_attempt("pat")
    assert store.locked_until("pat") is not None
    response = auth_client.post(f"/api/admin/users/{target.id}/password", headers=headers, json={"password": GOOD})
    assert response.status_code == 200 and GOOD not in response.text
    assert store.locked_until("pat") is None
    with store.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE user_id=?", (target.id,)).fetchone()["n"] == 0
    auth_client.cookies.clear()
    assert auth_client.post("/api/auth/login", json={"username": "pat", "password": GOOD}).status_code == 200


def test_set_a_password_is_refused_for_a_weak_one_and_for_an_oidc_user(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("reader", "quinn")
    assert auth_client.post(f"/api/admin/users/{target.id}/password", headers=headers,
                            json={"password": "short"}).status_code == 400
    sso = store.create_user("sso-user", "reader", auth_source="oidc", oidc_subject="sub-9")
    refused = auth_client.post(f"/api/admin/users/{sso.id}/password", headers=headers, json={"password": GOOD})
    assert refused.status_code == 400
    assert auth_client.post("/api/admin/users/nobody/password", headers=headers,
                            json={"password": GOOD}).status_code == 404


# ── Tokens ───────────────────────────────────────────────────────────────────

def test_an_admin_creates_lists_and_revokes_a_token_for_a_user(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("analyst", "sam")
    created = auth_client.post("/api/admin/tokens", headers=headers,
                               json={"user_id": target.id, "name": "nightly", "days": 30})
    assert created.status_code == 201
    token = created.json()["token"]
    assert token.startswith("ctp_") and created.json()["username"] == "sam" and created.json()["name"] == "nightly"
    # the token works as sam ...
    me = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.json()["username"] == "sam"
    # ... is never listed again, in any field ...
    listed = auth_client.get("/api/admin/tokens", headers=headers)
    assert token not in listed.text and "token_hash" not in listed.text
    row = next(t for t in listed.json() if t["id"] == created.json()["id"])
    assert row["name"] == "nightly" and row["revoked_at"] is None and row["user_id"] == target.id
    # ... and is refused once revoked.
    assert auth_client.delete(f"/api/admin/tokens/{row['id']}", headers=headers).status_code == 200
    auth_client.cookies.clear()
    assert auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert auth_client.get("/api/admin/tokens", headers=_login(auth_client, "root")).json()[0]["revoked_at"]


def _login(client, username):
    client.cookies.clear()
    r = client.post("/api/auth/login", json={"username": username, "password": AUTH_TEST_PASSWORD})
    return {"X-CSRF-Token": r.json()["csrf_token"]}


def test_token_creation_checks_its_input(auth_client, make_user, sign_in):
    _, headers = _admin(make_user, sign_in)
    target = make_user("reader", "ted")
    ok = {"user_id": target.id, "name": "x"}
    assert auth_client.post("/api/admin/tokens", headers=headers, json=ok).status_code == 201     # 90 days by default
    for days in (0, 366, -1):
        assert auth_client.post("/api/admin/tokens", headers=headers, json={**ok, "days": days}).status_code == 422
    assert auth_client.post("/api/admin/tokens", headers=headers, json={**ok, "days": 365}).status_code == 201
    assert auth_client.post("/api/admin/tokens", headers=headers, json={**ok, "name": "  "}).status_code == 400
    assert auth_client.post("/api/admin/tokens", headers=headers, json={**ok, "user_id": "nobody"}).status_code == 404
    assert auth_client.delete("/api/admin/tokens/nobody", headers=headers).status_code == 404


def test_the_default_lifetime_is_ninety_days(auth_client, make_user, sign_in):
    from datetime import datetime, timezone
    _, headers = _admin(make_user, sign_in)
    target = make_user("reader", "una")
    body = _body(auth_client.post("/api/admin/tokens", headers=headers, json={"user_id": target.id, "name": "x"}))
    left = datetime.fromisoformat(body["expires_at"]) - datetime.now(timezone.utc)
    assert 89 <= left.days <= 90


def test_a_user_manages_only_their_own_tokens(auth_client, make_user, sign_in):
    alice, other = make_user("reader", "alice"), make_user("reader", "olga")
    other_token, other_id = store.create_token(other.id, "olga's")
    headers = sign_in(alice)
    created = _body(auth_client.post("/api/auth/tokens", headers=headers, json={"name": "mine", "days": 7}))
    assert created["token"].startswith("ctp_") and created["username"] == "alice"
    listed = auth_client.get("/api/auth/tokens", headers=headers)
    assert [t["name"] for t in listed.json()] == ["mine"]
    assert created["token"] not in listed.text and other_token not in listed.text
    # another user's token: 404, and it still works
    assert auth_client.delete(f"/api/auth/tokens/{other_id}", headers=headers).status_code == 404
    assert store.find_token_user(other_token) is not None
    assert auth_client.delete(f"/api/auth/tokens/{created['id']}", headers=headers).status_code == 200
    assert auth_client.delete(f"/api/auth/tokens/{created['id']}", headers=headers).status_code == 404   # already revoked  # noqa: E501
    assert auth_client.delete("/api/auth/tokens/nobody", headers=headers).status_code == 404


def test_the_admin_routes_are_not_open_to_a_token_holder_of_a_lower_role(auth_client, make_user):
    reader = make_user("reader", "ria")
    token, _ = store.create_token(reader.id, "ci")
    headers = {"Authorization": f"Bearer {token}"}
    assert auth_client.get("/api/admin/tokens", headers=headers).status_code == 403
    assert auth_client.get("/api/auth/tokens", headers=headers).status_code == 200


def test_a_write_needs_the_csrf_token(auth_client, make_user, sign_in):
    sign_in(make_user("admin", "root"))
    assert auth_client.post("/api/admin/users", json={"username": "x1", "role": "reader", "password": GOOD}).status_code == 403  # noqa: E501


def test_every_route_answers_404_with_authentication_off(temp_db_client):
    calls = [
        ("GET", "/api/admin/users", None), ("POST", "/api/admin/users", {"username": "a", "role": "reader", "password": GOOD}),  # noqa: E501
        ("PATCH", "/api/admin/users/x", {"role": "reader"}), ("POST", "/api/admin/users/x/password", {"password": GOOD}),  # noqa: E501
        ("GET", "/api/admin/tokens", None), ("POST", "/api/admin/tokens", {"user_id": "x", "name": "n"}),
        ("DELETE", "/api/admin/tokens/x", None), ("GET", "/api/auth/tokens", None),
        ("POST", "/api/auth/tokens", {"name": "n"}), ("DELETE", "/api/auth/tokens/x", None),
    ]
    for method, path, body in calls:
        response = temp_db_client.request(method, path, json=body)
        assert response.status_code == 404, (method, path, response.status_code)
        assert response.json()["detail"] == "Authentication is off"


# ── The store ────────────────────────────────────────────────────────────────

def test_list_tokens_can_be_limited_to_a_user_id_and_revoke_to_an_owner(temp_db, make_user):
    a, b = make_user("reader", "ann"), make_user("reader", "bea")
    _, ta = store.create_token(a.id, "a")
    _, tb = store.create_token(b.id, "b")
    assert [t["name"] for t in store.list_tokens(user_id=a.id)] == ["a"]
    assert {t["name"] for t in store.list_tokens()} == {"a", "b"}
    assert store.revoke_token(tb, user_id=a.id) is False
    assert store.revoke_token(tb, user_id=b.id) is True
    assert store.revoke_token(tb) is False
    assert store.get_token(ta)["username"] == "ann" and store.get_token("nobody") is None


def test_update_user_rejects_an_unknown_user_and_role(temp_db, make_user):
    user = make_user("reader", "uma")
    with pytest.raises(store.AuthError):
        store.update_user("nobody", role="reader")
    with pytest.raises(store.AuthError):
        store.update_user(user.id, role="boss")
    assert store.update_user(user.id, display_name="  ").display_name == "uma"
    assert store.user_record(user.id)["username"] == "uma" and store.user_record("nobody") is None


def test_a_token_cannot_create_another_token(auth_client, make_user):
    admin = make_user("admin", "tokenroot")
    token, _ = store.create_token(admin.id, "ci")
    headers = {"Authorization": f"Bearer {token}"}
    own = auth_client.post("/api/auth/tokens", headers=headers, json={"name": "child", "days": 365})
    assert own.status_code == 403 and "session" in own.json()["detail"]
    other = auth_client.post("/api/admin/tokens", headers=headers,
                             json={"user_id": admin.id, "name": "child", "days": 365})
    assert other.status_code == 403
    assert [t["name"] for t in store.list_tokens(user_id=admin.id)] == ["ci"]
    assert auth_client.get("/api/auth/tokens", headers=headers).status_code == 200   # reading stays open to it
