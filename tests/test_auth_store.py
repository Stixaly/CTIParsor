"""Hashing, the lockout, sessions and tokens at the store level (api/auth/store.py)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from api.auth import passwords, store

GOOD = "correct horse battery staple"


def _at(minutes_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(timespec="microseconds")


def _fail_at(db, username: str, *minutes_ago: float) -> None:
    with db.get_conn() as conn:
        for m in minutes_ago:
            conn.execute("INSERT INTO login_failures (username, attempted_at) VALUES (?,?)", (username, _at(m)))


# ── Passwords ────────────────────────────────────────────────────────────────

def test_passwords_are_argon2id_and_verified():
    hashed = passwords.hash_password(GOOD)
    assert hashed.startswith("$argon2id$") and GOOD not in hashed
    assert passwords.verify(GOOD, hashed)
    assert not passwords.verify(GOOD + "x", hashed)
    assert passwords.hash_password(GOOD) != hashed                       # a salt per hash


def test_a_missing_or_unreadable_hash_never_verifies():
    assert not passwords.verify(GOOD, None)
    assert not passwords.verify(GOOD, "")
    assert not passwords.verify(GOOD, "not a hash")
    assert not passwords.verify("not a password anyone has", None)       # not even the dummy's own password


def test_a_missing_hash_costs_a_real_verification(monkeypatch):
    calls = []
    real = passwords._hasher

    class Spy:
        def verify(self, stored, password):
            calls.append(stored)
            return real.verify(stored, password)

    monkeypatch.setattr(passwords, "_hasher", Spy())
    passwords.verify(GOOD, None)
    assert calls == [passwords.DUMMY_HASH]


def test_the_password_policy():
    with pytest.raises(ValueError, match="at least"):
        passwords.hash_password("short")
    with pytest.raises(ValueError, match="at most"):
        passwords.hash_password("x" * (passwords.MAX_LENGTH + 1))


# ── Accounts ─────────────────────────────────────────────────────────────────

def test_an_account_is_stored_with_a_hash_and_a_lower_case_username(temp_db):
    user = store.create_user("  Alice ", "analyst", password=GOOD)
    assert (user.username, user.role, user.auth_source, user.disabled) == ("alice", "analyst", "local", False)
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT password_hash FROM users").fetchone()
    assert row["password_hash"].startswith("$argon2id$")
    assert store.check_credentials("ALICE", GOOD).id == user.id
    assert store.check_credentials("alice", "wrong password here") is None
    assert store.check_credentials("nobody", GOOD) is None


@pytest.mark.parametrize("name", ["", " ", "a b", "-alice", "a/b", "x" * 65, "é"])
def test_a_bad_username_is_refused(temp_db, name):
    with pytest.raises(store.AuthError):
        store.create_user(name, "reader", password=GOOD)


def test_a_username_is_unique_and_a_role_must_exist(temp_db):
    store.create_user("alice", "reader", password=GOOD)
    with pytest.raises(store.AuthError, match="taken"):
        store.create_user("Alice", "admin", password=GOOD)
    with pytest.raises(store.AuthError, match="role"):
        store.create_user("bob", "root", password=GOOD)
    with pytest.raises(store.AuthError, match="password"):
        store.create_user("bob", "reader")
    with pytest.raises(store.AuthError, match="at least"):
        store.create_user("bob", "reader", password="short")


def test_has_role_follows_the_order(temp_db):
    admin = store.create_user("a", "admin", password=GOOD)
    reader = store.create_user("r", "reader", password=GOOD)
    assert all(admin.has_role(r) for r in ("reader", "analyst", "admin"))
    assert reader.has_role("reader") and not reader.has_role("analyst") and not reader.has_role("admin")


def test_set_password_ends_the_sessions_and_clears_the_lock(temp_db):
    user = store.create_user("alice", "reader", password=GOOD)
    session_id, _ = store.create_session(user.id)
    _fail_at(temp_db, "alice", 1, 1, 1, 1, 1)
    assert store.locked_until("alice")
    store.set_password("alice", "another long password")
    assert store.find_session(session_id) is None
    assert store.locked_until("alice") is None
    assert store.check_credentials("alice", GOOD) is None
    assert store.check_credentials("alice", "another long password")


def test_only_a_local_account_has_a_password(temp_db):
    store.create_user("sso", "reader", auth_source="oidc", oidc_subject="s-1")
    with pytest.raises(store.AuthError):
        store.set_password("sso", GOOD)
    with pytest.raises(store.AuthError):
        store.create_user("sso2", "reader", password=GOOD, auth_source="oidc")        # no subject
    with pytest.raises(store.AuthError):
        store.set_password("nobody", GOOD)


def test_admin_exists_ignores_a_disabled_admin(temp_db):
    assert not store.admin_exists()
    store.create_user("alice", "analyst", password=GOOD)
    assert not store.admin_exists()
    store.create_user("root", "admin", password=GOOD)
    assert store.admin_exists()
    store.set_disabled("root")
    assert not store.admin_exists()


# ── Lockout ──────────────────────────────────────────────────────────────────

def test_four_failures_do_not_lock_five_do(temp_db):
    _fail_at(temp_db, "alice", 5, 4, 3, 2)
    assert store.locked_until("alice") is None
    _fail_at(temp_db, "alice", 1)
    until = store.locked_until("alice")
    assert until is not None and timedelta(minutes=13) < until - datetime.now(timezone.utc) <= timedelta(minutes=15)


def test_the_lock_lasts_fifteen_minutes_from_the_fifth_failure(temp_db):
    _fail_at(temp_db, "alice", 14, 13, 12, 11, 10)         # the fifth was 10 minutes ago: 5 minutes left
    until = store.locked_until("alice")
    assert until is not None
    assert timedelta(minutes=4) < until - datetime.now(timezone.utc) < timedelta(minutes=6)
    _fail_at(temp_db, "bob", 29, 28, 27, 26, 16)           # the fifth failure was 16 minutes ago: over
    assert store.locked_until("bob") is None


def test_failures_spread_over_more_than_the_window_do_not_lock(temp_db):
    _fail_at(temp_db, "alice", 28, 24, 20, 16, 12)         # five in 16 minutes
    assert store.locked_until("alice") is None
    _fail_at(temp_db, "alice", 8)                          # 24 / 20 / 16 / 12 / 8: five in 16 minutes again
    assert store.locked_until("alice") is None


def test_the_lock_is_per_username_and_not_case_sensitive(temp_db):
    store.record_failure("Alice")
    _fail_at(temp_db, "alice", 1, 1, 1, 1)
    assert store.locked_until("ALICE")
    assert store.locked_until("bob") is None


def test_clear_failures_and_the_purge_of_old_rows(temp_db):
    _fail_at(temp_db, "alice", 1, 1, 1, 1, 1, 45)
    store.clear_failures("alice")
    assert store.locked_until("alice") is None
    _fail_at(temp_db, "bob", 45)
    store.record_failure("carol")
    with temp_db.get_conn() as conn:
        assert [r["username"] for r in conn.execute("SELECT username FROM login_failures").fetchall()] == ["carol"]


# ── Sessions ─────────────────────────────────────────────────────────────────

def test_a_session_is_found_by_its_id_and_only_the_hash_is_kept(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    session_id, session = store.create_session(user.id)
    found = store.find_session(session_id)
    assert found is not None and found.user.id == user.id and found.csrf_token == session.csrf_token
    assert store.find_session(session_id + "x") is None and store.find_session("") is None
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT id_hash, csrf_token FROM sessions").fetchone()
    assert row["id_hash"] == hashlib.sha256(session_id.encode()).hexdigest()
    assert session_id not in row["id_hash"]
    assert len(session_id) >= 43                                        # 32 random bytes


def test_a_session_expires_after_the_configured_time(temp_db, monkeypatch):
    monkeypatch.setenv("SESSION_TTL_HOURS", "1")
    user = store.create_user("alice", "analyst", password=GOOD)
    session_id, session = store.create_session(user.id)
    assert timedelta(minutes=59) < session.expires_at - datetime.now(timezone.utc) <= timedelta(hours=1)
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE sessions SET expires_at=?", (_at(1),))
    assert store.find_session(session_id) is None


def test_two_sessions_have_different_ids_and_csrf_tokens(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    (id1, s1), (id2, s2) = store.create_session(user.id), store.create_session(user.id)
    assert id1 != id2 and s1.csrf_token != s2.csrf_token


def test_the_csrf_check_is_exact(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    _, session = store.create_session(user.id)
    assert store.csrf_matches(session, session.csrf_token)
    assert not store.csrf_matches(session, None) and not store.csrf_matches(session, "")
    assert not store.csrf_matches(session, session.csrf_token + "x")


# ── Tokens ───────────────────────────────────────────────────────────────────

def test_a_token_has_a_prefix_a_name_and_ninety_days_by_default(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    token, token_id = store.create_token(user.id, "  ci  ")
    assert token.startswith("ctp_") and len(token) > 40
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT name, token_hash, expires_at, created_at, revoked_at FROM api_tokens "
                           "WHERE id=?", (token_id,)).fetchone()
    assert row["name"] == "ci" and row["revoked_at"] is None
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(row["created_at"]) == timedelta(days=90)
    assert store.find_token_user(token).id == user.id


def test_a_token_can_be_given_a_lifetime_and_must_have_a_name(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    _, token_id = store.create_token(user.id, "short", days=7)
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT expires_at, created_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()
    assert datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(row["created_at"]) == timedelta(days=7)
    for bad in ({"name": ""}, {"name": "  "}, {"name": "n", "days": 0}, {"name": "n" * 129}):
        with pytest.raises(store.AuthError):
            store.create_token(user.id, **bad)
    with pytest.raises(store.AuthError):
        store.create_token("missing", "x")


def test_a_revoked_token_is_refused_and_a_second_revoke_says_so(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    token, token_id = store.create_token(user.id, "ci")
    assert store.revoke_token(token_id) is True
    assert store.revoke_token(token_id) is False
    assert store.find_token_user(token) is None


def test_the_last_use_is_recorded(temp_db):
    user = store.create_user("alice", "analyst", password=GOOD)
    token, token_id = store.create_token(user.id, "ci")
    store.find_token_user(token)
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT last_used_at FROM api_tokens WHERE id=?", (token_id,)).fetchone()["last_used_at"]
