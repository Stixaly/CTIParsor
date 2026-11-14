"""Regression tests for the authentication bugs of issues #740 to #744.

#740 a concurrent create of the same username is a 409, not a 500; #741 a time out of range is a 400;
#742 a logout keeps its cookie deletion when the session was slid; #743 an absurd session lifetime is
refused at start-up; #744 a malformed OIDC URL is an AuthConfigError.  (#745 is not here: see the report.)
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from api.auth import config, store
from api.auth.config import AuthConfigError

from .conftest import AUTH_TEST_PASSWORD


def _past(minutes: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="microseconds")


def _cursor(value) -> str:
    """A cursor as api/audit.py writes one, for an arbitrary decoded value."""
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _Nothing:
    def fetchone(self):
        return None


class _Blind:
    """A connection that does not see an account that already exists: the first SELECT of two
    concurrent creates of the same name (#740).  Every other statement is the real one."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        if sql.startswith("SELECT 1 FROM users"):
            return _Nothing()
        return self._conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


# ── #740: a username taken between the check and the insert ─────────────────

def test_a_username_taken_by_a_concurrent_create_is_a_409_740(auth_client, make_user, sign_in, monkeypatch):
    headers = sign_in(make_user("admin", "root"))
    store.create_user("bob", "reader", password=AUTH_TEST_PASSWORD)
    real_get_conn = store.get_conn
    monkeypatch.setattr(store, "get_conn", lambda: _Blind(real_get_conn()))
    response = auth_client.post("/api/admin/users", headers=headers,
                                json={"username": "bob", "role": "reader", "password": AUTH_TEST_PASSWORD})
    assert response.status_code == 409, response.text


def test_a_concurrent_create_with_a_taken_name_raises_username_taken_740(temp_db, monkeypatch):
    store.create_user("bob", "reader", password=AUTH_TEST_PASSWORD)
    real_get_conn = store.get_conn
    monkeypatch.setattr(store, "get_conn", lambda: _Blind(real_get_conn()))
    with pytest.raises(store.UsernameTakenError):
        store.create_user("bob", "reader", password=AUTH_TEST_PASSWORD)


def test_a_taken_oidc_subject_is_still_a_database_error_740(temp_db, monkeypatch):
    # The OIDC callback catches this one itself (api/auth/oidc.py): it must not turn into a name clash.
    store.create_user("ana", "reader", auth_source="oidc", oidc_subject="subject-1")
    real_get_conn = store.get_conn
    monkeypatch.setattr(store, "get_conn", lambda: _Blind(real_get_conn()))
    with pytest.raises(psycopg.errors.UniqueViolation):
        store.create_user("ana-2", "reader", auth_source="oidc", oidc_subject="subject-1")


# ── #741: a time that the UTC conversion cannot hold ────────────────────────

_OUT_OF_RANGE = [
    {"since": "9999-12-31T23:00:00-02:00"},
    {"until": "0001-01-01T00:00:00+02:00"},
    {"cursor": _cursor(["9999-12-31T23:00:00-02:00", 1])},
]


@pytest.mark.parametrize("params", _OUT_OF_RANGE, ids=["since", "until", "cursor"])
def test_a_time_out_of_range_is_a_400_741(auth_client, make_user, sign_in, temp_db, params):
    headers = sign_in(make_user("admin"))
    response = auth_client.get("/api/audit", params=params, headers=headers)
    assert response.status_code == 400, response.text


# ── #742: a logout whose session was slid keeps its cookie deletion ─────────

def test_a_logout_after_a_slide_clears_the_cookie_once_742(auth_client, make_user, temp_db):
    user = make_user("reader")
    csrf = auth_client.post("/api/auth/login", json={"username": user.username,
                                                     "password": AUTH_TEST_PASSWORD}).json()["csrf_token"]
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE sessions SET last_seen_at=?", (_past(2),))
    response = auth_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    session_cookies = [v for v in response.headers.get_list("set-cookie") if v.startswith("ctiparsor_session=")]
    assert len(session_cookies) == 1, session_cookies
    assert "max-age=0" in session_cookies[0].lower()


# ── #743: a session lifetime the clock cannot hold ──────────────────────────

@pytest.mark.parametrize("value", ["1e9", "1e-4"])
def test_an_absurd_session_lifetime_is_refused_at_start_up_743(monkeypatch, value):
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("SESSION_TTL_HOURS", value)
    with pytest.raises(AuthConfigError, match="SESSION_TTL_HOURS"):
        config.check_startup("127.0.0.1")


def test_a_session_lifetime_at_the_bounds_is_accepted_743(monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "local")
    monkeypatch.setenv("SESSION_TTL_HOURS", "87600")
    config.check_startup("127.0.0.1")


# ── #744: a malformed URL is a configuration error ──────────────────────────

def test_a_malformed_ipv6_url_is_an_auth_config_error_744():
    with pytest.raises(AuthConfigError):
        config._secure_url("X", "https://[")


def test_a_malformed_ipv6_url_is_not_secure_744():
    assert config.is_secure_url("https://[") is False
