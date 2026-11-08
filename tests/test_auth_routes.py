"""Sign-in, sessions, CSRF, bearer tokens, roles on real routes, the delete rule and
the owner of an import (ADR-0097 items 14 and 15).  The permission table itself is
in test_auth_permissions.py, the accounts and secrets in test_auth_store.py."""
from __future__ import annotations

import hashlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.auth import store
from pipeline import web_capture

from .conftest import AUTH_TEST_PASSWORD

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
_TEXT = "APT29 deployed SUNBURST against SolarWinds targets and contacted 185.220.101.45 for command and control."


def _login(client, username: str, password: str = AUTH_TEST_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def _past(days: float = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="microseconds")


def _insert_job(db, job_id: str, imported_by: str | None) -> None:
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, imported_by, created_at, updated_at) "
                     "VALUES (?,?,?,?,?,?)", (job_id, "r.txt", "completed", imported_by, "t", "t"))


def _job_exists(db, job_id: str) -> bool:
    with db.get_conn() as conn:
        return conn.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone() is not None


# ── Sign-in and the cookie ───────────────────────────────────────────────────

def test_a_sign_in_sets_a_hardened_session_cookie(auth_client, make_user):
    user = make_user("analyst")
    response = _login(auth_client, user.username)
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == user.username and body["role"] == "analyst" and body["auth_source"] == "local"
    assert body["auth_mode"] == "local" and body["csrf_token"]
    cookie = response.headers["set-cookie"]
    flags = {part.strip().lower() for part in cookie.split(";")}
    assert cookie.startswith("ctiparsor_session=")
    assert {"httponly", "secure", "samesite=strict", "path=/", "max-age=43200"} <= flags


def test_the_cookie_is_not_secure_only_for_plain_http_from_loopback(temp_db, make_user, monkeypatch):
    import api.main

    monkeypatch.setenv("AUTH_MODE", "local")
    user = make_user("reader")
    with patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app, base_url="http://testserver", client=("127.0.0.1", 50000)) as local:
            assert "secure" not in _login(local, user.username).headers["set-cookie"].lower()
        with TestClient(api.main.app, base_url="http://testserver", client=("192.168.1.20", 50000)) as lan:
            assert "secure" in _login(lan, user.username).headers["set-cookie"].lower()
        with TestClient(api.main.app, base_url="https://testserver", client=("127.0.0.1", 50000)) as tls:
            assert "secure" in _login(tls, user.username).headers["set-cookie"].lower()


def test_the_session_lifetime_follows_session_ttl_hours(auth_client, make_user, monkeypatch):
    monkeypatch.setenv("SESSION_TTL_HOURS", "2")
    response = _login(auth_client, make_user("reader").username)
    assert "max-age=7200" in response.headers["set-cookie"].lower()


def test_the_database_keeps_the_hash_of_the_session_id_not_the_id(auth_client, make_user, temp_db):
    _login(auth_client, make_user("reader").username)
    session_id = auth_client.cookies.get("ctiparsor_session")
    with temp_db.get_conn() as conn:
        stored = [r["id_hash"] for r in conn.execute("SELECT id_hash FROM sessions").fetchall()]
    assert stored == [hashlib.sha256(session_id.encode()).hexdigest()]
    assert session_id not in stored


def test_a_wrong_password_and_an_unknown_user_get_the_same_answer(auth_client, make_user):
    user = make_user("reader")
    wrong = _login(auth_client, user.username, "not the password at all")
    unknown = _login(auth_client, "nobody-here")
    assert (wrong.status_code, wrong.json()) == (unknown.status_code, unknown.json())
    assert wrong.status_code == 401
    assert "set-cookie" not in wrong.headers


def test_a_disabled_account_and_an_oidc_account_cannot_sign_in(auth_client, make_user):
    user = make_user("reader")
    store.set_disabled(user.username)
    assert _login(auth_client, user.username).status_code == 401
    store.create_user("sso-user", "reader", auth_source="oidc", oidc_subject="sub-1")
    assert _login(auth_client, "sso-user", AUTH_TEST_PASSWORD).status_code == 401


def test_five_failures_lock_the_username_for_fifteen_minutes(auth_client, make_user, temp_db):
    user = make_user("reader")
    for _ in range(4):
        assert _login(auth_client, user.username, "wrong password here").status_code == 401
    assert _login(auth_client, user.username, "wrong password here").status_code == 401   # the fifth
    locked = _login(auth_client, user.username)                     # the right password is refused too
    assert locked.status_code == 429
    assert 0 < int(locked.headers["retry-after"]) <= 15 * 60
    assert _login(auth_client, make_user("reader").username).status_code == 200            # another username
    # Fifteen minutes after the last failure the lock is over.
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE login_failures SET attempted_at=?", (_past(0.02),))
    assert _login(auth_client, user.username).status_code == 200


def test_an_unknown_username_is_locked_the_same_way(auth_client):
    for _ in range(5):
        assert _login(auth_client, "ghost").status_code == 401
    assert _login(auth_client, "ghost").status_code == 429


def test_a_good_sign_in_clears_the_failures(auth_client, make_user):
    user = make_user("reader")
    for _ in range(4):
        _login(auth_client, user.username, "wrong password here")
    assert _login(auth_client, user.username).status_code == 200
    for _ in range(4):
        assert _login(auth_client, user.username, "wrong password here").status_code == 401


# ── Who am I, sign-out ───────────────────────────────────────────────────────

def test_me_needs_a_session_and_returns_the_csrf_token(auth_client, make_user):
    assert auth_client.get("/api/auth/me").status_code == 401
    user = make_user("admin")
    csrf = _login(auth_client, user.username).json()["csrf_token"]
    me = auth_client.get("/api/auth/me").json()
    assert me == {"auth_mode": "local", "username": user.username, "display_name": user.username,
                  "role": "admin", "auth_source": "local", "csrf_token": csrf}


def test_a_sign_out_ends_the_session(auth_client, make_user, temp_db):
    user = make_user("reader")
    csrf = _login(auth_client, user.username).json()["csrf_token"]
    cookie = auth_client.cookies.get("ctiparsor_session")
    assert auth_client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).json() == {"signed_out": True}
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"] == 0
    auth_client.cookies.set("ctiparsor_session", cookie)              # a copy of the cookie signs nobody in
    assert auth_client.get("/api/auth/me").status_code == 401


def test_a_session_expires_and_slides_while_used(auth_client, make_user, temp_db):
    user = make_user("reader")
    _login(auth_client, user.username)
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE sessions SET last_seen_at=?, expires_at=?",
                     (_past(0.5), (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(timespec="microseconds")))
    assert auth_client.get("/api/auth/me").status_code == 200
    with temp_db.get_conn() as conn:
        expires = datetime.fromisoformat(conn.execute("SELECT expires_at FROM sessions").fetchone()["expires_at"])
    assert expires > datetime.now(timezone.utc) + timedelta(hours=11)       # pushed out to 12 h again
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE sessions SET expires_at=?", (_past(0.01),))
    assert auth_client.get("/api/auth/me").status_code == 401


def test_a_disabled_user_loses_the_session_at_once(auth_client, make_user):
    user = make_user("reader")
    _login(auth_client, user.username)
    assert auth_client.get("/api/jobs").status_code == 200
    store.set_disabled(user.username)
    assert auth_client.get("/api/jobs").status_code == 401


def test_sign_in_is_unavailable_with_authentication_off(temp_db_client):
    assert _login(temp_db_client, "anyone").status_code == 404


def test_local_sign_in_is_unavailable_with_oidc_only(auth_client, monkeypatch):
    monkeypatch.setenv("AUTH_MODE", "oidc")
    assert _login(auth_client, "anyone").status_code == 403


# ── CSRF and bearer tokens ───────────────────────────────────────────────────

def test_a_state_changing_request_with_the_cookie_needs_the_csrf_token(auth_client, make_user):
    csrf = _login(auth_client, make_user("analyst").username).json()["csrf_token"]
    assert auth_client.delete("/api/jobs/missing").status_code == 403
    assert auth_client.delete("/api/jobs/missing", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert auth_client.delete("/api/jobs/missing", headers={"X-CSRF-Token": csrf}).status_code == 404   # it got through
    assert auth_client.get("/api/jobs").status_code == 200                                      # a read needs none


def test_the_csrf_token_of_another_session_is_refused(auth_client, make_user):
    other = _login(auth_client, make_user("analyst").username).json()["csrf_token"]
    _login(auth_client, make_user("analyst").username)
    assert auth_client.delete("/api/jobs/missing", headers={"X-CSRF-Token": other}).status_code == 403


def test_a_bearer_token_needs_no_csrf_token(auth_client, make_user):
    user = make_user("analyst")
    token, _ = store.create_token(user.id, "ci")
    assert token.startswith("ctp_")
    assert auth_client.delete("/api/jobs/missing", headers={"Authorization": f"Bearer {token}"}).status_code == 404
    me = auth_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["username"] == user.username and me["csrf_token"] is None


def test_the_database_keeps_the_hash_of_the_token_not_the_token(auth_client, make_user, temp_db):
    token, _ = store.create_token(make_user("reader").id, "ci")
    with temp_db.get_conn() as conn:
        row = conn.execute("SELECT token_hash, expires_at, created_at FROM api_tokens").fetchone()
    assert row["token_hash"] == hashlib.sha256(token.encode()).hexdigest() != token
    days = (datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(row["created_at"])).days
    assert days == 90                                                   # the default lifetime


def test_an_expired_revoked_unknown_or_malformed_token_is_401(auth_client, make_user, temp_db):
    user = make_user("reader")
    live, _ = store.create_token(user.id, "live")
    expired, expired_id = store.create_token(user.id, "expired")
    revoked, revoked_id = store.create_token(user.id, "revoked")
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE api_tokens SET expires_at=? WHERE id=?", (_past(), expired_id))
    assert store.revoke_token(revoked_id)

    def status(authorization: str) -> int:
        return auth_client.get("/api/jobs", headers={"Authorization": authorization}).status_code

    assert status(f"Bearer {live}") == 200
    assert status(f"Bearer {expired}") == 401
    assert status(f"Bearer {revoked}") == 401
    assert status("Bearer ctp_not-a-token") == 401
    assert status("Bearer not-a-ctp-token") == 401
    assert status("Basic dXNlcjpwYXNz") == 401
    assert status("Bearer") == 401


def test_a_refused_bearer_token_is_not_retried_as_the_cookie(auth_client, make_user):
    _login(auth_client, make_user("reader").username)
    assert auth_client.get("/api/jobs", headers={"Authorization": "Bearer ctp_wrong"}).status_code == 401


def test_a_disabled_user_loses_the_tokens(auth_client, make_user):
    user = make_user("reader")
    token, _ = store.create_token(user.id, "ci")
    store.set_disabled(user.username)
    assert auth_client.get("/api/jobs", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    store.set_disabled(user.username, disabled=False)
    assert auth_client.get("/api/jobs", headers={"Authorization": f"Bearer {token}"}).status_code == 200


# ── Roles on real routes ─────────────────────────────────────────────────────

def test_each_role_reaches_what_it_may_and_not_more(auth_client, make_user, sign_in):
    # (method, path, minimum role)
    probes = [("GET", "/api/jobs", "reader"), ("DELETE", "/api/jobs/missing", "analyst"),
              ("GET", "/api/settings/formats", "admin")]
    ranks = {"reader": 0, "analyst": 1, "admin": 2}
    for role in ranks:
        headers = sign_in(make_user(role))
        for method, path, minimum in probes:
            status = auth_client.request(method, path, headers=headers).status_code
            allowed = ranks[role] >= ranks[minimum]
            assert (status == 403) is (not allowed), (role, method, path, status)


def test_no_credentials_is_401_but_health_stays_open(auth_client):
    assert auth_client.get("/api/jobs").status_code == 401
    assert auth_client.get("/api/health").status_code == 200


# ── The delete rule ──────────────────────────────────────────────────────────

def test_an_analyst_deletes_their_own_import_and_no_one_elses(auth_client, make_user, sign_in, temp_db):
    alice, bob = make_user("analyst"), make_user("analyst")
    for job_id, owner in (("mine", alice.id), ("his", bob.id), ("nobody", None)):
        _insert_job(temp_db, job_id, owner)
    headers = sign_in(alice)

    assert auth_client.delete("/api/jobs/his", headers=headers).status_code == 403
    assert auth_client.delete("/api/jobs/nobody", headers=headers).status_code == 403
    assert auth_client.delete("/api/jobs/missing", headers=headers).status_code == 404
    assert auth_client.delete("/api/jobs/mine", headers=headers).json() == {"deleted": "mine"}
    assert _job_exists(temp_db, "his") and _job_exists(temp_db, "nobody") and not _job_exists(temp_db, "mine")


def test_an_admin_deletes_any_report_including_one_without_an_owner(auth_client, make_user, sign_in, temp_db):
    analyst = make_user("analyst")
    for job_id, owner in (("his", analyst.id), ("nobody", None)):
        _insert_job(temp_db, job_id, owner)
    headers = sign_in(make_user("admin"))
    assert auth_client.delete("/api/jobs/his", headers=headers).status_code == 200
    assert auth_client.delete("/api/jobs/nobody", headers=headers).status_code == 200
    assert not _job_exists(temp_db, "his") and not _job_exists(temp_db, "nobody")


def test_with_authentication_off_any_report_can_be_deleted_as_before(temp_db_client, temp_db):
    _insert_job(temp_db, "nobody", None)
    assert temp_db_client.delete("/api/jobs/nobody").status_code == 200


# ── Who imported a report ────────────────────────────────────────────────────

@pytest.fixture()
def importing(auth_client, temp_db, monkeypatch):
    """The client with the worker stubbed; imported_by(job_id) reads the owner back."""
    import api.main

    api.main.limiter.reset()
    monkeypatch.setenv("STIX_ENRICHMENT_ENABLED", "1")
    with patch("api.worker.run_pipeline_async", return_value="started"):
        def imported_by(job_id: str):
            with temp_db.get_conn() as conn:
                return conn.execute("SELECT imported_by, pipeline_mode FROM jobs WHERE id=?", (job_id,)).fetchone()

        auth_client.imported_by = imported_by           # type: ignore[attr-defined]
        yield auth_client


def _fake_capture(monkeypatch):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(web_capture, "validate_url", lambda u: u)

    def fake(url, dest, **kwargs):
        dest.write_bytes(b"%PDF-1.4 fake")
        return web_capture.CaptureResult(pdf_path=dest, final_url=url, title="Report", bytes_written=13,
                                         js_enabled=False, blocked_requests=0, rendered_chars=len(_TEXT),
                                         dom_text=_TEXT)

    monkeypatch.setattr(web_capture, "capture_url_to_pdf", fake)


def test_every_way_to_import_a_report_records_the_user(importing, make_user, sign_in, monkeypatch):
    user = make_user("analyst")
    headers = sign_in(user)
    _fake_capture(monkeypatch)
    baseline = (BASELINES / "opencti_report.json").read_bytes()

    upload = importing.post("/api/upload", headers=headers,
                            files={"file": ("report.txt", io.BytesIO(_TEXT.encode()), "text/plain")})
    text = importing.post("/api/ingest/text", headers=headers, json={"text": _TEXT})
    url = importing.post("/api/ingest/url", headers=headers, json={"url": "https://example.com/report"})
    enrich = importing.post("/api/upload", headers=headers, files={
        "file": ("report.txt", io.BytesIO(_TEXT.encode()), "text/plain"),
        "baseline_stix": ("bundle.json", io.BytesIO(baseline), "application/json")})
    enrich_text = importing.post("/api/ingest/text", headers=headers,
                                 json={"text": _TEXT, "baseline_bundle": baseline.decode()})

    for response in (upload, text, url, enrich, enrich_text):
        assert response.status_code == 200, response.text
    for response in (upload, text, url):
        assert importing.imported_by(response.json()["job_id"])["imported_by"] == user.id
    for response in (enrich, enrich_text):
        row = importing.imported_by(response.json()["job_id"])
        assert (row["imported_by"], row["pipeline_mode"]) == (user.id, "enrich")


def test_a_bearer_token_import_records_the_token_owner(importing, make_user):
    user = make_user("analyst")
    token, _ = store.create_token(user.id, "ci")
    response = importing.post("/api/ingest/text", headers={"Authorization": f"Bearer {token}"}, json={"text": _TEXT})
    assert response.status_code == 200
    assert importing.imported_by(response.json()["job_id"])["imported_by"] == user.id


def test_a_reader_cannot_import_and_nothing_is_stored(importing, make_user, sign_in, temp_db):
    headers = sign_in(make_user("reader"))
    assert importing.post("/api/ingest/text", headers=headers, json={"text": _TEXT}).status_code == 403
    assert importing.post("/api/upload", headers=headers,
                          files={"file": ("r.txt", io.BytesIO(_TEXT.encode()), "text/plain")}).status_code == 403
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM jobs").fetchone()["n"] == 0


def test_with_authentication_off_the_owner_stays_empty(temp_db_client, temp_db):
    with patch("api.worker.run_pipeline_async", return_value="started"):
        response = temp_db_client.post("/api/ingest/text", json={"text": _TEXT})
    assert response.status_code == 200
    with temp_db.get_conn() as conn:
        assert conn.execute("SELECT imported_by FROM jobs").fetchone()["imported_by"] is None
