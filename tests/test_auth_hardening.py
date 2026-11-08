"""Findings of the security review of the authentication core: every route goes through the
access check, a running stream stops with its session, the guard says when it cannot judge,
and the admin CLI reports a refusal in one line."""
from __future__ import annotations

import threading
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import api.main
from api import admin
from api.auth import store
from api.auth.deps import current_user
from api.auth.middleware import DOC_PATHS, OPEN_REQUESTS
from api.routes import metrics, progress

from .conftest import AUTH_TEST_PASSWORD

# Routes that are not behind `current_user`, and why.
_NOT_GATED_BY_DEPENDENCY = {
    "/api/health": "the liveness probe, open",
    "/": "the page shown when the frontend is not built",
    "/openapi.json": "gated by the middleware",
    "/docs": "gated by the middleware",
    "/docs/oauth2-redirect": "gated by the middleware",
    "/redoc": "gated by the middleware",
    "/metrics": "its own rule: loopback or the METRICS_TOKEN bearer (api/routes/metrics.py)",
}


def _has_access_dependency(route) -> bool:
    deps = getattr(route, "dependencies", None)
    if deps is None and hasattr(route, "include_context"):                  # a router FastAPI included lazily
        deps = route.include_context.dependencies
    return any(d.dependency is current_user for d in deps or [])


def test_every_route_goes_through_current_user_except_an_explicit_list():
    open_paths = {path for _, path in OPEN_REQUESTS}
    stray = []
    for route in api.main.app.routes:
        path = getattr(route, "path", None)
        if path is None:                                                     # an included router
            if not _has_access_dependency(route) and getattr(route, "original_router", None) is not metrics.router:
                stray.append(repr(route))
        elif path in _NOT_GATED_BY_DEPENDENCY or path in open_paths:
            continue
        elif type(route).__name__ == "Mount":                                # the SPA's static files
            continue
        elif not _has_access_dependency(route):
            stray.append(path)
    assert stray == []
    assert set(DOC_PATHS) <= set(_NOT_GATED_BY_DEPENDENCY)


def test_the_middleware_gate_matches_the_open_operations():
    from api.auth.middleware import is_gated

    assert not is_gated("GET", "/api/health") and not is_gated("POST", "/api/auth/login")
    assert is_gated("POST", "/api/auth/logout") and is_gated("GET", "/api/jobs") and is_gated("GET", "/docs")
    assert not is_gated("GET", "/") and not is_gated("GET", "/assets/index.js")


# ── A stream stops with its session ──────────────────────────────────────────

@pytest.fixture()
def processing_job(temp_db):
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES ('j1','r.txt','processing','t','t')")
    return "j1"


@pytest.fixture()
def fast_stream(monkeypatch):
    monkeypatch.setattr(progress, "_POLL_INTERVAL_SECONDS", 0.05)
    monkeypatch.setattr(progress, "_REAUTH_SECONDS", 0.1)
    monkeypatch.setattr(progress, "_MAX_STREAM_SECONDS", 4)       # a stream that never stops fails, it does not hang


def _after(seconds: float, action) -> threading.Timer:
    timer = threading.Timer(seconds, action)
    timer.start()
    return timer


def test_a_stream_ends_when_its_user_is_disabled(auth_client, make_user, sign_in, processing_job, fast_stream):
    user = make_user("reader")
    sign_in(user)
    timer = _after(0.4, lambda: store.set_disabled(user.username))
    body = auth_client.get(f"/api/jobs/{processing_job}/progress").text
    timer.join()
    assert "session ended" in body and "timed out" not in body


def test_a_stream_ends_when_its_session_is_signed_out(auth_client, make_user, sign_in, processing_job, fast_stream,
                                                      temp_db):
    sign_in(make_user("reader"))

    def sign_out():
        with temp_db.get_conn() as conn:
            conn.execute("DELETE FROM sessions")

    timer = _after(0.4, sign_out)
    body = auth_client.get(f"/api/jobs/{processing_job}/progress").text
    timer.join()
    assert "session ended" in body


def test_a_stream_ends_when_its_token_is_revoked(auth_client, make_user, processing_job, fast_stream):
    token, token_id = store.create_token(make_user("reader").id, "ci")
    timer = _after(0.4, lambda: store.revoke_token(token_id))
    body = auth_client.get(f"/api/jobs/{processing_job}/progress",
                           headers={"Authorization": f"Bearer {token}"}).text
    timer.join()
    assert "session ended" in body


def test_a_stream_of_a_valid_session_runs_on(auth_client, make_user, sign_in, processing_job, fast_stream):
    sign_in(make_user("reader"))
    body = auth_client.get(f"/api/jobs/{processing_job}/progress").text
    assert "timed out" in body and "session ended" not in body


# ── The guard says when it cannot judge ──────────────────────────────────────

def test_a_start_with_no_known_bind_address_warns(temp_db, monkeypatch, caplog):
    monkeypatch.delenv("API_HOST", raising=False)
    monkeypatch.delenv("API_PUBLISHED_HOST", raising=False)
    with caplog.at_level("WARNING"), patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app):
            pass
    assert "neither API_HOST nor API_PUBLISHED_HOST" in caplog.text and "run_api.py" in caplog.text


def test_a_start_that_knows_its_address_does_not_warn(temp_db, caplog):
    with caplog.at_level("WARNING"), patch("api.main.init_db"), patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app):
            pass
    assert "neither API_HOST" not in caplog.text


# ── The admin CLI ────────────────────────────────────────────────────────────

@pytest.fixture()
def cli(temp_db, capsys, monkeypatch):
    monkeypatch.setattr("api.db.init_db", lambda: None)

    def run(*argv: str):
        capsys.readouterr()
        code = admin.main(list(argv))
        out = capsys.readouterr()
        return code, out.out, out.err

    return run


def _password_file(tmp_path, text: str = AUTH_TEST_PASSWORD, mode: int = 0o600) -> str:
    path = tmp_path / "password"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return str(path)


def test_list_tokens_and_revoke_token(cli, tmp_path):
    cli("create-admin", "--username", "alice", "--password-file", _password_file(tmp_path))
    code, out, _ = cli("create-token", "--user", "alice", "--name", "nightly")
    token = out.strip()
    code, out, _ = cli("list-tokens")
    assert code == 0 and "nightly" in out and "active" in out and token not in out
    token_id = out.split()[0]
    assert cli("list-tokens", "--user", "bob")[1].strip() == "no tokens"
    assert cli("revoke-token", "--id", token_id)[0] == 0
    assert store.find_token_user(token) is None
    assert "revoked" in cli("list-tokens", "--user", "alice")[1]
    code, _, err = cli("revoke-token", "--id", token_id)
    assert code == 1 and "no active token" in err


def test_an_absurd_lifetime_is_a_one_line_refusal(cli, tmp_path):
    cli("create-admin", "--username", "alice", "--password-file", _password_file(tmp_path))
    code, out, err = cli("create-token", "--user", "alice", "--name", "x", "--days", "99999999999999")
    assert code == 1 and out == "" and err.startswith("refused:") and "Traceback" not in err
    assert len(err.strip().splitlines()) == 1


def test_a_database_error_is_a_one_line_refusal(cli, monkeypatch):
    import psycopg

    def broken(*_):
        raise psycopg.OperationalError("connection refused\nsecond line")

    monkeypatch.setattr(store, "list_users", broken)
    code, _, err = cli("list-users")
    assert code == 1 and err.strip() == "database error: connection refused"


def test_a_password_file_others_can_read_is_warned_about(cli, tmp_path):
    code, _, err = cli("create-admin", "--username", "alice", "--password-file",
                       _password_file(tmp_path, mode=0o644))
    assert code == 0 and "can be read by other users" in err and AUTH_TEST_PASSWORD not in err
    code, _, err = cli("create-user", "--username", "bob", "--password-file", _password_file(tmp_path, mode=0o600))
    assert code == 0 and err == ""


def test_an_empty_password_file_is_named(cli, tmp_path):
    path = _password_file(tmp_path, text="\n")
    code, _, err = cli("create-admin", "--username", "alice", "--password-file", path)
    assert code == 1 and path in err and "empty" in err


def test_metrics_keep_their_own_rule_when_authentication_is_on(auth_client, monkeypatch):
    monkeypatch.setenv("METRICS_TOKEN", "m" * 32)
    assert auth_client.get("/metrics").status_code == 403                 # not loopback, no token
    assert auth_client.get("/metrics", headers={"Authorization": "Bearer " + "x" * 32}).status_code == 403
    answer = auth_client.get("/metrics", headers={"Authorization": "Bearer " + "m" * 32})
    assert answer.status_code == 200 and "ctiparsor_database_up" in answer.text
