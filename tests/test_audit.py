"""The audit trail (ADR-0097 item 17): one record per state-changing request and per command-line
change, the JSON line and the row, the retention, and GET /api/audit.

The records are checked through both outputs: the JSON lines on standard output (capsys) and the
`audit_events` rows.  The no-leak tests send a body, a query string, a header, a cookie, a bearer
token and a password, each with a marker text, and search both outputs for every marker."""
from __future__ import annotations

import getpass
import json
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from api import admin, audit
from api.auth import store

from .conftest import AUTH_TEST_PASSWORD

_COLUMNS = ("at", "request_id", "user_id", "username", "role", "auth", "method", "route", "target", "status",
            "outcome", "client", "attempted")
_LINE_KEYS = {"audit", *_COLUMNS}


def _lines(out: str) -> list[dict]:
    """The audit JSON lines in a standard output (the text log lines are skipped)."""
    found = []
    for line in out.splitlines():
        if line.startswith("{") and '"audit": true' in line:
            found.append(json.loads(line))
    return found


def _rows(db) -> list[dict]:
    with db.get_conn() as conn:
        found = conn.execute("SELECT " + ", ".join(_COLUMNS) + " FROM audit_events ORDER BY id").fetchall()
    rows = [dict(zip(_COLUMNS, tuple(row), strict=True)) for row in found]
    for row in rows:
        row["target"] = json.loads(row["target"]) if row["target"] is not None else None
    return rows


def _insert_job(db, job_id: str) -> None:
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES (?,?,?,?,?)", (job_id, "r.txt", "completed", "t", "t"))


def _rec(at: str, **overrides) -> dict:
    """A record as the middleware writes one, for the tests that need rows of their own."""
    record = {"at": at, "request_id": "seedreq", "user_id": None, "username": None, "role": None,
              "auth": "none", "method": "POST", "route": "/api/auth/logout", "target": {}, "status": 200,
              "outcome": "ok", "client": "127.0.0.1", "attempted": None}
    record.update(overrides)
    return record


def _login(client, username: str, password: str = AUTH_TEST_PASSWORD, **kwargs):
    return client.post("/api/auth/login", json={"username": username, "password": password}, **kwargs)


# ── One record per request ─────────────────────────────────────────────────────

def test_a_post_a_patch_and_a_delete_each_write_one_row_and_one_line(auth_client, make_user, sign_in, temp_db,
                                                                     capsys):
    admin_user = make_user("admin")
    headers = sign_in(admin_user)
    _insert_job(temp_db, "job-audit-1")
    capsys.readouterr()
    rows_before = len(_rows(temp_db))

    # The sign-out comes last: it ends the session the other two requests need.
    patched = auth_client.patch("/api/jobs/job-audit-1", json={"status": "reviewing"}, headers=headers)
    deleted = auth_client.delete("/api/jobs/job-audit-1", headers=headers)
    posted = auth_client.post("/api/auth/logout", headers=headers)

    assert (patched.status_code, deleted.status_code, posted.status_code) == (200, 200, 200)
    lines = _lines(capsys.readouterr().out)
    rows = _rows(temp_db)[rows_before:]
    assert len(lines) == len(rows) == 3
    expected = [("PATCH", "/api/jobs/{job_id}", {"job_id": "job-audit-1"}),
                ("DELETE", "/api/jobs/{job_id}", {"job_id": "job-audit-1"}), ("POST", "/api/auth/logout", {})]
    for line, row, (method, route, target) in zip(lines, rows, expected, strict=True):
        assert set(line) == _LINE_KEYS
        assert line["audit"] is True
        for record in (line, row):
            assert record["user_id"] == admin_user.id and record["username"] == admin_user.username
            assert record["role"] == "admin" and record["auth"] == "session"
            assert record["method"] == method and record["route"] == route
            assert record["target"] == target and record["outcome"] == "ok" and record["status"] == 200
            assert record["client"] == "testclient"
            assert record["attempted"] is None
        assert row["request_id"] == line["request_id"]


def test_a_read_writes_nothing(auth_client, make_user, sign_in, temp_db, capsys):
    headers = sign_in(make_user("reader"))
    capsys.readouterr()
    rows_before = len(_rows(temp_db))
    for path in ("/api/auth/me", "/api/jobs", "/api/health"):
        assert auth_client.get(path, headers=headers).status_code == 200
    assert _lines(capsys.readouterr().out) == []
    assert len(_rows(temp_db)) == rows_before


def test_a_refused_request_below_the_role_is_refused_with_the_user(auth_client, make_user, sign_in, temp_db,
                                                                  capsys):
    reader = make_user("reader")
    headers = sign_in(reader)
    _insert_job(temp_db, "job-audit-2")
    capsys.readouterr()

    response = auth_client.patch("/api/jobs/job-audit-2", json={"status": "completed"}, headers=headers)

    assert response.status_code == 403
    row = _rows(temp_db)[-1]
    assert row["status"] == 403 and row["outcome"] == "refused"
    assert row["username"] == reader.username and row["role"] == "reader" and row["auth"] == "session"
    assert _lines(capsys.readouterr().out)[-1]["outcome"] == "refused"


def test_an_anonymous_refused_request_is_a_log_line_and_not_a_row(auth_client, temp_db, capsys):
    capsys.readouterr()
    before = len(_rows(temp_db))
    response = auth_client.patch("/api/jobs/no-such-job", json={"status": "completed"})

    assert response.status_code == 401
    assert len(_rows(temp_db)) == before                    # an anonymous client cannot fill the table
    line = [r for r in _lines(capsys.readouterr().out) if r.get("route") == "/api/jobs/no-such-job"][-1]
    assert (line["user_id"], line["username"], line["role"], line["auth"]) == (None, None, None, "none")
    assert line["status"] == 401 and line["outcome"] == "refused" and line["target"] == {}


def test_an_unmatched_path_is_cut_to_256_characters(auth_client, capsys):
    capsys.readouterr()
    auth_client.post("/api/" + "x" * 5000)
    line = [r for r in _lines(capsys.readouterr().out) if str(r.get("route", "")).startswith("/api/xxx")][-1]
    assert len(line["route"]) == 256


def test_a_failed_sign_in_is_kept_as_a_row(auth_client, temp_db):
    before = len(_rows(temp_db))
    answer = auth_client.post("/api/auth/login", json={"username": "nobody", "password": "wrong password!"})
    assert answer.status_code == 401
    rows = _rows(temp_db)
    assert len(rows) == before + 1 and rows[-1]["route"] == "/api/auth/login" and rows[-1]["outcome"] == "refused"


def test_an_unknown_path_is_recorded_under_its_raw_path(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    response = auth_client.post("/api/nothing-here", headers=headers)
    row = _rows(temp_db)[-1]
    assert row["status"] == response.status_code >= 400
    assert row["route"] == "/api/nothing-here" and row["target"] == {} and row["outcome"] in ("refused", "error")


def test_the_request_id_of_the_header_is_the_one_recorded_and_logged(auth_client, make_user, sign_in, temp_db,
                                                                     capsys):
    headers = sign_in(make_user("admin"))
    capsys.readouterr()
    auth_client.post("/api/auth/logout", headers={**headers, "X-Request-ID": "req-w3-0001"})
    assert _rows(temp_db)[-1]["request_id"] == "req-w3-0001"
    assert _lines(capsys.readouterr().out)[-1]["request_id"] == "req-w3-0001"


def test_a_malformed_request_id_is_replaced_not_logged(auth_client, make_user, sign_in, temp_db, capsys):
    headers = sign_in(make_user("admin"))
    capsys.readouterr()
    auth_client.post("/api/auth/logout", headers={**headers, "X-Request-ID": "bad id forged"})
    recorded = _rows(temp_db)[-1]["request_id"]
    assert recorded and "forged" not in recorded and "\n" not in recorded
    assert "forged" not in capsys.readouterr().out


def test_with_authentication_off_a_change_is_recorded_with_no_user(temp_db_client, temp_db, capsys):
    capsys.readouterr()
    assert temp_db_client.post("/api/auth/logout").status_code == 200
    row = _rows(temp_db)[-1]
    assert (row["user_id"], row["username"], row["role"], row["auth"]) == (None, None, None, "none")
    assert row["route"] == "/api/auth/logout" and row["outcome"] == "ok"
    assert _lines(capsys.readouterr().out)[-1]["username"] is None


# ── Sign-in ───────────────────────────────────────────────────────────────────

def test_a_failed_sign_in_for_an_unknown_name_has_no_attempted(auth_client, temp_db, capsys):
    capsys.readouterr()
    response = _login(auth_client, "ghost-w3-name", "not-the-password")
    assert response.status_code == 401
    row = _rows(temp_db)[-1]
    assert row["route"] == "/api/auth/login" and row["attempted"] is None
    assert row["status"] == 401 and row["outcome"] == "refused" and row["user_id"] is None
    assert "ghost-w3-name" not in capsys.readouterr().out


def test_a_failed_sign_in_for_a_known_name_names_it_as_attempted(auth_client, make_user, temp_db, capsys):
    user = make_user("analyst")
    capsys.readouterr()
    assert _login(auth_client, user.username, "wrong password here").status_code == 401
    row = _rows(temp_db)[-1]
    assert row["attempted"] == user.username and row["user_id"] is None and row["username"] is None
    assert _lines(capsys.readouterr().out)[-1]["attempted"] == user.username


def test_a_lockout_is_attributed_to_the_account(auth_client, make_user, temp_db):
    user = make_user("analyst")
    for _ in range(5):
        assert _login(auth_client, user.username, "wrong password here").status_code == 401
    assert _login(auth_client, user.username).status_code == 429
    row = _rows(temp_db)[-1]
    assert row["status"] == 429 and row["outcome"] == "refused" and row["attempted"] == user.username


def test_a_sign_in_records_the_account_that_signed_in(auth_client, make_user, temp_db, capsys):
    user = make_user("admin")
    capsys.readouterr()
    assert _login(auth_client, user.username).status_code == 200
    row = _rows(temp_db)[-1]
    assert row["user_id"] == user.id and row["username"] == user.username and row["role"] == "admin"
    assert row["auth"] == "session" and row["attempted"] == user.username and row["outcome"] == "ok"
    assert _lines(capsys.readouterr().out)[-1]["username"] == user.username


# ── What is never written ─────────────────────────────────────────────────────

def test_no_body_query_header_cookie_token_or_password_reaches_either_output(auth_client, make_user, sign_in,
                                                                             temp_db, capsys):
    analyst = make_user("analyst")
    headers = sign_in(analyst)
    _insert_job(temp_db, "job-audit-3")
    token, _ = store.create_token(analyst.id, "ci")
    session_cookie = auth_client.cookies.get("ctiparsor_session")
    csrf = headers["X-CSRF-Token"]
    capsys.readouterr()

    markers = ["BODY-MARK-3e9a", "QUERY-MARK-71bc", "HEADER-MARK-0d4f", "PASSWORD-MARK-a2c8"]
    auth_client.post("/api/auth/login?leak=QUERY-MARK-71bc", json={"username": analyst.username,
                                                                   "password": "PASSWORD-MARK-a2c8"})
    auth_client.patch("/api/jobs/job-audit-3?leak=QUERY-MARK-71bc", json={"status": "BODY-MARK-3e9a"},
                      headers={**headers, "X-Leak": "HEADER-MARK-0d4f"})
    auth_client.patch("/api/jobs/job-audit-3", json={"status": "BODY-MARK-3e9a"},
                      headers={"Authorization": f"Bearer {token}", "X-Leak": "HEADER-MARK-0d4f"})
    auth_client.cookies.set("ctiparsor_session", "COOKIE-MARK-5b7e")
    auth_client.post("/api/auth/logout", headers={"X-Leak": "HEADER-MARK-0d4f"})
    auth_client.post("/api/auth/logout", headers={"Authorization": "Bearer ctp_MARK-6a1d"})

    out = capsys.readouterr().out
    stored = json.dumps(_rows(temp_db))
    secrets = markers + [token, session_cookie, csrf, AUTH_TEST_PASSWORD]
    for secret in secrets:
        assert secret and secret not in out and secret not in stored, secret
    assert "ctp_MARK-6a1d" not in out and "ctp_MARK-6a1d" not in stored
    assert "COOKIE-MARK-5b7e" not in out and "COOKIE-MARK-5b7e" not in stored
    assert len(_lines(out)) >= 5


# ── A failed write does not change the answer ──────────────────────────────────

def test_a_database_error_while_writing_keeps_the_answer(auth_client, make_user, sign_in, monkeypatch, capsys,
                                                         caplog):
    headers = sign_in(make_user("admin"))
    capsys.readouterr()

    def refuse(record):
        raise psycopg.OperationalError("the database is down")

    monkeypatch.setattr(audit, "_insert", refuse)
    response = auth_client.post("/api/auth/logout", headers=headers)

    assert response.status_code == 200 and response.json() == {"signed_out": True}
    out = capsys.readouterr().out
    assert _lines(out)[-1]["status"] == 200                              # the JSON line is still written
    assert "could not write an audit row (OperationalError)" in caplog.text


# ── Command-line changes ──────────────────────────────────────────────────────

@pytest.fixture()
def cli(temp_db, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("api.db.init_db", lambda: None)
    monkeypatch.setattr(getpass, "getuser", lambda: "ops-w3")
    password = tmp_path / "password"
    password.write_text(AUTH_TEST_PASSWORD + "\n", encoding="utf-8")

    def run(*argv: str) -> int:
        if argv[0] in ("create-admin", "create-user", "set-password"):
            argv = (*argv, "--password-file", str(password))
        return admin.main(list(argv))

    return run


def test_each_command_that_changes_something_writes_a_record(cli, temp_db, make_user):
    assert cli("create-admin", "--username", "mara") == 0
    assert cli("create-user", "--username", "rita", "--role", "analyst") == 0
    assert cli("disable", "--username", "rita") == 0
    assert cli("create-token", "--user", "mara", "--name", "ci") == 0
    token_id = _rows(temp_db)[-1]["target"]["token_id"]
    assert cli("revoke-token", "--id", token_id) == 0
    assert cli("set-password", "--username", "rita") == 0

    rows = _rows(temp_db)
    assert [row["route"] for row in rows] == ["create-admin", "create-user", "disable", "create-token",
                                              "revoke-token", "set-password"]
    for row in rows:
        assert row["auth"] == "cli" and row["username"] == "ops-w3" and row["user_id"] is None
        assert row["request_id"] is None and row["method"] is None and row["status"] is None
        assert row["outcome"] == "ok" and row["client"] is None
    assert rows[0]["target"] == {"username": "mara"}
    assert rows[3]["target"]["username"] == "mara" and rows[3]["target"]["token_id"]
    assert rows[4]["target"] == {"token_id": token_id}
    assert store.check_credentials("mara", AUTH_TEST_PASSWORD) is not None         # the password is not the record's
    assert AUTH_TEST_PASSWORD not in json.dumps(rows)


def test_a_refused_command_writes_no_record(cli, temp_db):
    assert cli("create-user", "--username", "short", "--role", "analyst") == 0       # a valid password: a row
    assert cli("create-user", "--username", "short", "--role", "analyst") == 1       # the name is taken
    assert [row["route"] for row in _rows(temp_db)] == ["create-user"]


def test_a_command_line_change_is_written_as_a_json_line_too(cli, capsys):
    capsys.readouterr()
    assert cli("create-admin", "--username", "mara") == 0
    captured = capsys.readouterr()
    line = _lines(captured.err)[-1]
    assert _lines(captured.out) == []                  # standard output is left to the command's own answer
    assert line["auth"] == "cli" and line["route"] == "create-admin" and line["username"] == "ops-w3"


# ── Retention ─────────────────────────────────────────────────────────────────

def _store_at(db, days_ago: float, route: str) -> None:
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    with db.get_conn() as conn:
        conn.execute("INSERT INTO audit_events (at, auth, route, outcome) VALUES (?,?,?,?)",
                     (audit.timestamp(moment), "none", route, "ok"))


def test_the_retention_deletes_the_rows_older_than_the_setting_and_keeps_the_others(temp_db, monkeypatch):
    monkeypatch.delenv("AUDIT_RETENTION_DAYS", raising=False)
    _store_at(temp_db, 400, "/api/old")
    _store_at(temp_db, 1, "/api/new")
    audit.prune()
    assert [row["route"] for row in _rows(temp_db)] == ["/api/new"]


def test_a_retention_of_zero_keeps_every_row(temp_db, monkeypatch):
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "0")
    _store_at(temp_db, 4000, "/api/ancient")
    audit.prune()
    assert [row["route"] for row in _rows(temp_db)] == ["/api/ancient"]


def test_the_retention_setting_is_read_from_the_environment(temp_db, monkeypatch):
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "30")
    assert audit.retention_days() == 30
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "-4")
    assert audit.retention_days() == 365
    monkeypatch.delenv("AUDIT_RETENTION_DAYS")
    assert audit.retention_days() == 365


def test_the_retention_runs_at_most_once_an_hour(temp_db, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(audit, "prune", lambda now=None: calls.append(1))
    monkeypatch.setattr(audit, "_last_pruned", float("-inf"))
    audit.prune_if_due()
    audit.prune_if_due()
    assert calls == [1]
    monkeypatch.setattr(audit, "_last_pruned", audit.time.monotonic() - 3601)
    audit.prune_if_due()
    assert calls == [1, 1]


# ── GET /api/audit ────────────────────────────────────────────────────────────

_BASE = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)


def _seed_records(db) -> list[dict]:
    """Seven records, a minute apart, for the filters and the cursor.  The table is emptied first, so
    a sign-in made before this call leaves no row of its own."""
    with db.get_conn() as conn:
        conn.execute("DELETE FROM audit_events")
    records = [
        _rec(audit.timestamp(_BASE + timedelta(minutes=i)), user_id="u1" if i % 2 == 0 else "u2",
             username="alice" if i % 2 == 0 else "bob", role="analyst", auth="session",
             method="PATCH", route="/api/jobs/{job_id}", target={"job_id": f"job-{i}"},
             status=403 if i == 3 else 200, outcome="refused" if i == 3 else "ok")
        for i in range(6)
    ]
    records.append(_rec(audit.timestamp(_BASE + timedelta(minutes=6)), route="create-user", auth="cli",
                        method=None, status=None, username="ops-w3"))
    for record in records:
        audit._insert(record)
    return records


def test_the_audit_route_is_admin_only(auth_client, make_user, sign_in, temp_db):
    _seed_records(temp_db)
    assert auth_client.get("/api/audit").status_code == 401
    assert auth_client.get("/api/audit", headers=sign_in(make_user("reader"))).status_code == 403
    assert auth_client.get("/api/audit", headers=sign_in(make_user("analyst"))).status_code == 403
    assert auth_client.get("/api/audit", headers=sign_in(make_user("admin"))).status_code == 200


def test_the_audit_route_lists_newest_first_with_the_target_as_an_object(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    listed = auth_client.get("/api/audit", headers=headers).json()
    assert [item["at"] for item in listed][:2] == [audit.timestamp(_BASE + timedelta(minutes=6)),
                                                   audit.timestamp(_BASE + timedelta(minutes=5))]
    assert listed[1]["target"] == {"job_id": "job-5"} and listed[-1]["target"] == {"job_id": "job-0"}
    assert listed[0]["target"] is None or listed[0]["target"] == {}


def test_the_audit_route_filters_by_user_route_outcome_and_time(auth_client, make_user, sign_in, temp_db):
    admin_headers = sign_in(make_user("admin"))
    _seed_records(temp_db)

    def ids(**params) -> list[str]:
        response = auth_client.get("/api/audit", params=params, headers=admin_headers)
        assert response.status_code == 200, response.text
        return [item["target"]["job_id"] for item in response.json() if item["target"]]

    assert ids(user="Alice") == ["job-4", "job-2", "job-0"]
    assert ids(route="/api/jobs/{job_id}", outcome="refused") == ["job-3"]
    since = audit.timestamp(_BASE + timedelta(minutes=2))
    until = audit.timestamp(_BASE + timedelta(minutes=4))
    assert ids(since=since, until=until) == ["job-3", "job-2"]
    naive = (_BASE + timedelta(minutes=2)).replace(tzinfo=None).isoformat()
    assert ids(since=naive, until=until) == ["job-3", "job-2"]


def test_the_audit_route_pages_with_a_cursor_and_no_record_twice(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    seen: list[int] = []
    params: dict = {"limit": 3}
    pages = 0
    while True:
        response = auth_client.get("/api/audit", params=params, headers=headers)
        assert response.status_code == 200
        assert len(response.json()) <= 3
        seen += [item["id"] for item in response.json()]
        pages += 1
        cursor = response.headers.get("X-Next-Cursor")
        if cursor is None:
            break
        params = {"limit": 3, "cursor": cursor}
    assert pages == 3 and len(seen) == 7 and len(set(seen)) == 7
    assert seen == sorted(seen, reverse=True)


def test_the_audit_route_refuses_bad_parameters(auth_client, make_user, sign_in, temp_db):
    headers = sign_in(make_user("admin"))
    _seed_records(temp_db)
    assert auth_client.get("/api/audit", params={"since": "not a time"}, headers=headers).status_code == 400
    assert auth_client.get("/api/audit", params={"cursor": "%%%"}, headers=headers).status_code == 400
    assert auth_client.get("/api/audit", params={"limit": 0}, headers=headers).status_code == 422
    assert auth_client.get("/api/audit", params={"limit": 501}, headers=headers).status_code == 422
    assert auth_client.get("/api/audit", params={"outcome": "maybe"}, headers=headers).status_code == 422
