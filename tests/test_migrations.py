"""api.migrate and api/migrations (ADR-0077): a database at any version since
the first PostgreSQL job store is brought to the current one, once, at start.

Every test gets its own empty schema; `_legacy` builds the schema init_db()
produced before versioning (tests/fixtures/schema_before_adr0077.json) or the
schema of an older deployment, version by version, without a version table —
the databases already in the field."""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path
from uuid import uuid4

import pytest

from api import migrate
from api import migrations as history
from api.db_backend import PgConnection

_FIXTURE = Path(__file__).parent / "fixtures" / "schema_before_adr0077.json"
# The last version init_db() had built when ADR-0077 froze it; every version
# after it exists only as a migration.
_FROZEN_AT = 9


@pytest.fixture()
def schema():
    """An empty PostgreSQL schema and a connection whose search_path is it."""
    import psycopg

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "m_" + uuid4().hex[:12]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{name}"')
    conns: list[PgConnection] = []

    def connect() -> PgConnection:
        c = PgConnection(url, schema=name)
        conns.append(c)
        return c

    yield connect
    for c in conns:
        c.close()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{name}" CASCADE')


def _run(conn: PgConnection, statements) -> None:
    for s in statements:
        conn.execute_script(s)


def _legacy_before_adr0077(conn: PgConnection) -> None:
    """What init_db() left in every database created before ADR-0077."""
    frozen = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    _run(conn, frozen["rules"])
    _run(conn, frozen["jobs"])


def _legacy_at(conn: PgConnection, version: int) -> None:
    """A deployment stopped at `version`, as the idempotent DDL list left it."""
    for mg in history.load()[:version]:
        _run(conn, mg.statements)


def _shape(conn: PgConnection) -> dict:
    """Tables, columns, constraints and indexes of the schema, order-free."""
    cols = conn.execute(
        "SELECT table_name, column_name, data_type, is_nullable, column_default, is_generated, "
        "generation_expression FROM information_schema.columns WHERE table_schema = current_schema() "
        "AND table_name <> 'schema_migrations'").fetchall()
    cons = conn.execute(
        "SELECT c.relname, x.contype, pg_get_constraintdef(x.oid) FROM pg_constraint x "
        "JOIN pg_class c ON c.oid = x.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = current_schema() AND c.relname <> 'schema_migrations'").fetchall()
    idx = conn.execute(
        "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() "
        "AND tablename <> 'schema_migrations'").fetchall()
    return {
        "columns": sorted(tuple(r) for r in cols),
        "constraints": sorted(tuple(r) for r in cons),
        # the schema name differs between two test schemas
        "indexes": sorted((r[0], re.sub(r" ON \S+\.", " ON ", r[1])) for r in idx),
    }


def _records(conn: PgConnection) -> list[tuple[int, str]]:
    return [(r["version"], r["how"]) for r in
            conn.execute("SELECT version, how FROM schema_migrations ORDER BY version").fetchall()]


# ── The history itself ───────────────────────────────────────────────────────

def test_the_history_is_one_unbroken_line_from_the_first_job_store():
    known = history.load()
    assert [m.version for m in known] == list(range(1, len(known) + 1))
    assert known[0].name == "job_store" and len(known) >= 9
    assert len({m.name for m in known}) == len(known)
    assert all(m.statements or m.data for m in known)
    assert history.latest_version() == len(known)


def test_the_import_scripts_get_each_store_from_the_history():
    rules, jobs = history.store_statements("rules"), history.store_statements("jobs")
    assert any(s.startswith("CREATE TABLE IF NOT EXISTS detection_rules") for s in rules)
    assert any(s.startswith("CREATE TABLE IF NOT EXISTS jobs") for s in jobs)
    assert not any("detection_rules" in s for s in jobs)


# ── From an empty database ───────────────────────────────────────────────────

def test_an_empty_database_gets_every_version_then_nothing(schema):
    conn = schema()
    report = migrate.upgrade(conn)
    target = history.latest_version()
    assert (report.before, report.after) == (0, target)
    assert report.applied == list(range(1, target + 1)) and report.recognised == []
    assert _records(conn) == [(v, "applied") for v in range(1, target + 1)]

    again = migrate.upgrade(conn)
    assert again.applied == [] and again.recognised == [] and again.before == target


def test_the_history_builds_the_schema_init_db_built_before_versioning(schema):
    built, frozen = schema(), schema()
    _legacy_at(built, _FROZEN_AT)
    _legacy_before_adr0077(frozen)
    assert _shape(built) == _shape(frozen)


# ── From a database already in the field ─────────────────────────────────────

def test_a_database_from_before_versioning_is_recognised_not_rebuilt(schema):
    conn = schema()
    _legacy_before_adr0077(conn)
    conn.execute("INSERT INTO jobs (id, original_filename, created_at, updated_at) VALUES ('j1','r.pdf','t','t')")
    report = migrate.upgrade(conn)
    target = history.latest_version()
    assert report.recognised == list(range(1, _FROZEN_AT + 1))
    assert report.applied == list(range(_FROZEN_AT + 1, target + 1))
    assert _records(conn) == ([(v, "recognised") for v in range(1, _FROZEN_AT + 1)]
                              + [(v, "applied") for v in range(_FROZEN_AT + 1, target + 1)])
    assert conn.execute("SELECT count(*) AS n FROM jobs").fetchone()["n"] == 1


@pytest.mark.parametrize("stopped_at", range(1, history.latest_version()))
def test_a_deployment_stopped_at_any_version_is_brought_up_to_date(schema, stopped_at):
    old, fresh = schema(), schema()
    _legacy_at(old, stopped_at)
    # Rows as a deployment at that version wrote them: from version 6 on, every
    # write path stamps who decided.
    origin = "'human'" if stopped_at >= 6 else "NULL"
    with_origin = ", decision_origin" if stopped_at >= 6 else ""
    old.execute("INSERT INTO jobs (id, original_filename, created_at, updated_at) VALUES ('j1','r.pdf','t','t')")
    old.execute(f"INSERT INTO entities (id, job_id, value, entity_type, accepted{with_origin}) "
                f"VALUES ('e1','j1','APT29','threat_actor',1{', ' + origin if with_origin else ''})")
    old.execute(f"INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, "
                f"accepted{with_origin}) VALUES ('r1','j1','APT29','uses','SUNBURST',1"
                f"{', ' + origin if with_origin else ''})")

    report = migrate.upgrade(old)
    target = history.latest_version()
    assert report.recognised == list(range(1, stopped_at + 1))
    assert report.applied == list(range(stopped_at + 1, target + 1))
    assert _records(old)[-1] == (target, "applied")

    migrate.upgrade(fresh)
    assert _shape(old) == _shape(fresh)
    # The data came through; version 6's backfill reached the decisions made
    # before it, and left alone those that had an origin.
    expected = "human" if stopped_at >= 6 else "legacy"
    assert old.execute("SELECT decision_origin FROM entities WHERE id='e1'").fetchone()["decision_origin"] == expected
    assert old.execute("SELECT decision_origin FROM relationships WHERE id='r1'").fetchone()["decision_origin"] \
        == expected


def test_a_recognised_version_whose_backfill_had_not_run_is_applied(schema):
    """Version 6's check covers its data: columns present but decisions left
    without an origin means the version is not there yet."""
    conn = schema()
    _legacy_at(conn, 6)
    conn.execute("INSERT INTO jobs (id, original_filename, created_at, updated_at) VALUES ('j1','r.pdf','t','t')")
    conn.execute("INSERT INTO entities (id, job_id, value, entity_type, accepted) "
                 "VALUES ('e1','j1','APT29','threat_actor',1)")
    report = migrate.upgrade(conn)
    assert 6 in report.applied and report.recognised == [1, 2, 3, 4, 5]
    assert conn.execute("SELECT decision_origin FROM entities").fetchone()["decision_origin"] == "legacy"


# ── Refusals ─────────────────────────────────────────────────────────────────

def test_a_database_newer_than_the_code_is_refused(schema):
    conn = schema()
    migrate.upgrade(conn)
    conn.execute("INSERT INTO schema_migrations (version, name, checksum, how, applied_at) "
                 "VALUES (999, 'from_the_future', 'x', 'applied', 't')")
    with pytest.raises(migrate.DatabaseNewerThanCode, match="schema version 999"):
        migrate.upgrade(conn)
    assert migrate.status(conn)["newer_than_code"] == [999]


def test_an_edited_migration_is_refused(schema):
    conn = schema()
    migrate.upgrade(conn)
    conn.execute("UPDATE schema_migrations SET checksum = 'edited' WHERE version = 3")
    with pytest.raises(migrate.ChecksumMismatch, match="version 3"):
        migrate.upgrade(conn)
    assert migrate.status(conn)["edited"] == [3]


def test_comments_around_a_migration_do_not_change_its_checksum():
    mg = history.load()[7]
    reworded = history.Migration(version=mg.version, name=mg.name, store=mg.store,
                                 statements=tuple(" " + s.replace(" ", "  ") + "\n" for s in mg.statements),
                                 is_applied=mg.is_applied, description="another wording")
    assert reworded.checksum == mg.checksum


# ── One transaction per version ──────────────────────────────────────────────

def _with_extra(monkeypatch, extra: history.Migration) -> None:
    base = history.load()
    monkeypatch.setattr(history, "load", lambda: [*base, extra])


def test_a_failing_version_rolls_back_entirely_and_stops_the_start(schema, monkeypatch):
    conn = schema()
    migrate.upgrade(conn)
    target = history.latest_version()
    _with_extra(monkeypatch, history.Migration(
        version=target + 1, name="broken", store="jobs",
        statements=("ALTER TABLE jobs ADD COLUMN half_done TEXT", "SELECT 1/0"),
        is_applied=lambda c: history.column_exists(c, "jobs", "half_done")))
    import psycopg
    with pytest.raises(psycopg.errors.DivisionByZero):
        migrate.upgrade(conn)
    assert not history.column_exists(conn, "jobs", "half_done")
    assert migrate.status(conn)["current"] == target


def test_a_version_whose_check_does_not_see_it_is_rolled_back(schema, monkeypatch):
    conn = schema()
    migrate.upgrade(conn)
    target = history.latest_version()
    _with_extra(monkeypatch, history.Migration(
        version=target + 1, name="unverified", store="jobs",
        statements=("ALTER TABLE jobs ADD COLUMN unverified TEXT",),
        is_applied=lambda c: False))
    with pytest.raises(migrate.VerificationFailed):
        migrate.upgrade(conn)
    assert not history.column_exists(conn, "jobs", "unverified")


def _mark_done(conn) -> None:
    conn.execute("UPDATE jobs SET status = 'migrated'")


def test_a_data_step_runs_once_and_a_destructive_one_keeps_a_snapshot(schema, monkeypatch):
    conn = schema()
    migrate.upgrade(conn)
    conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                 "VALUES ('j1','r.pdf','completed','t','t')")
    target = history.latest_version()
    _with_extra(monkeypatch, history.Migration(
        version=target + 1, name="rewrite_status", store="jobs", statements=(), data=_mark_done,
        snapshot_tables=("jobs",),
        is_applied=lambda c: c.execute("SELECT 1 FROM jobs WHERE status <> 'migrated'").fetchone() is None))
    assert migrate.upgrade(conn).applied == [target + 1]
    assert conn.execute("SELECT status FROM jobs").fetchone()["status"] == "migrated"
    assert conn.execute(f"SELECT status FROM _pre_v{target + 1:04d}_jobs").fetchone()["status"] == "completed"

    conn.execute("UPDATE jobs SET status = 'completed'")
    assert migrate.upgrade(conn).applied == []                       # recorded: never again
    assert conn.execute("SELECT status FROM jobs").fetchone()["status"] == "completed"


# ── Several processes at start ───────────────────────────────────────────────

def test_processes_starting_together_migrate_once(schema):
    reports: list[migrate.Report] = []
    errors: list[BaseException] = []
    conns = [schema() for _ in range(4)]

    def start(c):
        try:
            reports.append(migrate.upgrade(c))
        except BaseException as exc:                 # noqa: BLE001 — surfaced by the assert below
            errors.append(exc)

    threads = [threading.Thread(target=start, args=(c,)) for c in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    target = history.latest_version()
    assert sorted(v for r in reports for v in r.applied) == list(range(1, target + 1))
    assert _records(conns[0]) == [(v, "applied") for v in range(1, target + 1)]


# ── Command line ─────────────────────────────────────────────────────────────

def test_status_check_and_up_from_the_command_line(schema, monkeypatch, capsys):
    conn = schema()
    monkeypatch.setattr("api.db._postgres_conn", lambda: conn)
    assert migrate.main(["check"]) == 1
    assert migrate.main(["status"]) == 0
    assert "database at version 0" in capsys.readouterr().out
    assert migrate.main(["up"]) == 0
    assert migrate.main(["check"]) == 0
    assert "up to date" in capsys.readouterr().out
