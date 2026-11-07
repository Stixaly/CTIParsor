"""scripts/migrate_jobs_to_postgres.py (issue #466): the decision_origin backfill of
migration v0006 runs after the rows are copied (the DDL runs it on empty tables),
and a child row whose job the SQLite source does not hold is left out and
counted instead of failing the copy on a foreign key.

The target is a disposable PostgreSQL schema (CTIPARSOR_TEST_DATABASE_URL); the
source is a small SQLite file written by the test."""
from __future__ import annotations

import os
import sqlite3
from uuid import uuid4

import psycopg
import pytest

from scripts import migrate_jobs_to_postgres as migrate


@pytest.fixture()
def pg_target(monkeypatch):
    """(url, schema): an empty schema the script's psycopg connection lands in."""
    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    schema = "t_" + uuid4().hex[:12]
    admin = psycopg.connect(url, autocommit=True)
    admin.execute(f'CREATE SCHEMA "{schema}"')
    admin.close()
    monkeypatch.setenv("PGOPTIONS", f"-c search_path={schema}")
    yield url, schema
    admin = psycopg.connect(url, autocommit=True)
    try:
        admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
    finally:
        admin.close()


def _make_source(path):
    """A pre-v0006 job store: no decision_origin column, one orphan entity."""
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE jobs (id TEXT PRIMARY KEY, original_filename TEXT NOT NULL,
                           status TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE entities (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, value TEXT NOT NULL,
                               entity_type TEXT NOT NULL, context TEXT, confidence REAL,
                               mitre_id TEXT, accepted INTEGER, source TEXT);
        INSERT INTO jobs VALUES ('job-1', 'report.txt', 'completed', '2026-01-01', '2026-01-01');
        INSERT INTO entities VALUES ('e-accepted', 'job-1', 'Emotet', 'malware', '', 0.9, NULL, 1, 'llm');
        INSERT INTO entities VALUES ('e-undecided', 'job-1', 'Qakbot', 'malware', '', 0.9, NULL, NULL, 'llm');
        INSERT INTO entities VALUES ('e-orphan', 'ghost-job', '1.2.3.4', 'ipv4', '', 0.9, NULL, 1, 'ioc');
        """
    )
    con.commit()
    con.close()
    return path


def test_backfill_runs_after_copy_and_orphan_rows_are_skipped_issue_466(pg_target, tmp_path, capsys):
    url, schema = pg_target
    source = _make_source(tmp_path / "cti_stix.db")

    rc = migrate.main(["--sqlite", str(source), "--postgres", url])
    captured = capsys.readouterr()

    assert rc == 0
    # The orphan is named and counted on stderr, not inserted.
    assert "entities: 1 row(s) whose job is absent from the source - skipped" in captured.err
    # The backfill ran on the copied rows: an accepted decision is 'legacy',
    # an undecided one stays NULL.
    assert "entities: decision_origin backfilled on 1 row(s)" in captured.out

    with psycopg.connect(url, options=f"-c search_path={schema}") as conn:
        rows = dict(conn.execute("SELECT id, decision_origin FROM entities ORDER BY id").fetchall())
    assert rows == {"e-accepted": "legacy", "e-undecided": None}
