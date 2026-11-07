"""Issue #443: `migrate.upgrade` keeps `lock_timeout` on the connection when the
advisory lock is not obtained.

`upgrade` sets `lock_timeout` so that a process starting while another one
migrates gives up after DB_MIGRATION_LOCK_TIMEOUT_S, then resets it. The reset
used to come right after the lock call, outside any `finally`: when the lock
failed (LockNotAvailable), the reset was skipped and the connection, reused by
the next query, kept a 1 s lock_timeout.
"""
from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest

from api import migrate
from api.db_backend import PgConnection


@pytest.fixture()
def schema():
    """An empty PostgreSQL schema and connections whose search_path is it."""
    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "m443_" + uuid4().hex[:12]
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


def _lock_timeout(conn: PgConnection) -> str:
    return conn.execute("SHOW lock_timeout").fetchone()[0]


def test_a_failed_lock_does_not_keep_the_migration_lock_timeout_issue_443(schema, monkeypatch):
    conn = schema()
    holder = schema()
    before = _lock_timeout(conn)
    # Another process is migrating: it holds the same advisory lock (same schema, same key).
    holder.execute(f"SELECT pg_advisory_lock({migrate._LOCK_KEY})")
    monkeypatch.setenv("DB_MIGRATION_LOCK_TIMEOUT_S", "1")
    try:
        with pytest.raises(psycopg.errors.LockNotAvailable):
            migrate.upgrade(conn)
        assert _lock_timeout(conn) == before
    finally:
        holder.execute(f"SELECT pg_advisory_unlock({migrate._LOCK_KEY})")


def test_the_lock_timeout_is_reset_after_a_successful_upgrade_issue_443(schema, monkeypatch):
    # Control: the normal path still migrates and leaves lock_timeout as it was.
    conn = schema()
    before = _lock_timeout(conn)
    monkeypatch.setenv("DB_MIGRATION_LOCK_TIMEOUT_S", "1")
    report = migrate.upgrade(conn)
    assert report.after == report.target
    assert _lock_timeout(conn) == before
