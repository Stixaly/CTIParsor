"""The CLI brings its database to this code's schema before a run (audit 8.1.11).

On a database with no tables yet, `main.py` used to call the store
unreachable for the relationship policy and fail Stage 2f on `relation
"cve_cache" does not exist`: only the API, the workers and `bootstrap` ran the
migrations (ADR-0077).
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import main


@pytest.fixture()
def blank_schema(monkeypatch):
    """An empty PostgreSQL schema, the CLI's database: no table, no record."""
    import psycopg

    import api.db as db

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    schema = "t_" + uuid4().hex[:12]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    monkeypatch.setattr(db, "DATABASE_URL", url)
    monkeypatch.setattr(db, "_PG_SCHEMA", schema)
    db.reset_connections()
    yield db
    db.reset_connections()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{schema}" CASCADE')


def test_the_cli_migrates_a_blank_database(blank_schema):
    from api import migrations

    assert main.prepare_store() is True

    conn = blank_schema.get_conn()
    version = conn.execute("SELECT max(version) AS v FROM schema_migrations").fetchone()["v"]
    assert version == len(migrations.load())
    # The table Stage 2f failed on, and the one the policy is read from.
    assert conn.execute("SELECT count(*) AS n FROM cve_cache").fetchone()["n"] == 0
    from api.db import load_relationship_policy
    assert load_relationship_policy() is None


def test_without_database_url_the_cli_says_so_and_runs(monkeypatch, capsys):
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    assert main.prepare_store() is False
    assert "DATABASE_URL non défini" in capsys.readouterr().out


def test_an_unreachable_database_is_reported_once(monkeypatch, capsys):
    import api.db as db

    # Port 1 on the loopback: refused at once, no timeout to wait for.
    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://nobody@127.0.0.1:1/nothing")
    db.reset_connections()
    try:
        assert main.prepare_store() is False
    finally:
        db.reset_connections()
    assert "Base injoignable (OperationalError)" in capsys.readouterr().out


def test_a_database_the_code_cannot_migrate_stops_the_cli(monkeypatch):
    import api.db as db
    from api.migrate import DatabaseNewerThanCode

    def newer() -> None:
        raise DatabaseNewerThanCode("the database is at version 99, this code knows 10")

    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://u@127.0.0.1:5432/d")
    monkeypatch.setattr(db, "init_db", newer)
    with pytest.raises(SystemExit) as exc:
        main.prepare_store()
    assert "version 99" in str(exc.value)
