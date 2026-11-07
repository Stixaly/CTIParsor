"""scripts/migrate_rules_to_postgres.py (issue #534): a rule_text row whose rule the SQLite
source does not hold is left out and counted, instead of failing the copy on the
foreign key rule_text.rule_id -> detection_rules(id) (the same fix as #466 for jobs).

The target is a disposable PostgreSQL schema (CTIPARSOR_TEST_DATABASE_URL); the
source is a small SQLite file written by the test."""
from __future__ import annotations

import os
import sqlite3
from uuid import uuid4

import psycopg
import pytest

from scripts import migrate_rules_to_postgres as migrate


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
    """A rule store with one rule and two texts: one of the rule, one of a rule the store does not hold."""
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE detection_rules (id TEXT PRIMARY KEY, corpus TEXT NOT NULL,
                                      native_key TEXT NOT NULL, title TEXT NOT NULL);
        CREATE TABLE rule_text (rule_id TEXT PRIMARY KEY, body TEXT NOT NULL);
        INSERT INTO detection_rules VALUES ('r-1', 'sigma', 'native-1', 'Encoded PowerShell');
        INSERT INTO rule_text VALUES ('r-1', 'encoded powershell command line');
        INSERT INTO rule_text VALUES ('r-ghost', 'text of a rule that is not in the store');
        """
    )
    con.commit()
    con.close()
    return path


def test_orphan_rule_text_is_skipped_and_counted_issue_534(pg_target, tmp_path, capsys):
    url, schema = pg_target
    source = _make_source(tmp_path / "cti_stix.db")

    rc = migrate.main(["--sqlite", str(source), "--postgres", url])
    captured = capsys.readouterr()

    assert rc == 0
    # The orphan is named and counted on stderr, and the copy goes on.
    assert "rule_text: 1 row(s) whose rule is absent from the source - skipped" in captured.err
    assert "[migrate] committed" in captured.out

    with psycopg.connect(url, options=f"-c search_path={schema}") as conn:
        texts = conn.execute("SELECT rule_id FROM rule_text ORDER BY rule_id").fetchall()
    assert texts == [("r-1",)]
