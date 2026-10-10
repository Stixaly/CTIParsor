"""The state volume remembers which cluster each database was on (ADR-0077 part B, 9).

PostgreSQL replaced without moving the data leaves an empty database behind
the same address; the next start must stop there instead of migrating it into
a fresh install.  Against throwaway PostgreSQL schemas; the state directory is
the test's tmp_path (conftest).
"""
import json
import os
from uuid import uuid4

import pytest

from api import db_identity, migrate
from api import migrations as history
from api.db_backend import PgConnection


@pytest.fixture()
def schema():
    """A connection whose search_path is a new, empty PostgreSQL schema."""
    import psycopg

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "i_" + uuid4().hex[:12]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{name}"')
    conn = PgConnection(url, schema=name)
    yield conn
    conn.close()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{name}" CASCADE')


def _identity(tmp_path) -> dict:
    return json.loads((tmp_path / "state" / db_identity.FILE).read_text(encoding="utf-8"))


def _plant(tmp_path, conn, **entry):
    path = tmp_path / "state" / db_identity.FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({db_identity.address(conn): entry}), encoding="utf-8")


def test_every_start_records_the_cluster_and_the_version(schema, tmp_path):
    migrate.upgrade(schema)
    entry = _identity(tmp_path)[db_identity.address(schema)]
    assert entry["system_identifier"] == db_identity.system_identifier(schema)
    assert entry["schema_version"] == history.latest_version()


def test_an_empty_database_on_another_cluster_stops_the_start(schema, tmp_path):
    _plant(tmp_path, schema, system_identifier="1234", schema_version=10, recorded_at="2026-10-01")
    with pytest.raises(migrate.ClusterChanged, match="make db-upgrade"):
        migrate.upgrade(schema)
    # Nothing was migrated into a fresh install, and the record still names the old cluster.
    assert not history.table_exists(schema, "jobs")
    assert _identity(tmp_path)[db_identity.address(schema)]["system_identifier"] == "1234"


def test_a_database_restored_on_another_cluster_is_accepted_and_recorded(schema, tmp_path):
    migrate.upgrade(schema)              # tables present, as after pg_restore
    schema.execute("DELETE FROM schema_migrations")   # a dump from before ADR-0077 has no record
    _plant(tmp_path, schema, system_identifier="1234", schema_version=10)
    migrate.upgrade(schema)
    assert _identity(tmp_path)[db_identity.address(schema)]["system_identifier"] \
        == db_identity.system_identifier(schema)


@pytest.mark.parametrize("entry", [
    {"schema_version": 10},                                   # same cluster: filled in below
    {"system_identifier": "1234", "schema_version": 0},       # nothing had been migrated there
    {"system_identifier": "1234"},                            # no version recorded
])
def test_an_empty_database_with_nothing_lost_starts(schema, tmp_path, entry):
    if "system_identifier" not in entry:
        entry = {**entry, "system_identifier": db_identity.system_identifier(schema)}
    _plant(tmp_path, schema, **entry)
    assert migrate.upgrade(schema).after == history.latest_version()


def test_another_address_is_not_this_one(schema, tmp_path):
    path = tmp_path / "state" / db_identity.FILE
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"postgres:5432/ctiparsor/public": {
        "system_identifier": "1234", "schema_version": 10}}), encoding="utf-8")
    migrate.upgrade(schema)
    assert set(_identity(tmp_path)) == {"postgres:5432/ctiparsor/public", db_identity.address(schema)}


def test_the_record_never_blocks_a_start_on_its_own_problems(schema, tmp_path, monkeypatch, caplog):
    path = tmp_path / "state" / db_identity.FILE
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    assert migrate.upgrade(schema).after == history.latest_version()
    assert "unreadable" in caplog.text

    # A cluster that hides its identifier: no refusal, no record.
    other = tmp_path / "other"
    monkeypatch.setenv("CTIPARSOR_STATE_DIR", str(other))
    monkeypatch.setattr(db_identity, "system_identifier", lambda conn: None)
    migrate.upgrade(schema)
    assert not (other / db_identity.FILE).exists()


def test_a_state_directory_that_cannot_be_written_is_logged(schema, tmp_path, monkeypatch, caplog):
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("", encoding="utf-8")
    monkeypatch.setenv("CTIPARSOR_STATE_DIR", str(blocked / "state"))
    assert migrate.upgrade(schema).after == history.latest_version()
    assert "could not record" in caplog.text
