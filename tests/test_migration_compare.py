"""scripts/migration_compare.py: after this code's migrations, every row a
release's database held is still there with the same values, and a migration
that drops, blanks or rewrites one is caught, value by value (ADR-0094 item 2)."""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from api import migrate
from api import migrations as history
from api.db_backend import PgConnection
from scripts import migration_compare as mc
from scripts import migration_seed as ms


@pytest.fixture()
def schema():
    """An empty PostgreSQL schema and a connection whose search_path is it."""
    import psycopg

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "c_" + uuid4().hex[:12]
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{name}"')
    conn = PgConnection(url, schema=name)
    yield conn
    conn.close()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{name}" CASCADE')


def release_at(conn: PgConnection, version: int, monkeypatch) -> None:
    """The database a release at `version` created: its init_db() applied the
    migrations it knew, and recorded them."""
    known = history.load()
    with monkeypatch.context() as m:
        m.setattr(history, "load", lambda: known[:version])
        migrate.upgrade(conn)


def _lossy(version: int) -> history.Migration:
    return history.Migration(
        version=version, name="lossy", store="jobs",
        statements=(
            "UPDATE entities SET context = '' WHERE source = 'llm'",
            "DELETE FROM review_decisions WHERE job_id NOT IN (SELECT id FROM jobs)",
            "ALTER TABLE cve_cache DROP COLUMN cvss_vector",
            "UPDATE jobs SET status = 'error' WHERE status = 'failed'",
        ),
        is_applied=lambda c: not history.column_exists(c, "cve_cache", "cvss_vector"))


# ── A real migration ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("version", [11, history.latest_version()])
def test_a_seeded_release_migrates_with_every_value_kept(schema, monkeypatch, version):
    release_at(schema, version, monkeypatch)
    ms.seed(schema)
    before = mc.snapshot(schema)
    migrate.upgrade(schema)
    result = mc.compare(before, mc.snapshot(schema))
    assert result.ok, "\n".join(mc.summary(result))
    assert result.applied == list(range(version + 1, history.latest_version() + 1))
    assert result.rows == sum(len(t.rows) for t in before.values()) and result.values > result.rows
    if version == 11:                                       # v0.1.0: versions 12 and 13 apply
        assert result.new_tables == ["job_baselines"]
        assert result.new_columns["jobs"] == ["review_revision", "bundle_review_revision", "bundle_build_json",
                                              "pipeline_mode"]
        assert result.new_rows == {"schema_migrations": 2}
    else:
        assert (result.new_tables, result.new_columns, result.new_rows) == ([], {}, {})


def test_a_migration_that_loses_data_is_caught_value_by_value(schema, monkeypatch):
    migrate.upgrade(schema)
    seeded = ms.seed(schema)
    before = mc.snapshot(schema)
    known = history.load()
    monkeypatch.setattr(history, "load", lambda: [*known, _lossy(len(known) + 1)])
    migrate.upgrade(schema)
    after = mc.snapshot(schema)

    result = mc.compare(before, after)
    orphan = seeded.rows["review_decisions"][-1]["id"]
    assert sorted(d.line() for d in result.differences) == sorted([
        f"entities [id={ms._e('a-tool')!r}] context: 'the tool Rclone on the file server' -> ''",
        f"jobs [id={ms.JOB_A!r}] review_revision: 9 -> 11",   # version 12's trigger, once per row updated
        f"jobs [id={ms.JOB_D!r}] status: 'failed' -> 'error'",
        "cve_cache.cvss_vector: column dropped",
        f"review_decisions [id={orphan}]: row missing",
    ])
    assert not result.ok

    # Declared for the version that ran: listed with its reason, no longer a failure.
    lossy = len(known) + 1
    declared = mc.compare(before, after, {lossy: {"jobs.status": "failed is now error",
                                                  "review_decisions.*": "orphans dropped"},
                                          3: {"entities.context": "not this run's"}})
    assert {d.line() for d in declared.expected} == {
        f"jobs [id={ms.JOB_D!r}] status: 'failed' -> 'error'  (expected, version {lossy}: failed is now error)",
        f"review_decisions [id={orphan}]: row missing  (expected, version {lossy}: orphans dropped)",
    }
    assert len(declared.differences) == 3


def test_a_retyped_column_is_a_difference_unless_declared(schema):
    migrate.upgrade(schema)
    ms.seed(schema)
    before = mc.snapshot(schema)
    schema.execute_script("ALTER TABLE entities ALTER COLUMN accepted TYPE boolean USING accepted::boolean")
    schema.execute("INSERT INTO schema_migrations (version, name, checksum, how, applied_at) VALUES (?, ?, ?, ?, ?)",
                   (99, "flags", "", "applied", ""))
    after = mc.snapshot(schema)

    # 1 and True, 0 and False are equal values in Python: the type tells.
    assert [d.line() for d in mc.compare(before, after).differences] == [
        "entities.accepted: retyped integer -> boolean"]
    declared = mc.compare(before, after, {99: {"entities.accepted": "a decision is a boolean"}})
    assert declared.ok and [d.line() for d in declared.expected] == [
        "entities.accepted: retyped integer -> boolean  (expected, version 99: a decision is a boolean)"]


def test_a_sequence_behind_its_column_is_a_difference(schema):
    migrate.upgrade(schema)
    seeded = ms.seed(schema)
    tables = mc.snapshot(schema)
    assert mc.sequence_differences(schema, tables) == (2, [])
    top = max(row["id"] for row in seeded.rows["review_decisions"])
    schema.execute_script("ALTER TABLE review_decisions ALTER COLUMN id RESTART WITH 1")   # as a rebuilt table's
    checked, stuck = mc.sequence_differences(schema, tables)
    assert checked == 2 and [d.line() for d in stuck] == [
        f"review_decisions.id: its sequence gives 1 next, not above the highest value stored ({top}): "
        "the next row collides"]
    assert mc.sequence_differences(schema, ["jobs"]) == (0, [])             # only the tables named


# ── Values and keys ──────────────────────────────────────────────────────────

def test_values_are_made_comparable():
    assert mc.comparable({"b": 1, "a": [1, "é"]}) == '{"a": [1, "é"], "b": 1}'
    assert mc.comparable([2, 1]) == "[2, 1]"
    assert mc.comparable(datetime(2026, 10, 20, 9, 14, 3, 512345, tzinfo=timezone.utc)) \
        == "2026-10-20T09:14:03.512345+00:00"
    assert mc.comparable(date(2026, 10, 20)) == "2026-10-20"
    assert mc.comparable(b"\x00\xff") == mc.comparable(memoryview(b"\x00\xff")) == "00ff"
    assert mc.comparable(Decimal("0.10")) == "0.10"
    assert mc.comparable(UUID(int=1)) == "00000000-0000-0000-0000-000000000001"
    for kept in (None, True, 7, 0.62, "text"):
        assert mc.comparable(kept) == kept


def test_a_snapshot_reads_json_dates_bytes_and_keyless_rows(schema):
    schema.execute("SET TIME ZONE 'Asia/Tokyo'")              # the snapshot reads in UTC whatever the zone
    schema.execute("CREATE TABLE things (j jsonb, k json, at timestamptz, raw bytea, n numeric)")
    for _ in range(2):
        schema.execute("INSERT INTO things VALUES (?, ?, ?, ?, ?)",
                       ('{"b": 1, "a": 2}', "[1, 2]", "2026-10-20 09:14:03+00", b"\x00\xff", Decimal("0.10")))
    table = mc.snapshot(schema)["things"]
    assert table.key == () and table.columns["j"] == "jsonb"
    row = {"j": '{"a": 2, "b": 1}', "k": "[1, 2]", "at": "2026-10-20T09:14:03+00:00", "raw": "00ff", "n": "0.10"}
    values = tuple(row.values())
    assert table.rows == {(*values, 1): row, (*values, 2): row}

    before = mc.snapshot(schema)
    schema.execute("DELETE FROM things WHERE ctid = (SELECT min(ctid) FROM things)")
    result = mc.compare(before, mc.snapshot(schema))
    assert [d.line() for d in result.differences] == [
        "things [row '{\"a\": 2, \"b\": 1}', '[1, 2]', '2026-10-20T09:14:03+00:00', '00ff', '0.10']: row missing"]


def _table(rows: list[dict], key: tuple[str, ...] = ("id",)) -> mc.Table:
    columns = {c: "text" for c in rows[0]}
    return mc.Table(columns, key, mc._keyed(rows, key, tuple(columns)))


def test_what_a_migration_adds_is_listed_and_a_dropped_table_is_a_difference():
    before = {"jobs": _table([{"id": "a", "status": "completed"}]),
              "notes": _table([{"id": "n1", "body": "x"}, {"id": "n2", "body": "y"}])}
    after = {"jobs": _table([{"id": "a", "status": "completed", "mode": "full"},
                             {"id": "b", "status": "queued", "mode": "full"}]),
             "baselines": _table([{"id": "a"}])}
    result = mc.compare(before, after)
    assert [d.line() for d in result.differences] == ["notes: table dropped"]
    assert (result.new_tables, result.new_columns, result.new_rows) == (["baselines"], {"jobs": ["mode"]},
                                                                        {"jobs": 1})
    assert (result.tables, result.rows, result.values) == (2, 3, 2)
    assert mc.summary(result) == [
        "content: 2 tables, 3 rows, 2 values compared; 1 difference(s)",
        "  DIFF notes: table dropped",
        "  new tables: baselines",
        "  new columns in jobs: mode",
        "  new rows in jobs: 1",
    ]
    assert mc.summary(result, "after the read-back")[0] == \
        "after the read-back: 2 tables, 3 rows, 2 values compared; 1 difference(s)"


def test_a_long_value_is_cut_in_the_report():
    before = {"jobs": _table([{"id": "a", "bundle_json": "x" * 500}])}
    after = {"jobs": _table([{"id": "a", "bundle_json": "x" * 499}])}
    line = mc.compare(before, after).differences[0].line()
    assert line.startswith("jobs [id='a'] bundle_json: 'xxxx") and "... (500 chars) -> " in line
    assert line.endswith("... (499 chars)") and len(line) < 200
