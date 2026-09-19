"""
Integration tests for the PostgreSQL job store backend.

These tests verify that the job store runs correctly on PostgreSQL through the
same code paths used by the API: qmark placeholders, row access by name and
index, upserts, the transaction helper, the SSE resume id, and the two-store
split in the coverage code.

Tests are skipped if CTIPARSOR_TEST_DATABASE_URL is not set.
"""

from __future__ import annotations

import json
import os
import sqlite3

import pytest

pytestmark = pytest.mark.skipif(
    not (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip(),
    reason="CTIPARSOR_TEST_DATABASE_URL not set - PostgreSQL integration tests need a live server",
)


def _insert_job(db, job_id: str = "j1", **overrides) -> None:
    now = db.now_iso()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            (
                job_id,
                overrides.get("original_filename", "r.pdf"),
                overrides.get("status", "uploaded"),
                now,
                now,
            ),
        )


def test_backend_is_postgresql_and_stores_share_the_connection(temp_db):
    """ADR-0053: the rule store moved onto PostgreSQL too, so get_conn() and
    get_rule_conn() are the same connection to the same database now — kept
    as two accessors for a future split, not two engines today."""
    assert temp_db.backend() == "postgresql"
    assert temp_db.get_conn() is temp_db.get_rule_conn()
    assert type(temp_db.get_conn()).__name__ == "PgConnection"


def test_round_trip_row_access(temp_db):
    _insert_job(temp_db)
    conn = temp_db.get_conn()
    row = conn.execute("SELECT * FROM jobs WHERE id=?", ("j1",)).fetchone()
    assert row["id"] == "j1"
    assert row[0] == "j1"
    assert dict(row)["status"] == "uploaded"
    assert "created_at" in row.keys()

    cur = conn.execute("UPDATE jobs SET status=? WHERE id=?", ("done", "j1"))
    assert cur.rowcount == 1
    assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


def test_progress_event_ids_increase_and_resume(temp_db):
    _insert_job(temp_db)
    for i in range(1, 4):
        temp_db.emit_progress("j1", "stage", {"n": i})

    conn = temp_db.get_conn()
    rows = conn.execute(
        "SELECT id, event_type, data FROM progress_events WHERE job_id=? ORDER BY id", ("j1",)
    ).fetchall()
    assert len(rows) == 3
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids)
    assert len(set(ids)) == 3

    after = conn.execute(
        "SELECT id, event_type, data FROM progress_events WHERE job_id=? AND id>? ORDER BY id",
        ("j1", rows[0]["id"]),
    ).fetchall()
    assert len(after) == 2
    assert json.loads(after[-1]["data"]) == {"n": 3}


def test_policy_upsert_keeps_a_single_row(temp_db):
    conn = temp_db.get_conn()
    upsert_sql = (
        "INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?) "
        "ON CONFLICT (id) DO UPDATE SET policy_json = excluded.policy_json"
    )
    conn.execute(upsert_sql, ('{"a":1}',))
    conn.execute(upsert_sql, ('{"a":2}',))

    count = conn.execute("SELECT COUNT(*) FROM relationship_policy").fetchone()[0]
    assert count == 1
    policy = conn.execute("SELECT policy_json FROM relationship_policy WHERE id=1").fetchone()[0]
    assert policy == '{"a":2}'


def test_entity_upsert_do_nothing_is_idempotent(temp_db):
    _insert_job(temp_db)
    conn = temp_db.get_conn()
    insert_sql = (
        "INSERT INTO entities (id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING"
    )
    row = ("e1", "j1", "APT29", "threat_actor", "", 0.9, None, None, "auto")
    conn.executemany(insert_sql, [row])
    conn.executemany(insert_sql, [row])

    count = conn.execute("SELECT COUNT(*) FROM entities WHERE id='e1'").fetchone()[0]
    assert count == 1
    confidence = conn.execute("SELECT confidence FROM entities WHERE id='e1'").fetchone()[0]
    assert confidence == 0.9


def test_transaction_rolls_back_on_exception(temp_db):
    with pytest.raises(RuntimeError):
        with temp_db.transaction(temp_db.get_conn()) as c:
            c.execute(
                "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
                ("jx", "x.pdf", "uploaded", temp_db.now_iso(), temp_db.now_iso()),
            )
            raise RuntimeError("boom")

    conn = temp_db.get_conn()
    count = conn.execute("SELECT COUNT(*) FROM jobs WHERE id='jx'").fetchone()[0]
    assert count == 0

    with temp_db.transaction(temp_db.get_conn()) as c:
        c.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
            ("jy", "y.pdf", "uploaded", temp_db.now_iso(), temp_db.now_iso()),
        )

    count = conn.execute("SELECT COUNT(*) FROM jobs WHERE id='jy'").fetchone()[0]
    assert count == 1


def test_delete_job_cascades(temp_db):
    _insert_job(temp_db)
    conn = temp_db.get_conn()

    conn.execute(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, mitre_id, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("e1", "j1", "APT29", "threat_actor", "", 0.9, None, None, "auto"),
    )
    conn.execute(
        "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, confidence, accepted) "
        "VALUES (?,?,?,?,?,?,?)",
        ("r1", "j1", "APT29", "uses", "Cobalt Strike", 0.8, 1),
    )

    conn.execute("DELETE FROM jobs WHERE id=?", ("j1",))

    entity_count = conn.execute("SELECT COUNT(*) FROM entities WHERE job_id='j1'").fetchone()[0]
    assert entity_count == 0
    rel_count = conn.execute("SELECT COUNT(*) FROM relationships WHERE job_id='j1'").fetchone()[0]
    assert rel_count == 0


def test_coverage_reads_entities_from_the_job_store(temp_db):
    from models.detection import DetectionRule, Severity
    from pipeline.detection.coverage import compute_for_job
    from pipeline.detection.store import replace_corpus_rules

    replace_corpus_rules(
        temp_db.get_rule_conn(),
        "c1",
        [
            DetectionRule(
                id="c1:r1",
                corpus="c1",
                title="rule r1",
                technique_ids=["T1059"],
                severity=Severity.HIGH,
                license="MIT",
                raw="title: rule r1\nlogsource: c1\n",
            )
        ],
    )

    _insert_job(temp_db)
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("e1", "j1", "T1059", "technique", "", 1.0, "T1059", 1, "auto"),
    )

    result = compute_for_job(temp_db.get_rule_conn(), "j1", jobs_conn=temp_db.get_conn())
    assert result["techniques_total"] == 1
    assert result["cells"][0]["technique_id"] == "T1059"
    assert result["cells"][0]["rule_count"] >= 1

    # ADR-0053: unlike the pre-migration split (where the rule store's SQLite
    # file had no `entities` table and this had to fail loudly), the rule and
    # job tables now live in the same PostgreSQL database, so the omitted
    # jobs_conn falls back to `conn` and still finds them -- confirms the
    # consolidation didn't silently start double-counting or erroring.
    result_without_jobs_conn = compute_for_job(temp_db.get_rule_conn(), "j1")
    assert result_without_jobs_conn == result


def test_api_routes_answer_from_postgres(temp_db, temp_db_client):
    _insert_job(temp_db, "j1")

    r = temp_db_client.get("/api/jobs")
    assert r.status_code == 200
    assert [j["id"] for j in r.json()] == ["j1"]

    r = temp_db_client.get("/api/jobs/j1")
    assert r.status_code == 200
    assert r.json()["status"] == "uploaded"

    r = temp_db_client.get("/api/jobs/nope")
    assert r.status_code == 404

    r = temp_db_client.get("/api/jobs/j1/coverage")
    assert r.status_code == 200
    assert r.json()["techniques_total"] == 0


def test_migration_script_copies_a_sqlite_job_store(temp_db, tmp_path):
    """scripts/migrate_jobs_to_postgres.py is the one-shot tool an existing
    installation runs to move off the pre-ADR-0045 single-SQLite-file layout
    (ADR-0053 removed that layout from api.db itself, but the migration path
    off of it must keep working) -- build a legacy source file by hand with
    raw sqlite3, since api.db no longer knows how to create one.
    """
    src_path = tmp_path / "src.db"
    src = sqlite3.connect(str(src_path))
    src.executescript("""
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY, original_filename TEXT, status TEXT,
            created_at TEXT, updated_at TEXT
        );
        CREATE TABLE entities (
            id TEXT PRIMARY KEY, job_id TEXT, value TEXT, entity_type TEXT,
            context TEXT, confidence REAL, mitre_id TEXT, accepted INTEGER,
            source TEXT
        );
        CREATE TABLE relationships (
            id TEXT PRIMARY KEY, job_id TEXT, source_value TEXT,
            relationship_type TEXT, target_value TEXT, confidence REAL,
            accepted INTEGER
        );
        CREATE TABLE progress_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT,
            event_type TEXT, data TEXT, created_at TEXT
        );
        CREATE TABLE relationship_policy (
            id INTEGER PRIMARY KEY, policy_json TEXT
        );
    """)
    now = "2026-01-01T00:00:00+00:00"
    src.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("m1", "m.pdf", "uploaded", now, now),
    )
    src.execute(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, mitre_id, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("e1", "m1", "APT29", "threat_actor", "", 0.9, None, None, "auto"),
    )
    src.execute(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, mitre_id, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        ("e2", "m1", "T1059", "technique", "", 1.0, "T1059", 1, "auto"),
    )
    src.execute(
        "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, confidence, accepted) "
        "VALUES (?,?,?,?,?,?,?)",
        ("r1", "m1", "APT29", "uses", "Cobalt Strike", 0.8, 1),
    )
    for i in range(1, 4):
        src.execute(
            "INSERT INTO progress_events (job_id, event_type, data, created_at) VALUES (?,?,?,?)",
            ("m1", f"stage{i}", json.dumps({"n": i}), now),
        )
    src.execute(
        "INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?)",
        ('{"a":1}',),
    )
    src.commit()
    src.close()

    url = os.getenv("CTIPARSOR_TEST_DATABASE_URL")
    schema = temp_db._PG_SCHEMA
    url_with_schema = url + ("&" if "?" in url else "?") + "options=-c%20search_path%3D" + schema

    from scripts.migrate_jobs_to_postgres import main as migrate_main

    rc = migrate_main(["--sqlite", str(src_path), "--postgres", url_with_schema])
    assert rc == 0

    pg_conn = temp_db.get_conn()
    job_count = pg_conn.execute("SELECT COUNT(*) FROM jobs WHERE id='m1'").fetchone()[0]
    assert job_count == 1

    entity_count = pg_conn.execute("SELECT COUNT(*) FROM entities WHERE job_id='m1'").fetchone()[0]
    assert entity_count == 2

    rel_count = pg_conn.execute("SELECT COUNT(*) FROM relationships WHERE job_id='m1'").fetchone()[0]
    assert rel_count == 1

    event_count = pg_conn.execute("SELECT COUNT(*) FROM progress_events WHERE job_id='m1'").fetchone()[0]
    assert event_count == 3

    policy_count = pg_conn.execute("SELECT COUNT(*) FROM relationship_policy").fetchone()[0]
    assert policy_count == 1

    src_conn = sqlite3.connect(src_path)
    src_conn.row_factory = sqlite3.Row
    src_events = src_conn.execute("SELECT id FROM progress_events WHERE job_id='m1' ORDER BY id").fetchall()
    src_ids = [r[0] for r in src_events]
    src_conn.close()

    pg_events = pg_conn.execute("SELECT id FROM progress_events WHERE job_id='m1' ORDER BY id").fetchall()
    pg_ids = [r[0] for r in pg_events]
    assert pg_ids == src_ids

    temp_db.emit_progress("m1", "after", {})
    new_event = pg_conn.execute(
        "SELECT id FROM progress_events WHERE job_id='m1' AND event_type='after'"
    ).fetchone()
    assert new_event[0] > max(pg_ids)

    rc = migrate_main(["--sqlite", str(src_path), "--postgres", url_with_schema])
    assert rc == 1

    rc = migrate_main(["--sqlite", str(src_path), "--postgres", url_with_schema, "--append"])
    assert rc == 0

    job_count = pg_conn.execute("SELECT COUNT(*) FROM jobs WHERE id='m1'").fetchone()[0]
    assert job_count == 1
    entity_count = pg_conn.execute("SELECT COUNT(*) FROM entities WHERE job_id='m1'").fetchone()[0]
    assert entity_count == 2
