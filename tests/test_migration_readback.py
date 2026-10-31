"""scripts/migration_readback.py: what the seed wrote reads back through this
code's routes, the expectations derived from the rows the seed wrote, and a
route that no longer returns a value is named (ADR-0094 item 2)."""
from __future__ import annotations

import json
import os
import shutil
from uuid import uuid4

import pytest

from api import migrate
from api import migrations as history
from scripts import migration_readback as rb
from scripts import migration_seed as ms


@pytest.fixture()
def release_11(monkeypatch, tmp_path):
    """A database v0.1.0 created (schema version 11) and seeded, then brought
    to this code's version: what the API reads at its first start after the
    upgrade.  api.db points at it, as temp_db does."""
    import psycopg

    import api.db as db

    url = (os.getenv("CTIPARSOR_TEST_DATABASE_URL") or "").strip()
    if not url:
        pytest.fail("CTIPARSOR_TEST_DATABASE_URL is required (ADR-0053)")
    name = "r_" + uuid4().hex[:12]
    monkeypatch.setattr(db, "DATABASE_URL", url)
    monkeypatch.setattr(db, "_PG_SCHEMA", name)
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{name}"')
    db.reset_connections()
    conn = db.get_conn()
    known = history.load()
    with monkeypatch.context() as m:
        m.setattr(history, "load", lambda: known[:11])
        migrate.upgrade(conn)
    seeded = ms.seed(conn, tmp_path)
    migrate.upgrade(conn)
    yield seeded
    db.reset_connections()
    with psycopg.connect(url, autocommit=True) as admin:
        admin.execute(f'DROP SCHEMA "{name}" CASCADE')


def test_every_seeded_row_reads_back_through_the_routes(temp_db, temp_db_client, tmp_path):
    seeded = ms.seed(temp_db.get_conn(), tmp_path)
    result = rb.read_back(temp_db_client, seeded)
    assert result.mismatches == []
    assert result.skipped == []
    assert result.passed > 300


def test_a_value_a_route_no_longer_returns_is_named(temp_db, temp_db_client, tmp_path):
    conn = temp_db.get_conn()
    seeded = ms.seed(conn, tmp_path)
    conn.execute("UPDATE entities SET accepted = NULL WHERE id = ?", (ms._e("a-tool"),))
    conn.execute("UPDATE jobs SET bundle_validation = 'unverified' WHERE id = ?", (ms.JOB_A,))
    conn.execute("DELETE FROM entity_overrides WHERE action = 'deny'")
    conn.execute("UPDATE progress_events SET data = '{}' WHERE event_type = 'queued'")
    (tmp_path / "uploads" / f"{ms.JOB_A}.txt").write_bytes(b"another file")

    result = rb.read_back(temp_db_client, seeded)
    a = f"/api/jobs/{ms.JOB_A}"
    assert len(result.mismatches) == 5, result.mismatches
    assert f"GET {a}/entities [{ms._e('a-tool')}] accepted: expected True, got None" in result.mismatches
    assert f"GET {a}/bundle X-Bundle-Validation: expected 'validated', got 'unverified'" in result.mismatches
    assert f"GET /api/overrides [{ms.fixed_uuid4('override', 'deny')}]: not returned" in result.mismatches
    assert sum(m.startswith(f"GET {a}/source sha256 (uploads/{ms.JOB_A}.txt): expected '")
               for m in result.mismatches) == 1
    assert sum(m.startswith(f"GET {a}/progress events: expected [('connected'") for m in result.mismatches) == 1


def test_the_expectations_are_the_payloads_the_seed_wrote(temp_db, temp_db_client, tmp_path):
    """A release's own Stage 4 builds seeded (ADR-0094 item 2): the read-back
    expects those, not this code's."""
    stage4 = tmp_path / "old" / "tests" / "fixtures" / "stage4_reference"
    shutil.copytree(ms.STAGE4, stage4)
    path = stage4 / "expected" / "long_distance.json"
    canon = json.loads(path.read_text(encoding="utf-8"))
    canon["objects"][0]["x_release"] = "v0.2.0"
    path.write_text(json.dumps(canon), encoding="utf-8")
    seeded = ms.seed(temp_db.get_conn(), tmp_path, ms.release_stage4(tmp_path / "old"))

    result = rb.read_back(temp_db_client, seeded)
    assert result.mismatches == [] and result.passed > 300
    served = temp_db_client.get(f"/api/jobs/{ms.JOB_A}/bundle").json()
    assert served["objects"][0]["x_release"] == "v0.2.0"


def test_an_older_release_reads_back_without_what_it_had_no_column_for(release_11, api_client):
    result = rb.read_back(api_client, release_11)
    assert result.mismatches == []
    assert result.skipped == []
    assert result.passed > 250
    # Job C was in enrich mode; v0.1.0 had no pipeline_mode: nothing expects it.
    assert all("pipeline_mode" not in rb.expected_fields(job, rb._JOB) for job in release_11.rows["jobs"])


def test_the_entry_point_starts_the_app_and_writes_the_result(temp_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CTIPARSOR_ROLE", "api")                # no queue loop
    seeded = ms.seed(temp_db.get_conn(), tmp_path)
    (tmp_path / "seeded.json").write_text(seeded.to_json(), encoding="utf-8")
    assert rb.main([str(tmp_path / "seeded.json"), str(tmp_path / "result.json")]) == 0
    result = json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))
    assert result["mismatches"] == [] and result["passed"] > 300
    assert rb.main([str(tmp_path / "seeded.json")]) == 2


def test_the_expectations_follow_the_route_s_own_conversions():
    row = {"id": "e1", "accepted": 0, "control_sample": 1, "value": "x", "decided_at": "t"}
    assert rb.expected_fields(row, rb._ENTITY) == {"id": "e1", "accepted": False, "control_sample": True,
                                                   "value": "x"}
    assert rb.expected_fields({"accepted": None, "evidence_label": None}, rb._RELATIONSHIP) == {
        "accepted": None, "evidence_label": "reported"}
    assert rb._sse("event: connected\ndata: {}\n\nid: 7\nevent: done\ndata: {\"a\": 1}\n\n") == [
        ("connected", "{}"), ("done", '{"a": 1}')]
