"""/api/thresholds (ADR-0051) — read, recalibrate, hand-set, clear.

Runs on the isolated temp database on both engines.  The report shape is the
same the CLI prints; here the contract is that nothing is written unless
`apply` is asked for, and that a write is visible to the runtime lookup.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import pipeline.thresholds as thresholds


@pytest.fixture(autouse=True)
def _fresh_cache():
    thresholds.reload()
    yield
    thresholds.reload()


def _seed_split(db, job_id: str = "job-1") -> None:
    """640 gliner/malware decisions: 50 % accepted below 0.60, 95 % above."""
    conn = db.get_conn()
    now = db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        (job_id, "r.pdf", "for_review", now, now),
    )
    rows = []
    for s in range(40, 60):
        rows += [(s / 100, 1), (s / 100, 0)]
    for s in range(60, 90):
        rows += [(s / 100, 1)] * 19 + [(s / 100, 0)]
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(str(uuid4()), job_id, f"e{i}", "malware", "", conf, acc, "gliner") for i, (conf, acc) in enumerate(rows)],
    )
    conn.commit()


def test_get_reports_defaults_and_no_rows_on_a_fresh_store(temp_db, temp_db_client):
    resp = temp_db_client.get("/api/thresholds")
    assert resp.status_code == 200
    data = resp.json()
    assert data["enabled"] is True
    assert data["defaults"] == {"cyner": 0.70, "gliner": 0.40}
    assert data["auto_accept_level"] == 0.90
    assert data["rows"] == []


def test_recalibrate_is_a_dry_run_unless_asked(temp_db, temp_db_client):
    _seed_split(temp_db)
    resp = temp_db_client.post("/api/thresholds/recalibrate", json={"min_samples": 100})
    assert resp.status_code == 200
    data = resp.json()
    assert data["applied"] is False and data["written"] == 0
    [p] = data["proposals"]
    assert (p["source"], p["entity_type"], p["status"], p["proposed"]) == ("gliner", "malware", "ok", 0.60)
    assert temp_db_client.get("/api/thresholds").json()["rows"] == []
    assert thresholds.get_threshold("gliner", "malware", 0.40) == 0.40


def test_recalibrate_with_apply_writes_and_the_runtime_sees_it(temp_db, temp_db_client):
    _seed_split(temp_db)
    resp = temp_db_client.post("/api/thresholds/recalibrate", json={"min_samples": 100, "apply": True})
    assert resp.status_code == 200
    assert resp.json()["written"] == 1

    rows = temp_db_client.get("/api/thresholds").json()["rows"]
    assert len(rows) == 1
    assert (rows[0]["source"], rows[0]["entity_type"], rows[0]["threshold"]) == ("gliner", "malware", 0.60)
    assert rows[0]["origin"] == "calibrated" and rows[0]["sample_size"] == 640
    assert thresholds.get_threshold("gliner", "malware", 0.40) == 0.60


def test_recalibrate_rejects_a_bad_target_or_sample_floor(temp_db, temp_db_client):
    assert temp_db_client.post("/api/thresholds/recalibrate", json={"target_precision": 1.5}).status_code == 400
    assert temp_db_client.post("/api/thresholds/recalibrate", json={"target_precision": 0}).status_code == 400
    assert temp_db_client.post("/api/thresholds/recalibrate", json={"min_samples": 0}).status_code == 400


def test_put_hand_sets_a_cutoff_and_delete_restores_the_default(temp_db, temp_db_client):
    resp = temp_db_client.put("/api/thresholds/cyner/malware", json={"threshold": 0.85})
    assert resp.status_code == 200
    assert resp.json()["origin"] == "manual"
    assert thresholds.get_threshold("cyner", "malware", 0.70) == 0.85
    [row] = temp_db_client.get("/api/thresholds").json()["rows"]
    assert row["origin"] == "manual" and row["threshold"] == 0.85

    resp = temp_db_client.delete("/api/thresholds/cyner/malware")
    assert resp.status_code == 200
    assert resp.json()["default"] == 0.70
    assert thresholds.get_threshold("cyner", "malware", 0.70) == 0.70
    assert temp_db_client.delete("/api/thresholds/cyner/malware").status_code == 404


def test_put_validates_source_type_and_range(temp_db, temp_db_client):
    assert temp_db_client.put("/api/thresholds/llm/malware", json={"threshold": 0.5}).status_code == 400
    assert temp_db_client.put("/api/thresholds/gliner/not_a_type", json={"threshold": 0.5}).status_code == 400
    assert temp_db_client.put("/api/thresholds/gliner/malware", json={"threshold": 1.5}).status_code == 400
    assert temp_db_client.put("/api/thresholds/gliner/malware", json={"threshold": -0.1}).status_code == 400
    assert temp_db_client.get("/api/thresholds").json()["rows"] == []
