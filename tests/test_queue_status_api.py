"""Tests for GET /api/queue/status (ADR-0048).

Locks: counts reflect real GROUP BY data, the three guaranteed keys,
oldest-queued timing, worker staleness against the lease timeout,
and the route answers the same shape on SQLite and PostgreSQL via temp_db.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import api.queue_loop as queue_loop


def _insert_job(
    db,
    job_id: str,
    status: str,
    created_at: str,
    *,
    worker_id: str | None = None,
    heartbeat_at: str | None = None,
) -> None:
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, worker_id, heartbeat_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, f"{job_id}.txt", status, created_at, created_at, worker_id, heartbeat_at),
    )
    conn.commit()


def test_empty_queue_reports_zero_counts(temp_db, temp_db_client):
    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["counts"] == {"queued": 0, "processing": 0, "failed": 0}
    assert data["queue"]["depth"] == 0
    assert data["queue"]["oldest_queued_job_id"] is None
    assert data["queue"]["oldest_queued_seconds"] is None
    assert data["workers"] == []


def test_counts_reflect_real_rows(temp_db, temp_db_client):
    now = temp_db.now_iso()
    _insert_job(temp_db, "q1", "queued", now)
    _insert_job(temp_db, "q2", "queued", now)
    _insert_job(temp_db, "p1", "processing", now)
    _insert_job(temp_db, "f1", "failed", now)
    _insert_job(temp_db, "r1", "for_review", now)
    _insert_job(temp_db, "r2", "for_review", now)
    _insert_job(temp_db, "r3", "for_review", now)

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["counts"]["queued"] == 2
    assert data["counts"]["processing"] == 1
    assert data["counts"]["failed"] == 1
    assert data["counts"]["for_review"] == 3
    assert data["queue"]["depth"] == 2


def test_oldest_queued_job_is_the_one_with_earliest_created_at(temp_db, temp_db_client):
    now = temp_db.now_iso()
    _insert_job(temp_db, "new", "queued", now)
    _insert_job(temp_db, "old", "queued", "2020-01-01T00:00:00+00:00")

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["queue"]["oldest_queued_job_id"] == "old"
    assert data["queue"]["oldest_queued_seconds"] > 1000000


def test_worker_heartbeat_reports_age_and_activity(temp_db, temp_db_client):
    now = temp_db.now_iso()
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=now)

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["workers"]) == 1
    assert data["workers"][0]["worker_id"] == "w1"
    assert data["workers"][0]["running_jobs"] == 1
    assert data["workers"][0]["oldest_heartbeat_seconds_ago"] < 5
    assert data["workers"][0]["stale"] is False


def test_worker_with_expired_heartbeat_is_marked_stale(temp_db, temp_db_client, monkeypatch):
    monkeypatch.setattr("api.routes.queue.LEASE_TIMEOUT_S", 10)
    old_hb = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    now = temp_db.now_iso()
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=old_hb)

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["workers"][0]["stale"] is True


def test_two_workers_are_reported_separately(temp_db, temp_db_client):
    now = temp_db.now_iso()
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=now)
    _insert_job(temp_db, "p2", "processing", now, worker_id="w2", heartbeat_at=now)

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["workers"]) == 2
    assert {w["worker_id"] for w in data["workers"]} == {"w1", "w2"}


def test_role_and_backend_are_reported(temp_db, temp_db_client):
    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == queue_loop.role()
    assert data["backend"] == temp_db.backend()


def test_max_depth_reflects_the_configured_limit(temp_db, temp_db_client, monkeypatch):
    monkeypatch.setattr("api.routes.queue._QUEUE_MAX_DEPTH", 7)

    resp = temp_db_client.get("/api/queue/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["queue"]["max_depth"] == 7
