"""Tests for GET /api/queue/status (ADR-0048, ADR-0094 item 7).

Locks: counts reflect real GROUP BY data, the three guaranteed keys,
oldest-queued timing, worker staleness against the lease timeout,
and the route answers the same shape on SQLite and PostgreSQL via temp_db.
Every queue loop is listed, idle or busy, from its worker_heartbeats row; a
worker that holds a job without a row (the previous revision) from the job;
the freshest of the row heartbeat and the job heartbeats decides whether it
is stale; and the summary counts the live ones and their free slots.
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


def _insert_loop(
    db,
    worker_id: str,
    *,
    heartbeat_at: str | None = None,
    role: str = "worker",
    max_concurrent: int = 1,
) -> None:
    """A worker_heartbeats row, as api.queue_loop.stamp_worker writes it."""
    now = db.now_iso()
    db.get_conn().execute(
        "INSERT INTO worker_heartbeats (worker_id, role, max_concurrent, app_version, started_at, heartbeat_at) "
        "VALUES (?,?,?,?,?,?)",
        (worker_id, role, max_concurrent, "0.2.0", now, heartbeat_at or now),
    )


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


# ── Every queue loop, idle or busy (ADR-0094 item 7) ─────────────────────────

def test_an_idle_worker_is_listed_as_idle(temp_db, temp_db_client):
    _insert_loop(temp_db, "w-idle", max_concurrent=2)

    data = temp_db_client.get("/api/queue/status").json()
    assert data["workers"] == [{
        "worker_id": "w-idle", "state": "idle", "role": "worker", "max_concurrent": 2, "app_version": "0.2.0",
        "started_at": data["workers"][0]["started_at"], "running_jobs": 0,
        "heartbeat_seconds_ago": data["workers"][0]["heartbeat_seconds_ago"],
        "oldest_heartbeat_seconds_ago": None, "stale": False,
    }]
    assert data["workers"][0]["heartbeat_seconds_ago"] < 5
    assert data["worker_summary"] == {"alive": 1, "busy": 0, "idle": 1, "stale": 0, "capacity": 2, "idle_slots": 2}
    # The fields ADR-0048 published keep their names and meaning.
    assert {"role", "backend", "counts", "queue", "workers"} <= set(data)
    assert data["counts"] == {"queued": 0, "processing": 0, "failed": 0}


def test_a_busy_worker_counts_its_jobs_from_the_jobs_table(temp_db, temp_db_client):
    now = temp_db.now_iso()
    _insert_loop(temp_db, "w1", max_concurrent=2)
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=now)
    _insert_job(temp_db, "f1", "failed", now, worker_id="w1", heartbeat_at=now)    # finished: not running

    data = temp_db_client.get("/api/queue/status").json()
    [w1] = data["workers"]
    assert (w1["worker_id"], w1["state"], w1["running_jobs"], w1["stale"]) == ("w1", "busy", 1, False)
    assert w1["oldest_heartbeat_seconds_ago"] < 5
    assert data["worker_summary"] == {"alive": 1, "busy": 1, "idle": 0, "stale": 0, "capacity": 2, "idle_slots": 1}


def test_a_silent_worker_is_stale_and_leaves_the_capacity(temp_db, temp_db_client, monkeypatch):
    monkeypatch.setattr("api.routes.queue.LEASE_TIMEOUT_S", 10)
    old_hb = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    _insert_loop(temp_db, "w-dead", heartbeat_at=old_hb, max_concurrent=4)
    _insert_loop(temp_db, "w-live", max_concurrent=1)

    data = temp_db_client.get("/api/queue/status").json()
    assert [(w["worker_id"], w["state"], w["stale"]) for w in data["workers"]] == [
        ("w-live", "idle", False), ("w-dead", "stale", True)]                   # the live ones first
    assert data["workers"][1]["heartbeat_seconds_ago"] > 90
    assert data["worker_summary"] == {"alive": 1, "busy": 0, "idle": 1, "stale": 1, "capacity": 1, "idle_slots": 1}


def test_a_fresh_row_keeps_a_worker_alive_whatever_its_job_heartbeats(temp_db, temp_db_client, monkeypatch):
    monkeypatch.setattr("api.routes.queue.LEASE_TIMEOUT_S", 10)
    now = temp_db.now_iso()
    old_hb = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    _insert_loop(temp_db, "w1", heartbeat_at=now)
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=old_hb)

    [w1] = temp_db_client.get("/api/queue/status").json()["workers"]
    assert (w1["state"], w1["stale"], w1["running_jobs"]) == ("busy", False, 1)
    assert w1["heartbeat_seconds_ago"] < 5                                     # the row
    assert w1["oldest_heartbeat_seconds_ago"] > 90                             # the job


def test_a_fresh_job_heartbeat_keeps_a_worker_alive_whatever_its_row(temp_db, temp_db_client, monkeypatch):
    monkeypatch.setattr("api.routes.queue.LEASE_TIMEOUT_S", 10)
    now = temp_db.now_iso()
    old_hb = (datetime.now(timezone.utc) - timedelta(seconds=100)).isoformat()
    _insert_loop(temp_db, "w1", heartbeat_at=old_hb)
    _insert_job(temp_db, "p1", "processing", now, worker_id="w1", heartbeat_at=now)

    [w1] = temp_db_client.get("/api/queue/status").json()["workers"]
    assert (w1["state"], w1["stale"], w1["running_jobs"]) == ("busy", False, 1)
    assert w1["heartbeat_seconds_ago"] < 5                                     # the job
    assert w1["oldest_heartbeat_seconds_ago"] < 5


def test_a_worker_without_a_row_is_listed_from_the_job_it_holds(temp_db, temp_db_client):
    """A worker of the previous revision writes no worker_heartbeats row: during
    an upgrade it is still listed while it runs a job, and nobody can say how
    many slots it has."""
    now = temp_db.now_iso()
    _insert_loop(temp_db, "w-new", max_concurrent=1)
    _insert_job(temp_db, "p1", "processing", now, worker_id="w-old", heartbeat_at=now)

    data = temp_db_client.get("/api/queue/status").json()
    by_id = {w["worker_id"]: w for w in data["workers"]}
    assert set(by_id) == {"w-new", "w-old"}
    old = by_id["w-old"]
    assert (old["state"], old["running_jobs"]) == ("busy", 1)
    assert (old["role"], old["max_concurrent"], old["app_version"], old["started_at"]) == (None, None, None, None)
    assert by_id["w-new"]["state"] == "idle"
    assert data["worker_summary"] == {"alive": 2, "busy": 1, "idle": 1, "stale": 0, "capacity": None,
                                      "idle_slots": None}


def test_an_unlimited_worker_has_no_capacity_figure(temp_db, temp_db_client):
    _insert_loop(temp_db, "w-any", max_concurrent=0)                              # WORKER_MAX_CONCURRENT=0
    summary = temp_db_client.get("/api/queue/status").json()["worker_summary"]
    assert (summary["alive"], summary["capacity"], summary["idle_slots"]) == (1, None, None)


def test_a_running_loop_is_listed_and_gone_once_it_stops(temp_db, temp_db_client):
    """The loop writes its row, the route reads it: no list left empty while a worker waits."""
    loop = queue_loop.WorkerLoop(max_concurrent=3, worker_id="w-loop", spawn=lambda *a: None)
    loop.run_once()

    data = temp_db_client.get("/api/queue/status").json()
    [w] = data["workers"]
    assert (w["worker_id"], w["state"], w["role"], w["max_concurrent"]) == ("w-loop", "idle", "worker", 3)
    assert w["started_at"] == loop.started_at
    assert data["worker_summary"]["idle_slots"] == 3

    loop.forget()
    data = temp_db_client.get("/api/queue/status").json()
    assert data["workers"] == []
    assert data["worker_summary"] == {"alive": 0, "busy": 0, "idle": 0, "stale": 0, "capacity": 0, "idle_slots": 0}
