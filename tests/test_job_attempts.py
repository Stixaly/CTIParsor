"""A job counts its claims and is quarantined after JOB_MAX_ATTEMPTS (ADR-0097 item 20).

A claim increments `jobs.attempts`.  requeue_orphans requeues an expired job
only while it has been claimed fewer than JOB_MAX_ATTEMPTS times; the others
are marked failed, with a `done` event that names the reason.
"""

from __future__ import annotations

import json

import pytest

import api.queue_loop as queue_loop
from api.db import get_conn
from api.paths import uploads_dir

STALE = "2020-01-01T00:00:00+00:00"


@pytest.fixture
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    return temp_db


def _insert(job_id: str, status: str, *, attempts: int = 0, heartbeat_at: str | None = None,
            worker_id: str | None = None) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, worker_id, heartbeat_at, "
        "attempts) VALUES (?,?,?,?,?,?,?,?)",
        (job_id, f"{job_id}.txt", status, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z", worker_id,
         heartbeat_at, attempts),
    )
    conn.commit()


def _state(job_id: str):
    return get_conn().execute("SELECT status, attempts, worker_id FROM jobs WHERE id=?", (job_id,)).fetchone()


def _done_events(job_id: str) -> list[dict]:
    rows = get_conn().execute(
        "SELECT data FROM progress_events WHERE job_id=? AND event_type='done' ORDER BY id", (job_id,)).fetchall()
    return [json.loads(r[0]) for r in rows]


def test_a_claim_counts_one_attempt(db):
    _insert("j1", "queued")
    uploads_dir().joinpath("j1.txt").touch()

    assert queue_loop.claim_next_queued("w1") is not None

    state = _state("j1")
    assert (state["status"], state["attempts"], state["worker_id"]) == ("processing", 1, "w1")


def test_a_job_whose_lease_expired_is_requeued_below_the_limit(db, monkeypatch):
    monkeypatch.setattr(queue_loop, "JOB_MAX_ATTEMPTS", 3)
    _insert("j1", "processing", attempts=2, heartbeat_at=STALE, worker_id="w1")

    assert queue_loop.requeue_orphans() == 1

    state = _state("j1")
    assert (state["status"], state["attempts"], state["worker_id"]) == ("queued", 2, None)
    assert _done_events("j1") == []


def test_a_job_at_the_limit_is_failed_and_not_requeued(db, monkeypatch):
    monkeypatch.setattr(queue_loop, "JOB_MAX_ATTEMPTS", 3)
    _insert("j1", "processing", attempts=3, heartbeat_at=STALE, worker_id="w1")
    _insert("j2", "processing", attempts=1, heartbeat_at=STALE, worker_id="w2")

    assert queue_loop.requeue_orphans() == 1          # only j2 goes back to the queue

    assert _state("j1")["status"] == "failed"
    assert _state("j2")["status"] == "queued"
    assert _done_events("j1") == [{"status": "failed",
                                   "error": "quarantined after 3 attempts (JOB_MAX_ATTEMPTS)"}]
    assert _done_events("j2") == []


def test_a_job_that_keeps_killing_its_worker_stops_after_the_limit(db, monkeypatch):
    monkeypatch.setattr(queue_loop, "JOB_MAX_ATTEMPTS", 3)
    _insert("j1", "queued")
    uploads_dir().joinpath("j1.txt").touch()

    for _ in range(3):                                # each claim, then the worker dies: lease expires
        assert queue_loop.claim_next_queued("w") is not None
        get_conn().execute("UPDATE jobs SET heartbeat_at=? WHERE id='j1'", (STALE,))
        get_conn().commit()
        queue_loop.requeue_orphans()

    state = _state("j1")
    assert state["attempts"] == 3
    assert state["status"] == "failed"
    assert queue_loop.claim_next_queued("w") is None  # nothing left to claim: the loop does not spin on it


def test_a_clean_stop_gives_the_attempt_back_and_a_lost_lease_keeps_it(db, monkeypatch):
    """Three clean stops, then one lost lease: the job is requeued, not quarantined (ADR-0097 item 20)."""
    monkeypatch.setattr(queue_loop, "JOB_MAX_ATTEMPTS", 3)
    _insert("j1", "queued")
    uploads_dir().joinpath("j1.txt").touch()
    loop = queue_loop.WorkerLoop(max_concurrent=1, worker_id="w", heartbeat_s=0, spawn=lambda *a, **k: None)

    for _ in range(3):
        assert queue_loop.claim_next_queued("w") is not None
        assert _state("j1")["attempts"] == 1
        assert loop.terminate_and_requeue(["j1"]) == 1
        state = _state("j1")
        assert (state["status"], state["attempts"]) == ("queued", 0)

    assert queue_loop.claim_next_queued("w") is not None
    get_conn().execute("UPDATE jobs SET heartbeat_at=? WHERE id='j1'", (STALE,))
    get_conn().commit()
    assert queue_loop.requeue_orphans() == 1

    state = _state("j1")
    assert (state["status"], state["attempts"]) == ("queued", 1)
    assert _done_events("j1") == []
