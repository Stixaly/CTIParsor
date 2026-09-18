"""Queue-loop contract (ADR-0046).

What these tests lock: the claim is atomic on both engines, the lease-based
orphan requeue, the loop's slot accounting with a fake spawn, and the three
answers of `run_pipeline_async` under each role.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

import api.queue_loop as queue_loop
import api.worker as worker
from api.db import get_conn, now_iso


@pytest.fixture
def setup_db(temp_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolated database, plus an uploads/ root under tmp_path.

    temp_db (tests/conftest.py) repoints api.db.DB_PATH at a throwaway
    file and runs the real migrations, so the worker and these tests share one
    schema.  A hand-written CREATE TABLE here would silently relax constraints
    the real schema enforces -- jobs.updated_at is NOT NULL -- and, worse,
    leave the test bodies talking to the developer's cti_stix.db.
    """
    monkeypatch.setattr(worker, "_ROOT", tmp_path)
    (tmp_path / "uploads").mkdir(exist_ok=True)
    return temp_db


def _insert_job(
    job_id: str, status: str, created_at: str, *,
    worker_id: str | None = None, heartbeat_at: str | None = None,
) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, worker_id, heartbeat_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, f"{job_id}.txt", status, created_at, created_at, worker_id, heartbeat_at),
    )
    conn.commit()


def _touch_upload(job_id: str) -> None:
    (worker._ROOT / "uploads" / f"{job_id}.txt").touch()


class FakeHandle:
    def __init__(self) -> None:
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


class FakeSpawn:
    """Records spawns; the test triggers on_exit itself."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.on_exit: dict[str, callable] = {}
        self.handles: dict[str, FakeHandle] = {}

    def __call__(self, job_id: str, file_path: str, name: str, on_exit: callable) -> FakeHandle:
        self.calls.append((job_id, file_path, name))
        self.on_exit[job_id] = on_exit
        handle = FakeHandle()
        self.handles[job_id] = handle
        return handle


def test_role_parsing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CTIPARSOR_ROLE", raising=False)
    assert queue_loop.role() == "all"

    monkeypatch.setenv("CTIPARSOR_ROLE", "API ")
    assert queue_loop.role() == "api"

    monkeypatch.setenv("CTIPARSOR_ROLE", "worker")
    assert queue_loop.role() == "worker"

    monkeypatch.setenv("CTIPARSOR_ROLE", "bogus")
    assert queue_loop.role() == "all"


def test_claim_next_queued_is_atomic(setup_db):
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _insert_job("j2", "queued", "2024-01-01T00:00:01Z")
    _touch_upload("j1")
    _touch_upload("j2")

    results: list[tuple[str, str, str] | None] = []
    lock = threading.Lock()

    def claim() -> None:
        res = queue_loop.claim_next_queued("w")
        with lock:
            results.append(res)

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successful_claims = [r for r in results if r is not None]
    assert len(successful_claims) <= 2

    claimed_ids = [r[0] for r in successful_claims]
    assert len(claimed_ids) == len(set(claimed_ids)), "Duplicate claims detected"

    conn = get_conn()
    for job_id in claimed_ids:
        row = conn.execute("SELECT status, worker_id, heartbeat_at FROM jobs WHERE id=?", (job_id,)).fetchone()
        assert row["status"] == "processing"
        assert row["worker_id"] == "w"
        assert row["heartbeat_at"] is not None


def test_claim_skips_job_whose_upload_vanished(setup_db, monkeypatch: pytest.MonkeyPatch):
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _insert_job("j2", "queued", "2024-01-01T00:00:01Z")
    _touch_upload("j2")

    emitted: list[tuple[str, str, dict]] = []

    def mock_emit(job_id: str, event_type: str, data: dict) -> None:
        emitted.append((job_id, event_type, data))

    monkeypatch.setattr(queue_loop, "emit_progress", mock_emit)

    result = queue_loop.claim_next_queued("w")

    assert result is not None
    assert result[0] == "j2"

    conn = get_conn()
    row = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "failed"

    assert any(
        job_id == "j1" and event_type == "done" and data.get("status") == "failed"
        for job_id, event_type, data in emitted
    )


def test_requeue_orphans_unconditional_resets_all_processing(setup_db):
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w1")
    _insert_job("j2", "processing", "2024-01-01T00:00:01Z", worker_id="w2")
    _insert_job("j3", "for_review", "2024-01-01T00:00:02Z")

    count = queue_loop.requeue_orphans(unconditional=True)
    assert count == 2

    conn = get_conn()
    row1 = conn.execute("SELECT status, worker_id FROM jobs WHERE id='j1'").fetchone()
    row2 = conn.execute("SELECT status, worker_id FROM jobs WHERE id='j2'").fetchone()
    row3 = conn.execute("SELECT status FROM jobs WHERE id='j3'").fetchone()

    assert row1["status"] == "queued"
    assert row1["worker_id"] is None
    assert row2["status"] == "queued"
    assert row2["worker_id"] is None
    assert row3["status"] == "for_review"


def test_requeue_orphans_honours_the_lease(setup_db):
    fresh = now_iso()
    from datetime import datetime, timedelta, timezone

    old_dt = datetime.now(timezone.utc) - timedelta(seconds=queue_loop.LEASE_TIMEOUT_S + 60)
    old = old_dt.isoformat()

    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w1", heartbeat_at=fresh)
    _insert_job("j2", "processing", "2024-01-01T00:00:01Z", worker_id="w2", heartbeat_at=old)
    _insert_job("j3", "processing", "2024-01-01T00:00:02Z", worker_id="w3", heartbeat_at=None)

    count = queue_loop.requeue_orphans()
    assert count == 2

    conn = get_conn()
    row1 = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    row2 = conn.execute("SELECT status FROM jobs WHERE id='j2'").fetchone()
    row3 = conn.execute("SELECT status FROM jobs WHERE id='j3'").fetchone()

    assert row1["status"] == "processing"
    assert row2["status"] == "queued"
    assert row3["status"] == "queued"


def test_heartbeat_touches_only_own_processing_rows(setup_db):
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w")
    _insert_job("j2", "processing", "2024-01-01T00:00:01Z", worker_id="other")
    _insert_job("j3", "queued", "2024-01-01T00:00:02Z")

    count = queue_loop.heartbeat(["j1", "j2", "j3"], "w")
    assert count == 1

    conn = get_conn()
    row1 = conn.execute("SELECT heartbeat_at FROM jobs WHERE id='j1'").fetchone()
    row2 = conn.execute("SELECT heartbeat_at FROM jobs WHERE id='j2'").fetchone()
    row3 = conn.execute("SELECT heartbeat_at FROM jobs WHERE id='j3'").fetchone()

    assert row1["heartbeat_at"] is not None
    assert row2["heartbeat_at"] is None
    assert row3["heartbeat_at"] is None


def test_kick_respects_max_concurrent_and_frees_slots(setup_db):
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _insert_job("j2", "queued", "2024-01-01T00:00:01Z")
    _insert_job("j3", "queued", "2024-01-01T00:00:02Z")
    _touch_upload("j1")
    _touch_upload("j2")
    _touch_upload("j3")

    spawn = FakeSpawn()
    loop = queue_loop.WorkerLoop(max_concurrent=2, spawn=spawn)

    started = loop.kick()
    assert started == 2
    assert loop.running_count == 2

    conn = get_conn()
    row3 = conn.execute("SELECT status FROM jobs WHERE id='j3'").fetchone()
    assert row3["status"] == "queued"

    first_job_id = spawn.calls[0][0]
    spawn.on_exit[first_job_id](first_job_id)

    assert len(spawn.calls) == 3
    assert loop.running_count == 2

    _insert_job("j4", "queued", "2024-01-01T00:00:03Z")
    _insert_job("j5", "queued", "2024-01-01T00:00:04Z")
    _insert_job("j6", "queued", "2024-01-01T00:00:05Z")
    _touch_upload("j4")
    _touch_upload("j5")
    _touch_upload("j6")

    spawn2 = FakeSpawn()
    loop2 = queue_loop.WorkerLoop(max_concurrent=0, spawn=spawn2)
    started2 = loop2.kick()
    assert started2 == 3


def test_kick_marks_job_failed_when_spawn_raises(setup_db):
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    def bad_spawn(job_id: str, file_path: str, name: str, on_exit: callable) -> FakeHandle:
        raise RuntimeError("boom")

    loop = queue_loop.WorkerLoop(max_concurrent=1, spawn=bad_spawn)
    started = loop.kick()
    assert started == 0
    assert loop.running_count == 0

    conn = get_conn()
    row = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "failed"


def test_run_once_touches_the_alive_file(setup_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(queue_loop, "ALIVE_FILE", tmp_path / "alive")
    loop = queue_loop.WorkerLoop(max_concurrent=1, spawn=FakeSpawn())
    loop.run_once()
    assert (tmp_path / "alive").exists()


def test_run_once_does_not_touch_alive_file_when_a_db_call_fails(
    setup_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    """The worker container's HEALTHCHECK watches this file's mtime -- it must
    go stale (and the container report unhealthy) when the DB is actually
    unreachable, not stay fresh forever because touch_alive() doesn't check
    what the DB calls above it did."""
    monkeypatch.setattr(queue_loop, "ALIVE_FILE", tmp_path / "alive")

    def broken_requeue(*, unconditional: bool = False) -> int:
        raise RuntimeError("DB unreachable")

    monkeypatch.setattr(queue_loop, "requeue_orphans", broken_requeue)
    loop = queue_loop.WorkerLoop(max_concurrent=1, spawn=FakeSpawn())
    loop.run_once()
    assert not (tmp_path / "alive").exists()


def test_terminate_and_requeue(setup_db):
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    spawn = FakeSpawn()
    loop = queue_loop.WorkerLoop(max_concurrent=1, spawn=spawn)
    loop.kick()

    ids = loop.running_ids
    assert len(ids) == 1

    count = loop.terminate_and_requeue(ids)
    assert count == 1

    assert spawn.handles[ids[0]].terminated
    assert ids[0] not in loop.running_ids

    conn = get_conn()
    row = conn.execute("SELECT status, worker_id FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "queued"
    assert row["worker_id"] is None

    assert loop.running_count == 0


def test_run_pipeline_async_rejects_when_queue_is_full(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_QUEUE_MAX_DEPTH", 1)
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _insert_job("j2", "uploaded", "2024-01-01T00:00:01Z")

    emitted: list[tuple[str, str, dict]] = []

    def mock_emit(job_id: str, event_type: str, data: dict) -> None:
        emitted.append((job_id, event_type, data))

    monkeypatch.setattr(worker, "emit_progress", mock_emit)

    result = worker.run_pipeline_async("j2", "/x", "f.txt")
    assert result == "rejected"

    conn = get_conn()
    row = conn.execute("SELECT status FROM jobs WHERE id='j2'").fetchone()
    assert row["status"] == "failed"

    assert any(
        job_id == "j2" and event_type == "done"
        for job_id, event_type, _ in emitted
    )


def test_run_pipeline_async_only_enqueues_in_role_api(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CTIPARSOR_ROLE", "api")
    spawn = FakeSpawn()
    monkeypatch.setattr(queue_loop, "_default_spawn", spawn)

    _insert_job("j1", "uploaded", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    result = worker.run_pipeline_async("j1", "/x", "f.txt")
    assert result == "queued"

    conn = get_conn()
    row = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "queued"

    assert spawn.calls == []


def test_run_pipeline_async_starts_in_role_all(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CTIPARSOR_ROLE", "all")
    spawn = FakeSpawn()
    monkeypatch.setattr(queue_loop, "_default_spawn", spawn)

    _insert_job("j1", "uploaded", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    try:
        queue_loop.stop_embedded()
        result = worker.run_pipeline_async("j1", "/x", "f.txt")
        assert result == "started"

        conn = get_conn()
        row = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
        assert row["status"] == "processing"

        assert len(spawn.calls) == 1
        assert queue_loop.embedded() is not None
    finally:
        queue_loop.stop_embedded()


def test_main_once_runs_a_single_pass(setup_db, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(queue_loop, "_default_spawn", FakeSpawn())
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    result = queue_loop.main(["--once", "--max-concurrent", "1"])
    assert result == 0

    conn = get_conn()
    row = conn.execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "processing"


def test_current_owner_reads_the_claimed_worker_id(setup_db):
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w1")
    _insert_job("j2", "queued", "2024-01-01T00:00:00Z")

    assert worker._current_owner("j1") == "w1"
    assert worker._current_owner("j2") is None
    assert worker._current_owner("does-not-exist") is None


def test_finalize_job_applies_unconditionally_when_owner_is_none(setup_db):
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z")

    assert worker._finalize_job("j1", "for_review", None, bundle_json="{}") is True

    row = get_conn().execute("SELECT status, bundle_json FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "for_review"
    assert row["bundle_json"] == "{}"


def test_finalize_job_applies_when_worker_id_still_matches(setup_db):
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w1")

    assert worker._finalize_job("j1", "failed", "w1") is True

    row = get_conn().execute("SELECT status FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "failed"


def test_finalize_job_is_a_noop_when_the_job_was_reclaimed(setup_db):
    """The exact race api/worker.py's _finalize_job exists to close: a stale
    subprocess (worker_id="w1") tries to finalize a job that the lease-based
    requeue_orphans() has since handed to another worker ("w2")."""
    _insert_job("j1", "processing", "2024-01-01T00:00:00Z", worker_id="w2")

    assert worker._finalize_job("j1", "for_review", "w1", bundle_json='{"stale": true}') is False

    row = get_conn().execute("SELECT status, bundle_json FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "processing"
    assert row["bundle_json"] != '{"stale": true}'
