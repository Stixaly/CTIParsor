"""Non-regression tests for three worker and database bugs.

#747: stopping the API's embedded loop (role all) requeues the jobs it runs
      instead of leaving their watchers to mark them failed.
#748: the pipeline subprocess ignores SIGINT; the supervisor alone drains and
      requeues on Ctrl+C.
#750: a caught exception from a nested `with get_conn()` does not roll back
      the outer transaction() block.
"""

from __future__ import annotations

import signal
import threading
import time

import pytest
from psycopg.pq import TransactionStatus

import api.queue_loop as queue_loop
import api.worker as worker
from api.db import get_conn, now_iso, transaction
from api.paths import uploads_dir


@pytest.fixture
def setup_db(temp_db):
    """Isolated database with an uploads/ root (see tests/test_job_queue.py)."""
    uploads_dir().mkdir(parents=True, exist_ok=True)
    return temp_db


def _insert_job(job_id: str, status: str, created_at: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        (job_id, f"{job_id}.txt", status, created_at, created_at),
    )
    conn.commit()


def _touch_upload(job_id: str) -> None:
    (uploads_dir() / f"{job_id}.txt").touch()


class FakeHandle:
    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.terminated = False
        self.status_at_terminate: str | None = None

    def terminate(self) -> None:
        self.terminated = True
        row = get_conn().execute("SELECT status FROM jobs WHERE id=?", (self.job_id,)).fetchone()
        self.status_at_terminate = row["status"]

    def join(self, timeout: float | None = None) -> None:
        pass


class FakeSpawn:
    """Records the spawns; the test never triggers on_exit, as a job still running would not."""

    def __init__(self) -> None:
        self.handles: dict[str, FakeHandle] = {}

    def __call__(self, job_id: str, file_path: str, name: str, on_exit) -> FakeHandle:
        handle = FakeHandle(job_id)
        self.handles[job_id] = handle
        return handle


# ── #747 ─────────────────────────────────────────────────────────────────────

def test_stopping_the_embedded_loop_requeues_its_running_job_747(setup_db, monkeypatch: pytest.MonkeyPatch):
    spawn = FakeSpawn()
    monkeypatch.setattr(queue_loop, "_default_spawn", spawn)
    queue_loop.stop_embedded()
    _insert_job("j1", "queued", "2024-01-01T00:00:00Z")
    _touch_upload("j1")

    try:
        loop = queue_loop.start_embedded(max_concurrent=1)
        deadline = time.monotonic() + 10
        while loop.running_count == 0 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert loop.running_ids == ["j1"]

        queue_loop.stop_embedded()
    finally:
        queue_loop.stop_embedded()

    # Requeued before the handle was terminated, so the watcher's failed write is void.
    assert spawn.handles["j1"].terminated
    assert spawn.handles["j1"].status_at_terminate == "queued"
    row = get_conn().execute("SELECT status, worker_id FROM jobs WHERE id='j1'").fetchone()
    assert row["status"] == "queued"
    assert row["worker_id"] is None


class TimedHandle(FakeHandle):
    def __init__(self, job_id: str) -> None:
        super().__init__(job_id)
        self.join_timeouts: list[float | None] = []

    def join(self, timeout: float | None = None) -> None:
        self.join_timeouts.append(timeout)


def _insert_processing(job_id: str, worker_id: str) -> None:
    _insert_job(job_id, "processing", "2024-01-01T00:00:00Z")
    conn = get_conn()
    conn.execute("UPDATE jobs SET worker_id=? WHERE id=?", (worker_id, job_id))
    conn.commit()


def test_an_expired_stop_budget_still_requeues_every_job_747(setup_db):
    loop = queue_loop.WorkerLoop(max_concurrent=3, role="all", spawn=FakeSpawn())
    handles = {}
    for job_id in ("j3", "j4", "j5"):
        _insert_processing(job_id, loop.worker_id)
        handles[job_id] = loop._handles[job_id] = TimedHandle(job_id)

    count = loop.terminate_and_requeue(list(handles), deadline=time.monotonic() - 1)

    assert count == 3
    for handle in handles.values():
        assert handle.terminated
        assert handle.join_timeouts == [0.0]
    rows = get_conn().execute("SELECT status FROM jobs WHERE id IN ('j3','j4','j5')").fetchall()
    assert [row["status"] for row in rows] == ["queued"] * 3


def test_a_claim_in_flight_when_stopping_is_requeued_too_747(setup_db, monkeypatch: pytest.MonkeyPatch):
    loop = queue_loop.WorkerLoop(max_concurrent=1, role="all", spawn=FakeSpawn())
    _insert_processing("j6", loop.worker_id)
    handle = FakeHandle("j6")
    # A kick is under way: its claim is written, its process is not yet in _handles.
    loop._kick_lock.acquire()

    def finish_the_spawn() -> None:
        time.sleep(0.2)
        with loop._lock:
            loop._handles["j6"] = handle
        loop._kick_lock.release()

    spawner = threading.Thread(target=finish_the_spawn)
    spawner.start()
    # A loop thread that outlives the join, as one stuck in a database call would.
    stuck = threading.Event()
    thread = threading.Thread(target=stuck.wait, daemon=True)
    thread.start()
    monkeypatch.setattr(queue_loop, "_embedded", loop)
    monkeypatch.setattr(queue_loop, "_embedded_thread", thread)
    try:
        queue_loop.stop_embedded(timeout_s=0.05)
    finally:
        stuck.set()
        spawner.join()

    assert handle.terminated
    row = get_conn().execute("SELECT status, worker_id FROM jobs WHERE id='j6'").fetchone()
    assert row["status"] == "queued"
    assert row["worker_id"] is None


# ── #748 ─────────────────────────────────────────────────────────────────────

def test_the_subprocess_ignores_sigint_748(monkeypatch: pytest.MonkeyPatch):
    for var in ("OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "TOKENIZERS_PARALLELISM"):
        monkeypatch.setenv(var, "x")          # recorded, so teardown removes what setdefault adds
        monkeypatch.delenv(var)
    seen: list[object] = []
    monkeypatch.setattr(worker, "_run_pipeline", lambda *args: seen.append(signal.getsignal(signal.SIGINT)))

    previous = signal.getsignal(signal.SIGINT)
    try:
        worker._subprocess_entry("j1", "/u/j1.txt", "r.txt")
    finally:
        signal.signal(signal.SIGINT, previous)

    assert seen == [signal.SIG_IGN]


# ── #750 ─────────────────────────────────────────────────────────────────────

def test_a_caught_inner_error_does_not_roll_back_the_outer_transaction_750(setup_db):
    conn = get_conn()
    with pytest.raises(RuntimeError):
        with transaction(conn):
            try:
                with get_conn():
                    raise ValueError("recoverable")
            except ValueError:
                pass
            conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                         "VALUES (?,?,?,?,?)", ("j750", "j750.txt", "queued", now_iso(), now_iso()))
            # Still inside the explicit transaction: the INSERT is not autocommitted.
            assert conn._conn.info.transaction_status == TransactionStatus.INTRANS
            raise RuntimeError("outer block fails: transaction() must roll back")

    row = conn.execute("SELECT id FROM jobs WHERE id='j750'").fetchone()
    assert row is None
