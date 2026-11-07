"""A launch carries the identity of the claim that started it (#491).

The loop claims a queued job as its worker_id, then launches it.  Between the
claim and the launch the lease can expire and another loop can take the row.
The launch must not read the new owner and run the job under its identity:
it is abandoned, and the job is left to the loop that holds it.  The
interleaving is fixed by a spawn stand-in that runs the other loop's steps
before the real `_spawn_job`.  No process is started, and no thread waits on
a real lease."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

import api.queue_loop as queue_loop
import api.worker as worker
from api.db import get_conn, now_iso
from api.paths import uploads_dir

_LONG_AGO = "2000-01-01T00:00:00+00:00"


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    return temp_db


def _queued(job_id: str) -> None:
    ts = now_iso()
    conn = get_conn()
    conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                 "VALUES (?,?,?,?,?)", (job_id, f"{job_id}.txt", "queued", ts, ts))
    conn.commit()
    (uploads_dir() / f"{job_id}.txt").touch()


def _row(job_id: str) -> dict:
    return dict(get_conn().execute("SELECT status, worker_id FROM jobs WHERE id=?", (job_id,)).fetchone())


def _expire_lease(job_id: str) -> None:
    conn = get_conn()
    conn.execute("UPDATE jobs SET heartbeat_at=? WHERE id=?", (_LONG_AGO, job_id))
    conn.commit()


@pytest.fixture()
def children(monkeypatch):
    """Stands in for the pipeline processes: each launch that starts one is recorded.
    The watcher thread waits until the test ends, so no exit is reported."""
    started: list[tuple] = []
    release = threading.Event()

    class FakeProcess:
        def __init__(self, target, args, daemon, name):
            self.args, self.pid, self.exitcode = args, 4242, None

        def start(self):
            started.append(self.args)

        def join(self):
            release.wait(60)

    monkeypatch.setattr(worker.mp, "get_context", lambda method: SimpleNamespace(Process=FakeProcess))
    yield started
    release.set()


def test_a_launch_whose_claim_was_taken_over_is_abandoned(db, children):
    """(#491) A claims j1; its lease expires; B requeues and claims it; A's
    delayed launch must start nothing and leave B's row alone.  Before the fix,
    `_spawn_job` read worker-B and started a child as B: children == [(..., 'worker-B')]."""
    _queued("j1")

    def stale_launch(job_id, file_path, original_filename, on_exit):
        _expire_lease(job_id)
        assert queue_loop.requeue_orphans() == 1
        assert queue_loop.claim_next_queued("worker-B") is not None
        return worker._spawn_job(job_id, file_path, original_filename, on_exit)

    loop = queue_loop.WorkerLoop(max_concurrent=1, worker_id="worker-A", spawn=stale_launch)
    assert loop.kick() == 0
    assert children == []
    assert loop.running_ids == []
    assert _row("j1") == {"status": "processing", "worker_id": "worker-B"}


def test_a_requeued_launch_runs_under_the_claim_that_starts_it(db, children):
    """(#491) A's claim is requeued before its launch, and nobody claims it in
    between: the launch is abandoned, the loop claims the job again, and the
    child carries that claim's identity.  Before the fix, `_spawn_job` read the
    NULL owner and started a child with worker_id None."""
    _queued("j1")
    launches: list[str] = []

    def launch(job_id, file_path, original_filename, on_exit):
        launches.append(job_id)
        if len(launches) == 1:
            _expire_lease(job_id)
            assert queue_loop.requeue_orphans() == 1
        return worker._spawn_job(job_id, file_path, original_filename, on_exit)

    loop = queue_loop.WorkerLoop(max_concurrent=1, worker_id="worker-A", spawn=launch)
    assert loop.kick() == 1
    assert [args[0] for args in children] == ["j1"]
    assert children[0][3] == "worker-A"
    assert _row("j1") == {"status": "processing", "worker_id": "worker-A"}


def test_an_unclaimed_launch_still_reads_the_owner_the_row_carries(db, children):
    """(#491) Outside the loop there is no claim to carry: `_spawn_job` keeps
    reading the row's owner, as before the fix."""
    _queued("j1")
    assert queue_loop.claim_next_queued("worker-A") is not None

    worker._spawn_job("j1", str(uploads_dir() / "j1.txt"), "j1.txt", lambda job_id: None)
    assert children == [("j1", str(uploads_dir() / "j1.txt"), "j1.txt", "worker-A")]
