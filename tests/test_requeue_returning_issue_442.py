"""Issue #442: requeue_orphans reports only the rows its own UPDATE requeued.

The requeue used to read the ids with a SELECT and then run a separate UPDATE
with the same predicate.  A row another loop took over in between was still
in the SELECT's list, so it got a "Requeued after a restart" event it never
received.  The requeue is now one `UPDATE ... RETURNING id`, and the events
follow the returned ids.
"""

from __future__ import annotations

import api.queue_loop as queue_loop
from api.db import get_conn, now_iso


def _insert_processing(job_id: str, worker_id: str, heartbeat_at: str) -> None:
    conn = get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at, worker_id, heartbeat_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, f"{job_id}.txt", "processing", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
         worker_id, heartbeat_at),
    )
    conn.commit()


class _AnotherWorkerTakesJ2First:
    """Delegates to the real connection, but first hands j2 to another loop.

    The hand-over happens right before the requeue's UPDATE, the window the
    old SELECT-then-UPDATE code left open.  j2 gets a fresh heartbeat, so the
    lease predicate no longer matches it.
    """

    def __init__(self, real) -> None:
        self._real = real

    def execute(self, sql, params=None):
        if "SET status='queued'" in sql:
            self._real.execute(
                "UPDATE jobs SET status='processing', worker_id='w9', heartbeat_at=? WHERE id='j2'",
                (now_iso(),),
            )
        return self._real.execute(sql, params)


def test_requeue_orphans_does_not_announce_a_row_it_did_not_requeue_issue_442(temp_db, monkeypatch):
    stale = "2020-01-01T00:00:00+00:00"
    _insert_processing("j1", "w1", stale)
    _insert_processing("j2", "w2", stale)

    real = get_conn()
    monkeypatch.setattr(queue_loop, "get_conn", lambda: _AnotherWorkerTakesJ2First(real))

    count = queue_loop.requeue_orphans()
    assert count == 1

    row2 = real.execute("SELECT status, worker_id FROM jobs WHERE id='j2'").fetchone()
    assert row2["status"] == "processing"
    assert row2["worker_id"] == "w9"

    # j2 was not requeued by this call, so its stream must not see the event.
    assert real.execute(
        "SELECT COUNT(*) AS n FROM progress_events WHERE job_id='j2'"
    ).fetchone()["n"] == 0
    assert real.execute(
        "SELECT COUNT(*) AS n FROM progress_events WHERE job_id='j1' AND event_type='stage'"
    ).fetchone()["n"] == 1


def test_requeue_orphans_announces_every_row_it_requeues_issue_442(temp_db):
    """Control: with no race, each requeued row still gets exactly one event."""
    stale = "2020-01-01T00:00:00+00:00"
    _insert_processing("j1", "w1", stale)
    _insert_processing("j2", "w2", stale)

    assert queue_loop.requeue_orphans() == 2

    conn = get_conn()
    for job_id in ("j1", "j2"):
        assert conn.execute(
            "SELECT COUNT(*) AS n FROM progress_events WHERE job_id=? AND event_type='stage'", (job_id,)
        ).fetchone()["n"] == 1
