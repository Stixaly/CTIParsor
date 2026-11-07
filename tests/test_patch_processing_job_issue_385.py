"""#385: a PATCH that changes the status of a job a worker is running is refused with the
same 409 as a DELETE of that job.  Before, `PATCH {"status": "for_review"}` answered 200 and
moved the job out of its lease: the heartbeat only stamps `processing` rows, so
requeue_orphans never took it back."""
from __future__ import annotations

import pytest

from api.queue_loop import now_iso

_OLD = "2026-01-01T00:00:00+00:00"


def _add_job(db, job_id: str, *, status: str, heartbeat: str | None = None) -> None:
    fields = {"id": job_id, "original_filename": "report.pdf", "status": status,
              "created_at": _OLD, "updated_at": _OLD}
    if status == "processing":
        fields.update(worker_id="w-live", heartbeat_at=heartbeat or now_iso())
    with db.get_conn() as conn:
        conn.execute(
            f"INSERT INTO jobs ({', '.join(fields)}) VALUES ({', '.join('?' for _ in fields)})",
            tuple(fields.values()),
        )
        conn.commit()


def _row(db, job_id: str):
    with db.get_conn() as conn:
        return conn.execute("SELECT status, worker_id, heartbeat_at FROM jobs WHERE id=?", (job_id,)).fetchone()


@pytest.mark.parametrize("status", ["for_review", "reviewing", "completed", "failed"])
def test_a_status_change_of_a_running_job_is_refused_issue_385(temp_db_client, temp_db, status):
    _add_job(temp_db, "p1", status="processing")
    before = _row(temp_db, "p1")

    resp = temp_db_client.patch("/api/jobs/p1", json={"status": status})

    assert resp.status_code == 409
    assert _row(temp_db, "p1") == before     # status, worker and heartbeat untouched
    deleted = temp_db_client.delete("/api/jobs/p1")
    assert deleted.status_code == 409
    assert resp.json() == deleted.json()     # the same refusal as the DELETE


def test_the_refusal_does_not_depend_on_the_lease_issue_385(temp_db_client, temp_db):
    # A heartbeat older than any lease: the DELETE refuses it too, so the PATCH does.
    _add_job(temp_db, "stale", status="processing", heartbeat="2020-01-01T00:00:00+00:00")

    assert temp_db_client.patch("/api/jobs/stale", json={"status": "for_review"}).status_code == 409
    assert _row(temp_db, "stale")["status"] == "processing"


@pytest.mark.parametrize("status", ["queued", "for_review"])
def test_a_job_not_running_can_still_be_set_issue_385(temp_db_client, temp_db, status):
    # Control: only a job a worker holds is refused.
    _add_job(temp_db, "j1", status=status)

    assert temp_db_client.patch("/api/jobs/j1", json={"status": "reviewing"}).json() == {"status": "reviewing"}
    assert temp_db_client.get("/api/jobs/j1").json()["status"] == "reviewing"


def test_an_invalid_status_is_still_400_on_a_running_job_issue_385(temp_db_client, temp_db):
    _add_job(temp_db, "p1", status="processing")

    assert temp_db_client.patch("/api/jobs/p1", json={"status": "processing"}).status_code == 400
