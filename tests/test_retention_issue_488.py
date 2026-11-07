"""The retention sweep deletes a job only while it is still expired (#488).

The sweep lists the expired jobs, then deletes each one.  Between the list and
the DELETE a job can be requeued or touched again; the DELETE must carry the
expiry it was chosen for, so that such a job is kept, with its rows.  The
interleaving is fixed by a hook on the transaction that `_delete_job` opens
right after it has read the row, as in test_jobs_routes.py."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from api.paths import uploads_dir
from api.routes import jobs as jobs_routes


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    return temp_db


def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def _add_job(db, job_id: str, *, status: str, updated_at: str) -> None:
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                     "VALUES (?,?,?,?,?)", (job_id, "report.pdf", status, updated_at, updated_at))
        conn.execute("INSERT INTO entities (id, job_id, value, entity_type) VALUES (?,?,?,?)",
                     (f"{job_id}_e", job_id, "APT29", "threat-actor"))
        conn.commit()


def _count(db, table: str, job_id: str) -> int:
    column = "id" if table == "jobs" else "job_id"
    with db.get_conn() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (job_id,)).fetchone()[0]


def _requeued(conn) -> None:
    conn.execute("UPDATE jobs SET status='queued' WHERE id='old'")


def _touched(conn) -> None:
    conn.execute("UPDATE jobs SET updated_at=? WHERE id='old'", (datetime.now(timezone.utc).isoformat(),))


@pytest.mark.parametrize("change", [_requeued, _touched], ids=["requeued", "touched"])
def test_a_job_changed_after_the_sweep_chose_it_is_kept_with_its_rows(db, monkeypatch, change):
    """(#488) The sweep chose `old` as expired; a worker requeues or touches it
    between the sweep's read and its DELETE.  The DELETE must refuse: the job
    and its entity survive, and the sweep counts nothing.  Before the fix, the
    DELETE only excluded `processing`, so the job went: `sweep == 1`, row gone."""
    _add_job(db, "old", status="for_review", updated_at=_days_ago(40))
    real_transaction = jobs_routes.transaction

    def changed_first(conn, **kw):
        # Runs after `_delete_job` read the row, before its DELETEs.
        change(conn)
        return real_transaction(conn, **kw)

    monkeypatch.setattr(jobs_routes, "transaction", changed_first)
    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 0
    assert _count(db, "jobs", "old") == 1
    assert _count(db, "entities", "old") == 1


def test_a_job_that_stays_expired_is_still_swept_through_the_guarded_delete(db, monkeypatch):
    """(#488) The guard refuses only what changed: an expired job whose state
    did not move is deleted, rows and all, through the same guarded DELETE."""
    _add_job(db, "old", status="for_review", updated_at=_days_ago(40))
    real_transaction = jobs_routes.transaction
    hooked = []

    def untouched(conn, **kw):
        hooked.append(True)
        return real_transaction(conn, **kw)

    monkeypatch.setattr(jobs_routes, "transaction", untouched)
    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 1
    assert hooked and _count(db, "jobs", "old") == 0 and _count(db, "entities", "old") == 0
