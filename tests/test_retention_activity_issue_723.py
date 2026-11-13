"""A human decision renews the retention clock of its report (#723).

The retention sweep deletes a report whose last update is older than the window.
A report whose entities or relationships an analyst decided this week, but whose
`updated_at` is old, used to be deleted as if it were idle.  A decision now sets
`jobs.activity_at` in the transaction that writes it; GET and polling do not.

The sweep's DELETE repeats the expiry test (#488), so a decision committed after
the sweep chose the report keeps it, rows and files included.  Reports are
created with old timestamps directly; every decision goes through the API routes,
or through the same clock step the routes take, from another connection.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from api.paths import output_dir, uploads_dir
from api.routes import _common
from api.routes import jobs as jobs_routes
from pipeline import decisions


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True, exist_ok=True)     # under tmp_path (conftest)
    output_dir().mkdir(parents=True, exist_ok=True)
    return temp_db


def _ago(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _old_job(db, job_id: str = "old", *, status: str = "for_review", days: int = 40) -> None:
    """A report last updated `days` ago, with one entity, one relationship and its files."""
    from api.worker import bundle_output_path

    stamp = _ago(days)
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", status, "APT29 used WellMess.", stamp, stamp),
        )
        conn.execute(
            "INSERT INTO entities (id, job_id, value, entity_type, confidence, accepted, source) "
            "VALUES (?,?,?,?,?,?,?)",
            (f"{job_id}-e", job_id, "WellMess", "malware", 0.5, None, "gliner"),
        )
        conn.execute(
            "INSERT INTO relationships (id, job_id, source_value, relationship_type, target_value, "
            "confidence, accepted) VALUES (?,?,?,?,?,?,?)",
            (f"{job_id}-r", job_id, "APT29", "uses", "WellMess", 0.8, None),
        )
        conn.commit()
    (uploads_dir() / f"{job_id}.txt").write_text("source", encoding="utf-8")
    bundle_output_path(job_id, "report").write_text("{}", encoding="utf-8")


def _count(db, table: str, job_id: str = "old") -> int:
    column = "id" if table == "jobs" else "job_id"
    with db.get_conn() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}=?", (job_id,)).fetchone()[0]


def _files_kept(job_id: str = "old") -> bool:
    from api.worker import bundle_output_path

    return (uploads_dir() / f"{job_id}.txt").exists() and bundle_output_path(job_id, "report").exists()


def _assert_kept(db, job_id: str = "old") -> None:
    assert _count(db, "jobs", job_id) == 1
    assert _count(db, "entities", job_id) == 1
    assert _count(db, "relationships", job_id) == 1
    assert _count(db, "review_decisions", job_id) >= 1
    assert _files_kept(job_id)


# The decisions an analyst makes through the API, each on the report "old".
DECISIONS = {
    "entity_patch": ("patch", "/api/jobs/old/entities/old-e", {"accepted": True}),
    "entity_bulk": ("post", "/api/jobs/old/entities/bulk",
                    {"entity_type": "malware", "action": "accept", "scope": "pending"}),
    "entity_accept_pending": ("post", "/api/jobs/old/entities/accept-pending", None),
    "relationship_patch": ("patch", "/api/jobs/old/relationships/old-r", {"accepted": True}),
    "relationship_bulk": ("post", "/api/jobs/old/relationships/bulk", {"ids": ["old-r"], "action": "accept"}),
}


@pytest.mark.parametrize("name", list(DECISIONS))
def test_a_decision_through_the_api_keeps_an_old_report_and_its_files(db, temp_db_client, name):
    """(#723) A report last updated 40 days ago, decided this minute: the sweep with a
    30-day window keeps it, its rows and its files.  Before the fix, the decision did not
    touch `updated_at`, and the sweep deleted the report."""
    _old_job(db)
    method, path, body = DECISIONS[name]
    send = getattr(temp_db_client, method)
    response = send(path, json=body) if body is not None else send(path)
    assert response.status_code == 200, response.text

    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 0
    _assert_kept(db)


def test_a_decision_made_long_ago_does_not_protect_the_report(db, temp_db_client, monkeypatch):
    """The clock step of a decision is the time of the decision: one made 40 days ago
    leaves the report expired, and the sweep deletes it with its rows and files."""
    _old_job(db)
    monkeypatch.setattr(_common, "now_iso", lambda: _ago(40), raising=False)
    assert temp_db_client.patch("/api/jobs/old/entities/old-e", json={"accepted": True}).status_code == 200

    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 1
    # The decision journal outlives the report (migration 7), so it is not counted here.
    assert _count(db, "jobs") == 0 and _count(db, "entities") == 0
    assert not _files_kept()


@pytest.mark.parametrize("path", ["/api/jobs/old", "/api/jobs/old/entities", "/api/jobs/old/relationships"])
def test_reading_the_report_does_not_renew_its_clock(db, temp_db_client, path):
    """(#723) GET and polling are not activity: the report expires as if nobody had looked at it."""
    _old_job(db)
    assert temp_db_client.get(path).status_code == 200

    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 1
    assert _count(db, "jobs") == 0


def test_a_decision_whose_write_fails_does_not_renew_the_clock(db, temp_db_client, monkeypatch):
    """(#723) The renewal is in the transaction of the write: when the write raises, the
    transaction rolls back and the report keeps its old clock."""
    from api.routes import entities as entity_routes

    _old_job(db)

    def refused(*args, **kwargs):
        raise RuntimeError("decision refused")

    monkeypatch.setattr(entity_routes.decisions, "record", refused)
    with pytest.raises(RuntimeError, match="decision refused"):
        temp_db_client.patch("/api/jobs/old/entities/old-e", json={"accepted": True})

    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 1
    assert _count(db, "jobs") == 0


def test_queued_and_processing_reports_and_a_disabled_sweep_keep_their_rows(db, temp_db_client):
    """(#723) The protections that were there before stay: an active report is never swept,
    and a window of 0 days disables the sweep whatever the activity."""
    _old_job(db, "queued-job", status="queued")
    _old_job(db, "processing-job", status="processing")
    assert jobs_routes.sweep_expired_jobs(retention_days=0) == 0
    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 0
    assert _count(db, "jobs", "queued-job") == 1 and _count(db, "jobs", "processing-job") == 1


@pytest.mark.parametrize("kind", ["entity", "relationship"])
def test_a_decision_committed_after_the_sweep_chose_the_report_keeps_it(db, monkeypatch, kind):
    """(#723, #488) The sweep has read the report as expired; a decision is committed by
    another connection before the sweep's DELETE.  The DELETE tests the activity again and
    matches nothing: the report, its rows and its files survive."""
    _old_job(db)
    row_id = "old-e" if kind == "entity" else "old-r"
    real_transaction = jobs_routes.transaction
    other_connection: dict = {}

    def decided_elsewhere(conn, **kw):
        # Runs after `_delete_job` read the row, before its DELETEs.  The decision is written
        # from another thread, so from another connection, and committed.
        def decide():
            try:
                with db.get_conn() as other:
                    with db.transaction(other):
                        decisions.record(other, kind, "id=?", (row_id,), accepted=True,
                                         origin=decisions.HUMAN, decided_at=db.now_iso())
                        _common.renew_retention(other, "old")
            except Exception as exc:          # reported by the assertions below
                other_connection["error"] = exc

        worker = threading.Thread(target=decide)
        worker.start()
        worker.join()
        return real_transaction(conn, **kw)

    monkeypatch.setattr(jobs_routes, "transaction", decided_elsewhere)
    assert jobs_routes.sweep_expired_jobs(retention_days=30) == 0
    assert "error" not in other_connection, other_connection.get("error")
    _assert_kept(db)
