"""Guards and small workflows shared by the job-scoped route modules."""
from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException

from api.db import _lock, get_conn, now_iso
from api.db_backend import DBConnection


def require_job(conn: DBConnection, job_id: str) -> None:
    """Raise 404 unless *job_id* names an existing job.

    Ten handlers across four route modules repeated this guard verbatim.  It
    takes the caller's already-open connection rather than opening its own — as
    a FastAPI dependency it would have added a second connection per request,
    which is exactly the kind of extra SQLite traffic this codebase has had to
    hunt down before.
    """
    if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
        raise HTTPException(404, "Job not found")


def start_job(
    job_id: str, dest: Path, filename: str, tlp: str | None, pap: str | None
) -> dict[str, object]:
    """Insert the `jobs` row and hand the file to the pipeline.

    Shared by every ingestion entry point (file upload, pasted text, a
    captured URL — api/routes/upload.py and api/routes/ingest.py) so the
    queue-outcome contract lives in one place instead of three copies that
    have to be kept in sync by hand.
    """
    from api.worker import run_pipeline_async

    ts = now_iso()
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, original_filename, status, tlp_level, pap_level, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (job_id, filename, "uploaded", tlp, pap, ts, ts),
            )
            conn.commit()

    outcome = run_pipeline_async(job_id, str(dest), filename)
    if outcome == "rejected":
        raise HTTPException(503, "The processing queue is full — try again in a few minutes.")

    # "started" keeps reporting "processing" — the value these endpoints have
    # always returned and the frontend switches on. "queued" is reported as
    # itself: answering "processing" for work that has not started is the lie
    # this contract exists to remove.
    status = "queued" if outcome == "queued" else "processing"
    return {"job_id": job_id, "filename": filename, "status": status}
