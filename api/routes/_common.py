"""Guards shared by the job-scoped route modules."""
from __future__ import annotations

from fastapi import HTTPException

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
