"""Queue-wide status (ADR-0048).

A snapshot of backlog and worker liveness, distinct from
GET /jobs/{id}/progress, which streams one job. Read-only, unauthenticated
like every other GET route here (SECURITY.md).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from api.db import backend, get_conn
from api.queue_loop import LEASE_TIMEOUT_S, role
from api.worker import _QUEUE_MAX_DEPTH

router = APIRouter(prefix="/api", tags=["queue"])


def _seconds_since(iso: str | None) -> float | None:
    """Return seconds elapsed since the given ISO-8601 timestamp, or None if unparseable."""
    if iso is None or iso == "":
        return None
    try:
        parsed = datetime.fromisoformat(iso)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())


@router.get("/queue/status")
def get_queue_status():
    """Return a snapshot of queue depth, job counts, and worker liveness."""
    with get_conn() as conn:
        rows = conn.execute("SELECT status, COUNT(*) as n FROM jobs GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        for key in ("queued", "processing", "failed"):
            counts.setdefault(key, 0)

        oldest = conn.execute(
            "SELECT id, created_at FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
        ).fetchone()

        worker_rows = conn.execute(
            "SELECT worker_id, COUNT(*) as running, MIN(heartbeat_at) as oldest_hb, MAX(heartbeat_at) as newest_hb "
            "FROM jobs WHERE status='processing' AND worker_id IS NOT NULL GROUP BY worker_id"
        ).fetchall()

    queue_depth = counts.get("queued", 0)
    workers = []
    for w in worker_rows:
        newest_age = _seconds_since(w["newest_hb"])
        workers.append(
            {
                "worker_id": w["worker_id"],
                "running_jobs": w["running"],
                "oldest_heartbeat_seconds_ago": _seconds_since(w["oldest_hb"]),
                "stale": newest_age is not None and newest_age > LEASE_TIMEOUT_S,
            }
        )

    return {
        "role": role(),
        "backend": backend(),
        "counts": counts,
        "queue": {
            "depth": queue_depth,
            "max_depth": _QUEUE_MAX_DEPTH,
            "oldest_queued_job_id": oldest["id"] if oldest else None,
            "oldest_queued_seconds": _seconds_since(oldest["created_at"]) if oldest else None,
        },
        "workers": workers,
    }
