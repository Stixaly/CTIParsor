"""Queue-wide status (ADR-0048, ADR-0094 item 7).

A snapshot of backlog and worker liveness, distinct from
GET /jobs/{id}/progress, which streams one job. Read-only, unauthenticated
like every other GET route here (SECURITY.md).

`workers` lists every queue loop that runs, busy or idle: each loop keeps a
row in `worker_heartbeats` (api/queue_loop.py), and a worker that holds a
`processing` job without such a row (one of the previous revision, during an
upgrade) is listed from the job.  Its running jobs are counted from `jobs`.
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


def _workers(loop_rows: list, job_rows: list) -> list[dict]:
    """One entry per worker_id that has a worker_heartbeats row or a `processing` job."""
    loops = {r["worker_id"]: r for r in loop_rows}
    held = {r["worker_id"]: r for r in job_rows}
    workers = []
    for worker_id in set(loops) | set(held):
        loop, jobs = loops.get(worker_id), held.get(worker_id)
        ages = [a for a in (_seconds_since(loop["heartbeat_at"]) if loop else None,
                            _seconds_since(jobs["newest_hb"]) if jobs else None) if a is not None]
        newest_age = min(ages) if ages else None
        stale = newest_age is not None and newest_age > LEASE_TIMEOUT_S
        running = jobs["running"] if jobs else 0
        workers.append({
            "worker_id": worker_id,
            "state": "stale" if stale else "busy" if running else "idle",
            "role": loop["role"] if loop else None,
            "max_concurrent": loop["max_concurrent"] if loop else None,
            "app_version": loop["app_version"] if loop else None,
            "started_at": loop["started_at"] if loop else None,
            "running_jobs": running,
            "heartbeat_seconds_ago": newest_age,
            "oldest_heartbeat_seconds_ago": _seconds_since(jobs["oldest_hb"]) if jobs else None,
            "stale": stale,
        })
    workers.sort(key=lambda w: (w["stale"], w["worker_id"]))
    return workers


def _summary(workers: list[dict]) -> dict:
    """Live workers and their free slots.  `capacity` is None when a live worker's
    limit is unknown (no row) or unlimited (WORKER_MAX_CONCURRENT <= 0)."""
    alive = [w for w in workers if not w["stale"]]
    limits = [w["max_concurrent"] for w in alive]
    capacity = None if any(m is None or m <= 0 for m in limits) else sum(limits)
    running = sum(w["running_jobs"] for w in alive)
    return {
        "alive": len(alive),
        "busy": sum(w["state"] == "busy" for w in workers),
        "idle": sum(w["state"] == "idle" for w in workers),
        "stale": len(workers) - len(alive),
        "capacity": capacity,
        "idle_slots": None if capacity is None else max(0, capacity - running),
    }


@router.get("/queue/status")
def get_queue_status():
    """Return a snapshot of queue depth, job counts, and every worker loop's liveness."""
    with get_conn() as conn:
        rows = conn.execute("SELECT status, COUNT(*) as n FROM jobs GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        for key in ("queued", "processing", "failed"):
            counts.setdefault(key, 0)

        oldest = conn.execute(
            "SELECT id, created_at FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
        ).fetchone()

        job_rows = conn.execute(
            "SELECT worker_id, COUNT(*) as running, MIN(heartbeat_at) as oldest_hb, MAX(heartbeat_at) as newest_hb "
            "FROM jobs WHERE status='processing' AND worker_id IS NOT NULL GROUP BY worker_id"
        ).fetchall()
        loop_rows = conn.execute(
            "SELECT worker_id, role, max_concurrent, app_version, started_at, heartbeat_at FROM worker_heartbeats"
        ).fetchall()

    queue_depth = counts.get("queued", 0)
    workers = _workers(loop_rows, job_rows)

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
        "worker_summary": _summary(workers),
    }
