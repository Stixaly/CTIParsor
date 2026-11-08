"""Version 17 — a job counts its claims, so a job that keeps killing its worker stops (ADR-0097 item 20).

`jobs.attempts` is the number of times a queue loop claimed the job
(`api/queue_loop.py`, `claim_next_queued`).  `requeue_orphans` requeues a job
whose lease expired only while `attempts < JOB_MAX_ATTEMPTS`; the others are
marked failed, so a job that crashes its worker every time does not loop.
Existing rows start at 0: a job queued or running when this version starts
gets its full allowance again.
NOT NULL with a default: the column is added in place, without a rewrite of the
table, and no insert that does not name it breaks."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=17,
    name="job_attempts",
    store="jobs",
    description="jobs.attempts: the claims of a job, bounded by JOB_MAX_ATTEMPTS",
    is_applied=lambda conn: columns_exist(conn, "jobs", "attempts"),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0",
    ),
)
