"""Version 7 — the decision journal outlives its report (ADR-0059, commit
6c62c53): deleting a report must not erase who decided what on it, so
`review_decisions` loses the cascading key version 6 gave it.  Rows hold ids,
origins and times, not report content."""
from api.migrations import Migration, constraint_exists, table_exists

MIGRATION = Migration(
    version=7,
    name="review_decisions_survive_job_deletion",
    store="jobs",
    description="review_decisions: drop the foreign key to jobs",
    is_applied=lambda conn: (table_exists(conn, "review_decisions")
                             and not constraint_exists(conn, "review_decisions", "review_decisions_job_id_fkey")),
    statements=(
        "ALTER TABLE review_decisions DROP CONSTRAINT IF EXISTS review_decisions_job_id_fkey",
    ),
)
