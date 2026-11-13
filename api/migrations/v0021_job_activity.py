"""Version 21 — the retention clock of a report counts its human decisions (#723).

`jobs.activity_at` is the time of the last decision or edit an analyst made on the
report's entities and relationships (api/routes/_common.py, `renew_retention`).  The
write and this column are one transaction: a decision that is refused or rolled back
does not renew the report.  The retention sweep (api/routes/jobs.py) deletes a report
only when neither `updated_at` nor `activity_at` is recent.

`updated_at` is not used for this: the dashboard reads it as the end of a run, so a
decision made after a report was finished would lengthen its measured duration.

Existing rows: the backfill takes the newest human decision of each report from the
decision journal (`review_decisions`, origin `human` or `human_bulk`), so a report an
analyst decided on within the window is kept after the upgrade.  Edits that were not
decisions (a value or a type changed, a row created or deleted) are not in the journal
and cannot be backfilled.  NULL means no such decision is known.  Running the backfill
again keeps the newer of the two values, so nothing is lost."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=21,
    name="job_activity",
    store="jobs",
    description="jobs.activity_at: the last human decision on a report, the retention clock's second input",
    is_applied=lambda conn: columns_exist(conn, "jobs", "activity_at"),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS activity_at TEXT",
        "UPDATE jobs SET activity_at = d.last FROM ("
        " SELECT job_id, MAX(created_at) AS last FROM review_decisions"
        " WHERE origin IN ('human', 'human_bulk') GROUP BY job_id) d"
        " WHERE jobs.id = d.job_id AND (jobs.activity_at IS NULL OR jobs.activity_at < d.last)",
    ),
)
