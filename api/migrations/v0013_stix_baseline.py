"""Version 13 — enriching a STIX 2.1 bundle the analyst already has (ADR-0090).

`jobs.pipeline_mode` is 'full' (no baseline, as before) or 'enrich'.  The
baseline lives in `job_baselines`, one row per job, deleted with it (the foreign
key cascades, as the entities' does): the bundle as received (`bundle_json`,
never rewritten), its normalised index and its intake report.  `validated` is 1
once the worker has re-run the intake with the JSON schemas (the HTTP request does not: it costs seconds per thousand
objects).  `enrichment_status` and `baseline_stix_id` on entities and
relationships say how a row relates to the baseline; NULL in full mode.  Every
addition is nullable or defaulted, no backfill, so a worker of the previous
revision keeps inserting."""
from api.migrations import Migration, columns_exist, table_exists

MIGRATION = Migration(
    version=13,
    name="stix_baseline",
    store="jobs",
    description="jobs.pipeline_mode, job_baselines, entities/relationships "
                "enrichment_status and baseline_stix_id",
    is_applied=lambda conn: (
        columns_exist(conn, "jobs", "pipeline_mode")
        and table_exists(conn, "job_baselines")
        and columns_exist(conn, "entities", "enrichment_status", "baseline_stix_id")
        and columns_exist(conn, "relationships", "enrichment_status", "baseline_stix_id")),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS pipeline_mode TEXT NOT NULL DEFAULT 'full'",
        "CREATE TABLE IF NOT EXISTS job_baselines ("
        " job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE, sha256 TEXT NOT NULL,"
        " size_bytes INTEGER NOT NULL, report_id TEXT,"
        " bundle_json TEXT NOT NULL, index_json TEXT NOT NULL, intake_json TEXT NOT NULL,"
        " validated INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
        "ALTER TABLE entities ADD COLUMN IF NOT EXISTS enrichment_status TEXT",
        "ALTER TABLE entities ADD COLUMN IF NOT EXISTS baseline_stix_id TEXT",
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS enrichment_status TEXT",
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS baseline_stix_id TEXT",
    ),
)
