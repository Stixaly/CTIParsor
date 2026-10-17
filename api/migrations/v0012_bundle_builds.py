"""Version 12 — which build of a job's bundle is stored (ADR-0086).

`review_revision` counts every write to the job's `entities` and `relationships`
rows.  A row-level trigger bumps it in the transaction of the write itself, so
no route, worker step or future writer has to remember to.
`bundle_review_revision` is the `review_revision` the stored bundle was built
from: a finalize that read the rows at an older revision than the stored
bundle's is refused instead of overwriting it.  NULL means built before this
version, or by a writer with no snapshot — any build may replace it.
`bundle_build_json` is what built the stored bundle (code revision, policy,
environment, manifest, kind); NULL means built before this version, and
`run_config_json` describes it.  Nullable, no backfill: every job starts at
revision 0."""
from api.migrations import Migration, columns_exist, triggers_exist

MIGRATION = Migration(
    version=12,
    name="bundle_builds",
    store="jobs",
    description="jobs.review_revision, jobs.bundle_review_revision, jobs.bundle_build_json, "
                "triggers that bump the revision",
    is_applied=lambda conn: (
        columns_exist(conn, "jobs", "review_revision", "bundle_review_revision", "bundle_build_json")
        and triggers_exist(conn, "entities_review_revision", "relationships_review_revision")),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS review_revision BIGINT NOT NULL DEFAULT 0",
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS bundle_review_revision BIGINT",
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS bundle_build_json TEXT",
        # The UPDATE names the schema of the table that fired the trigger: every
        # test, and any deployment that sets search_path, has its own `jobs`.
        # A write that moves a row to another job bumps both.
        """CREATE OR REPLACE FUNCTION bump_review_revision() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    jobs_touched text[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        jobs_touched := ARRAY[NEW.job_id];
    ELSIF TG_OP = 'DELETE' THEN
        jobs_touched := ARRAY[OLD.job_id];
    ELSE
        jobs_touched := ARRAY[NEW.job_id, OLD.job_id];
    END IF;
    EXECUTE format('UPDATE %I.jobs SET review_revision = review_revision + 1 WHERE id = ANY($1)',
                   TG_TABLE_SCHEMA) USING jobs_touched;
    RETURN NULL;
END
$$""",
        "CREATE OR REPLACE TRIGGER entities_review_revision AFTER INSERT OR UPDATE OR DELETE ON entities "
        "FOR EACH ROW EXECUTE FUNCTION bump_review_revision()",
        "CREATE OR REPLACE TRIGGER relationships_review_revision AFTER INSERT OR UPDATE OR DELETE ON relationships "
        "FOR EACH ROW EXECUTE FUNCTION bump_review_revision()",
    ),
)
