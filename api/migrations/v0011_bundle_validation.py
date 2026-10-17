"""Version 11 — what Stage 5 said of the stored bundle.

`bundle_validation` is Stage 5's status for the bundle in `bundle_json`:
`validated`, `unverified` (the JSON schemas were missing) or `invalid`;
`bundle_validation_errors` is a JSON list of the first error messages.  Written
in the same statement as the bundle.  The API refuses to serve an invalid
bundle, and finalize never completes a job with one.  Nullable, no backfill:
NULL means built before this version, or Stage 5 did not run — unknown, served
as before."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=11,
    name="bundle_validation",
    store="jobs",
    description="jobs.bundle_validation, jobs.bundle_validation_errors",
    is_applied=lambda conn: columns_exist(conn, "jobs", "bundle_validation", "bundle_validation_errors"),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS bundle_validation TEXT",
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS bundle_validation_errors TEXT",
    ),
)
