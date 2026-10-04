"""Version 8 — what Stage 4 did with each row, written with every bundle
(ADR-0061, commit f142334)."""
from api.migrations import Migration, column_exists

MIGRATION = Migration(
    version=8,
    name="bundle_ledger",
    store="jobs",
    description="jobs.bundle_ledger_json",
    is_applied=lambda conn: column_exists(conn, "jobs", "bundle_ledger_json"),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS bundle_ledger_json TEXT",
    ),
)
