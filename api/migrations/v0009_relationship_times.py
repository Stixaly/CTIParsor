"""Version 9 — every date the source attaches to a relationship, as
TemporalAssertion JSON (ADR-0063, commit 3a25f45).  Not the TEXT columns of
version 4: a partial value ("2023-03") does not survive the finalize reload's
fromisoformat, and a relationship can carry several dates."""
from api.migrations import Migration, column_exists

MIGRATION = Migration(
    version=9,
    name="relationship_times",
    store="jobs",
    description="relationships.times_json",
    is_applied=lambda conn: column_exists(conn, "relationships", "times_json"),
    statements=(
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS times_json TEXT",
    ),
)
