"""Version 4 — STIX 2.1 start_time / stop_time on relationships (commit
e8167d6).  Written by nothing since ADR-0063 (version 9); a row that still has
them is legacy and is read as dates of unknown precision (pipeline.temporal)."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=4,
    name="relationship_time_bounds",
    store="jobs",
    description="relationships.start_time, relationships.stop_time",
    is_applied=lambda conn: columns_exist(conn, "relationships", "start_time", "stop_time"),
    statements=(
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS start_time TEXT",
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS stop_time TEXT",
    ),
)
