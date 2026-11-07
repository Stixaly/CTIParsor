"""Version 15 — the types Stage 2 resolved away, kept for the finalize ledger (#397).

`jobs.resolved_types_json` is a JSON list of `{"value", "entity_type", "source"}`:
the entities `resolve_type_conflicts` dropped because their name was typed two
ways and another source's type outranked theirs (ADR-0092).  The worker writes
it with `llm_result_json`, `"[]"` when Stage 2 dropped none.  A finalize or a
rebuild reads it to record them in the MappingLedger as `outranked_type`, as the
CLI run does; the bundle is the same with or without it.  Nullable, no backfill:
NULL means the job ran before this version, and its finalize ledger lacks the
losers, as before.  A worker of the previous revision ignores the column."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=15,
    name="resolved_types",
    store="jobs",
    description="jobs.resolved_types_json",
    is_applied=lambda conn: columns_exist(conn, "jobs", "resolved_types_json"),
    statements=(
        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS resolved_types_json TEXT",
    ),
)
