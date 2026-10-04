"""Version 3 — deny and promote lists grown from analyst decisions (ADR-0052,
commit 5787c6e)."""
from api.migrations import Migration, index_exists, table_exists

MIGRATION = Migration(
    version=3,
    name="entity_overrides",
    store="jobs",
    description="entity_overrides: terms to deny or promote, with their counts",
    is_applied=lambda conn: (table_exists(conn, "entity_overrides")
                             and index_exists(conn, "idx_entity_overrides_status")),
    statements=(
        """CREATE TABLE IF NOT EXISTS entity_overrides (
    id TEXT PRIMARY KEY,
    term TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate',
    display TEXT,
    accepted_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    job_count INTEGER NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT 'auto',
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (term, entity_type, action)
)""",
        "CREATE INDEX IF NOT EXISTS idx_entity_overrides_status ON entity_overrides(status)",
    ),
)
