"""Version 10 — why the pipeline held a row back from the bundle (ADR-0082).

A relationship Stage 3d could not decide, or a technique Stage 3f's selection
could not, is stored pending with the reason in `held_reason`.  Finalize
exports a pending row only when this is NULL; an analyst's accept ships it.
Nullable, no backfill: every row stored before this version was shipped."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=10,
    name="held_for_review",
    store="jobs",
    description="entities.held_reason, relationships.held_reason",
    is_applied=lambda conn: (columns_exist(conn, "entities", "held_reason")
                             and columns_exist(conn, "relationships", "held_reason")),
    statements=(
        "ALTER TABLE entities ADD COLUMN IF NOT EXISTS held_reason TEXT",
        "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS held_reason TEXT",
    ),
)
