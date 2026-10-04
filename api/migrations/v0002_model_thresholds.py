"""Version 2 — calibrated NER confidence cutoffs (ADR-0051, commit c57068a)."""
from api.migrations import Migration, table_exists

MIGRATION = Migration(
    version=2,
    name="model_thresholds",
    store="jobs",
    description="model_thresholds: per source and entity type, the calibrated cutoff",
    is_applied=lambda conn: table_exists(conn, "model_thresholds"),
    statements=(
        """CREATE TABLE IF NOT EXISTS model_thresholds (
    source TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    threshold DOUBLE PRECISION NOT NULL,
    sample_size INTEGER NOT NULL DEFAULT 0,
    target_precision DOUBLE PRECISION,
    precision_at DOUBLE PRECISION,
    recall_retained DOUBLE PRECISION,
    origin TEXT NOT NULL DEFAULT 'calibrated',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source, entity_type)
)""",
    ),
)
