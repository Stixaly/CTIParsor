"""Version 5 — the detection-rule store moves to PostgreSQL (ADR-0053, commit
59602b3).  Corpus-derived, not per report: scripts/build_detection_index.py
fills it.  `rule_text` replaces SQLite's FTS5 table with a generated tsvector
and a GIN index ('simple' configuration: no stemming, no substring match)."""
from api.migrations import Migration, indexes_exist, tables_exist

_TABLES = ("detection_rules", "rule_bytes", "rule_techniques", "rule_text", "rule_atoms", "rule_related")
_INDEXES = ("idx_rule_text_tsv", "idx_rule_related_key", "idx_rule_tech_tech", "idx_detection_corpus",
            "idx_detection_dedup", "idx_detection_canon", "idx_rule_atoms_value")

MIGRATION = Migration(
    version=5,
    name="rule_store",
    store="rules",
    description="Detection-rule store: rules, byte sizes, techniques, full text, atoms, provenance",
    is_applied=lambda conn: tables_exist(conn, *_TABLES) and indexes_exist(conn, *_INDEXES),
    statements=(
        """CREATE TABLE IF NOT EXISTS detection_rules (
    id           TEXT PRIMARY KEY,
    corpus       TEXT NOT NULL,
    native_key   TEXT NOT NULL,
    format       TEXT NOT NULL DEFAULT 'sigma',
    title        TEXT NOT NULL,
    description  TEXT DEFAULT '',
    severity     TEXT DEFAULT 'unknown',
    license      TEXT DEFAULT 'unknown',
    source_ref   TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    dedup_key    TEXT DEFAULT '',
    is_canonical INTEGER DEFAULT 1,
    data_sources TEXT DEFAULT '[]',
    platform     TEXT DEFAULT '',
    raw          TEXT DEFAULT ''
)""",
        # Byte length of each rule body in its own table (ADR-0022), so reading
        # it never walks the multi-kilobyte `raw` body.
        """CREATE TABLE IF NOT EXISTS rule_bytes (
    rule_id TEXT PRIMARY KEY,
    bytes   INTEGER NOT NULL DEFAULT 0
)""",
        """CREATE TABLE IF NOT EXISTS rule_techniques (
    rule_id      TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, technique_id)
)""",
        # ADR-0031: full-text index over each canonical rule's title and
        # description; GENERATED, so always in sync with `body`.
        """CREATE TABLE IF NOT EXISTS rule_text (
    rule_id  TEXT PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    body     TEXT NOT NULL,
    body_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', body)) STORED
)""",
        "CREATE INDEX IF NOT EXISTS idx_rule_text_tsv ON rule_text USING GIN (body_tsv)",
        # ADR-0014: the literal values a rule looks for, from its `detection:` block.
        """CREATE TABLE IF NOT EXISTS rule_atoms (
    rule_id    TEXT NOT NULL,
    atom_class TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (rule_id, atom_class, value)
)""",
        # ADR-0017: declared rule provenance, the Sigma `related:` block.
        """CREATE TABLE IF NOT EXISTS rule_related (
    rule_id     TEXT NOT NULL,
    related_key TEXT NOT NULL,
    rel_type    TEXT NOT NULL,
    PRIMARY KEY (rule_id, related_key, rel_type)
)""",
        "CREATE INDEX IF NOT EXISTS idx_rule_related_key ON rule_related(related_key)",
        "CREATE INDEX IF NOT EXISTS idx_rule_tech_tech   ON rule_techniques(technique_id)",
        "CREATE INDEX IF NOT EXISTS idx_detection_corpus ON detection_rules(corpus)",
        "CREATE INDEX IF NOT EXISTS idx_detection_dedup  ON detection_rules(dedup_key)",
        "CREATE INDEX IF NOT EXISTS idx_detection_canon  ON detection_rules(is_canonical)",
        "CREATE INDEX IF NOT EXISTS idx_rule_atoms_value ON rule_atoms(value)",
    ),
)
