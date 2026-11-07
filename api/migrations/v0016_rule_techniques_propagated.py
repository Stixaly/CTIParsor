"""Version 16 — the techniques a canonical rule inherits from its cluster are marked (#432).

`rule_techniques` held two kinds of row under the same key: the techniques a rule
has from its own corpus, and the ones dedup gave the canonical rule from the other
rules folded under it (`pipeline/detection/dedup.py`, ADR-0010).  Nothing told them
apart, so an inherited technique outlived the corpus it came from.  `propagated` is
1 for the inherited rows: dedup deletes them and computes them again at every pass.
Existing rows are 0, the inherited ones of an earlier store included, so they stay
until the corpus of the rule they sit under is rewritten: `replace_corpus_rules`
deletes that rule's rows, and `rebuild_store` rewrites every corpus whose clone is
present.  A corpus skipped for a missing clone keeps them until its clone is back.
NOT NULL with a default: the column is added in place, without a rewrite of the
table, and no insert that does not name it breaks."""
from api.migrations import Migration, columns_exist

MIGRATION = Migration(
    version=16,
    name="rule_techniques_propagated",
    store="rules",
    description="rule_techniques.propagated",
    is_applied=lambda conn: columns_exist(conn, "rule_techniques", "propagated"),
    statements=(
        "ALTER TABLE rule_techniques ADD COLUMN IF NOT EXISTS propagated INTEGER NOT NULL DEFAULT 0",
    ),
)
