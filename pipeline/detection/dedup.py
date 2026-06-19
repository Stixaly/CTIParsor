"""Cross-corpus rule deduplication (ADR-0010).

The store keeps every ingested rule row (lossless — `raw` and provenance per
corpus are preserved). This module runs *after* a full rebuild and elects one
**canonical** rule per cluster of logical duplicates, demoting the rest
(`is_canonical = 0`). Coverage and drill-down read canonical-only, so a rule
copied across corpora (e.g. hayabusa's converted SigmaHQ rules) counts once,
while genuinely independent rules covering the same technique are untouched.

Clustering axis — `dedup_key` (sha256 of the normalized detection logic, computed
by the adapter). Rules with no usable detection logic fall back to their own
`content_hash`, so they never collapse together. Election is by corpus priority
(lower wins), then corpus name, then rule id — fully deterministic.

This is a global pass, not per-corpus: `replace_corpus_rules` writes one corpus
at a time and can't see cross-corpus duplicates, so dedup must run once the whole
store is built (and again after any single-corpus rebuild).
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict

_DEFAULT_PRIORITY = 1000  # corpora without an explicit priority rank lowest


def dedupe_store(conn: sqlite3.Connection, priority: dict[str, int] | None = None) -> dict:
    """Recompute `is_canonical` across the whole detection-rule store.

    Args:
        conn:     open connection to the detection store.
        priority: corpus name → priority (lower = higher authority / preferred
                  canonical). Missing corpora rank at _DEFAULT_PRIORITY.

    Returns a summary: total rows, distinct clusters, canonical kept, duplicates
    folded.
    """
    priority = priority or {}
    rows = conn.execute(
        "SELECT id, corpus, dedup_key, content_hash FROM detection_rules"
    ).fetchall()

    clusters: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for rule_id, corpus, dedup_key, content_hash in rows:
        # An empty dedup_key (no detection logic) must not pool with other such
        # rules — key it by content_hash, then by id, so it stays singular.
        key = dedup_key or f"raw:{content_hash or rule_id}"
        clusters[key].append((rule_id, corpus))

    canonical: list[str] = []
    duplicates: list[str] = []
    for members in clusters.values():
        winner, *rest = sorted(
            members,
            key=lambda m: (priority.get(m[1], _DEFAULT_PRIORITY), m[1], m[0]),
        )
        canonical.append(winner[0])
        duplicates.extend(m[0] for m in rest)

    # Bulk-flag: demote everything, then promote the winners.
    conn.execute("UPDATE detection_rules SET is_canonical=0")
    conn.executemany(
        "UPDATE detection_rules SET is_canonical=1 WHERE id=?",
        [(rid,) for rid in canonical],
    )
    conn.commit()

    return {
        "total": len(rows),
        "clusters": len(clusters),
        "canonical": len(canonical),
        "duplicates": len(duplicates),
    }
