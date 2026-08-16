"""Cross-corpus rule deduplication (ADR-0010, ADR-0017).

The store keeps every ingested rule row (lossless — `raw` and provenance per
corpus are preserved). This module runs *after* a full rebuild and elects one
**canonical** rule per cluster of logical duplicates, demoting the rest
(`is_canonical = 0`). Coverage and drill-down read canonical-only, so a rule
copied across corpora (e.g. hayabusa's converted SigmaHQ rules) counts once,
while genuinely independent rules covering the same technique are untouched.

Clustering axes:
1. `dedup_key` (sha256 of the normalized detection logic, computed by the
   adapter). Rules with no usable detection logic fall back to their own
   `content_hash`, so they never collapse together.
2. Provenance (ADR-0017): Sigma `related:` blocks declaring `derived` or
   `renamed` relationships. This is critical because hayabusa shares only 1
   `dedup_key` with sigmahq, yet 4758 of its 4759 rules declare a `related:`
   pointing to a present sigmahq id. Without provenance folding, these would
   remain distinct clusters despite being logical duplicates.

Election is by corpus priority (lower wins), then corpus name, then rule id —
fully deterministic.

This is a global pass, not per-corpus: `replace_corpus_rules` writes one corpus
at a time and can't see cross-corpus duplicates, so dedup must run once the whole
store is built (and again after any single-corpus rebuild).
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict

#: The only `related:` types that mean "same detection logic".
#:
#: `similar` is the one that must NOT fold: it means same idea, *different* logic
#: or logsource — SigmaHQ's own MeshAgent Windows and MacOS rules declare each
#: other `similar` and are two real detections, so folding them loses coverage.
#: `obsolete` runs the other way (A obsoletes B means B is the dead one), and
#: `merged` is ambiguous. Only `derived` and `renamed` fold.
FOLDING_RELATIONS: frozenset[str] = frozenset({"derived", "renamed"})

_DEFAULT_PRIORITY = 1000  # corpora without an explicit priority rank lowest


def _find(parent: dict[str, str], x: str) -> str:
    """Find the root of x with iterative path compression."""
    if x not in parent:
        parent[x] = x
        return x
    # Iterative path compression to avoid recursion depth limits
    root = x
    while parent[root] != root:
        root = parent[root]
    # Compress path
    while parent[x] != root:
        next_x = parent[x]
        parent[x] = root
        x = next_x
    return root


def _union(parent: dict[str, str], a: str, b: str) -> None:
    """Union two elements, keeping the lexicographically smallest root as parent."""
    root_a = _find(parent, a)
    root_b = _find(parent, b)
    if root_a == root_b:
        return
    # Deterministic: always attach the larger root to the smaller one
    if root_a < root_b:
        parent[root_b] = root_a
    else:
        parent[root_a] = root_b


def _load_related_edges(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """Load provenance edges from rule_related table for folding.

    Returns pairs (rule_id, target_id) where both rules exist in detection_rules
    and the relationship type is in FOLDING_RELATIONS.
    """
    # Check if table exists
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='rule_related'"
    ).fetchone()
    if row is None:
        return []

    # Build index: native_key -> [rule_id, ...]
    native_key_index: dict[str, list[str]] = defaultdict(list)
    for native_key, rule_id in conn.execute("SELECT native_key, id FROM detection_rules"):
        native_key_index[native_key].append(rule_id)

    edges: list[tuple[str, str]] = []
    # Iterate cursor directly to avoid loading entire table into memory
    cursor = conn.execute(
        "SELECT rule_id, related_key, rel_type FROM rule_related"
    )
    for rule_id, related_key, rel_type in cursor:
        # Guard the type: these rows come from third-party YAML, and a rule with
        # `type: 1` in its related block would otherwise crash the whole rebuild.
        if not isinstance(rel_type, str) or not isinstance(related_key, str):
            continue
        if rel_type.strip().lower() not in FOLDING_RELATIONS:
            continue
        # Resolve related_key to target rule ids
        target_ids = native_key_index.get(related_key, [])
        for target_id in target_ids:
            if target_id != rule_id:  # Skip self-references
                edges.append((rule_id, target_id))

    return edges


def _propagate_techniques(
    conn: sqlite3.Connection, clusters: dict[str, list[tuple[str, str]]]
) -> int:
    """Give each canonical rule the union of its cluster's ATT&CK techniques.

    Folding says "these are the same logical detection", so their technique tags
    describe the same detection and belong on the survivor.  Without this,
    coverage silently drops: SigmaHQ's "Double Extension" family derives several
    rules from one parent, and the *derivatives* carry T1036.007 while the parent
    does not — folding them lost the technique its own cluster still detects.
    Measured on the real store, this was the difference between losing 2
    techniques and losing none.

    Idempotent (INSERT OR IGNORE), and safe to re-run: `replace_corpus_rules`
    rewrites `rule_techniques` per corpus and `rebuild_store` calls dedup after,
    so propagated rows are regenerated rather than accumulated.

    Returns the number of technique rows added.
    """
    if conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='rule_techniques'"
    ).fetchone() is None:
        return 0

    # Two full scans, not two queries per cluster: at ~6.3k clusters the
    # per-cluster form issued ~12k round-trips and dominated the rebuild.
    techs_by_rule: dict[str, set[str]] = defaultdict(set)
    for rule_id, technique_id in conn.execute(
        "SELECT rule_id, technique_id FROM rule_techniques"
    ):
        techs_by_rule[rule_id].add(technique_id)
    if not techs_by_rule:
        return 0
    canonical_ids = {
        r[0] for r in conn.execute("SELECT id FROM detection_rules WHERE is_canonical=1")
    }

    rows: list[tuple[str, str]] = []
    for members in clusters.values():
        if len(members) < 2:
            continue                      # nothing folded, nothing to inherit
        techs: set[str] = set()
        winner: str | None = None
        for rid, _corpus in members:
            techs |= techs_by_rule.get(rid, frozenset())
            if winner is None and rid in canonical_ids:
                winner = rid
        if winner is None or not techs:
            continue
        rows.extend((winner, t) for t in sorted(techs - techs_by_rule.get(winner, frozenset())))

    if rows:
        conn.executemany(
            "INSERT OR IGNORE INTO rule_techniques (rule_id, technique_id) VALUES (?,?)",
            rows,
        )
    return len(rows)


def dedupe_store(conn: sqlite3.Connection, priority: dict[str, int] | None = None) -> dict:
    """Recompute `is_canonical` across the whole detection-rule store.

    Args:
        conn:     open connection to the detection store.
        priority: corpus name → priority (lower = higher authority / preferred
                  canonical). Missing corpora rank at _DEFAULT_PRIORITY.

    Returns a summary dict with keys:
        - total: total number of rule rows
        - clusters: number of final clusters
        - canonical: number of canonical rules kept
        - duplicates: number of rules demoted
        - provenance_edges: number of provenance edges loaded
        - merged_by_provenance: number of clusters reduced by provenance folding
    """
    priority = priority or {}
    rows = conn.execute(
        "SELECT id, corpus, dedup_key, content_hash FROM detection_rules"
    ).fetchall()

    # Initialize union-find: each rule is its own root
    parent: dict[str, str] = {rule_id: rule_id for rule_id, _, _, _ in rows}

    # Fusion 1 — by dedup_key
    clusters_by_key: dict[str, list[str]] = defaultdict(list)
    for rule_id, _, dedup_key, content_hash in rows:
        key = dedup_key or f"raw:{content_hash or rule_id}"
        clusters_by_key[key].append(rule_id)

    for members in clusters_by_key.values():
        if len(members) > 1:
            first = members[0]
            for member in members[1:]:
                _union(parent, first, member)

    # Count clusters after fusion 1 only
    clusters_after_fusion1 = len({_find(parent, rid) for rid, _, _, _ in rows})

    # Fusion 2 — by provenance
    edges = _load_related_edges(conn)
    for a, b in edges:
        # Only union if both ids exist in parent (i.e., in detection_rules)
        if a in parent and b in parent:
            _union(parent, a, b)

    # Group rule_ids by final root
    final_clusters: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for rule_id, corpus, _, _ in rows:
        root = _find(parent, rule_id)
        final_clusters[root].append((rule_id, corpus))

    # Election: sort each cluster by (priority, corpus, rule_id), first is canonical
    canonical: list[str] = []
    duplicates: list[str] = []
    # Distinct name from the `members` of the dedup_key loop above: that one is
    # a list[str] of rule ids, this one a list[tuple[rule_id, corpus]], and
    # rebinding the same name to a second type is what mypy flags here.
    for cluster in final_clusters.values():
        winner, *rest = sorted(
            cluster,
            key=lambda m: (priority.get(m[1], _DEFAULT_PRIORITY), m[1], m[0]),
        )
        canonical.append(winner[0])
        duplicates.extend(m[0] for m in rest)

    # Write results
    conn.execute("UPDATE detection_rules SET is_canonical=0")
    conn.executemany(
        "UPDATE detection_rules SET is_canonical=1 WHERE id=?",
        [(rid,) for rid in canonical],
    )
    promoted = _propagate_techniques(conn, final_clusters)
    conn.commit()

    clusters_after_fusion2 = len(final_clusters)
    merged_by_provenance = clusters_after_fusion1 - clusters_after_fusion2

    return {
        "total": len(rows),
        "clusters": clusters_after_fusion2,
        "canonical": len(canonical),
        "duplicates": len(duplicates),
        "provenance_edges": len(edges),
        "merged_by_provenance": merged_by_provenance,
        "techniques_propagated": promoted,
    }
