"""SQLite persistence for the detection-rule store (ADR-0006).

Functions take an explicit connection so they're usable from both the build
script and the API, and testable against an isolated temp database.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable

from models.detection import DetectionRule


def _native_key(rule_id: str) -> str:
    """The corpus-independent key (Sigma id or content hash) embedded in a rule id."""
    return rule_id.split(":", 1)[1] if ":" in rule_id else rule_id


def replace_corpus_rules(conn: sqlite3.Connection, corpus: str, rules: Iterable[DetectionRule]) -> int:
    """Idempotently replace all rules for one corpus. Returns rules written."""
    old = [r[0] for r in conn.execute(
        "SELECT id FROM detection_rules WHERE corpus=?", (corpus,)
    ).fetchall()]
    if old:
        conn.executemany("DELETE FROM rule_techniques WHERE rule_id=?", [(i,) for i in old])
        conn.executemany("DELETE FROM rule_atoms WHERE rule_id=?", [(i,) for i in old])
        conn.executemany("DELETE FROM rule_related WHERE rule_id=?", [(i,) for i in old])
        conn.execute("DELETE FROM detection_rules WHERE corpus=?", (corpus,))

    rule_rows, tech_rows, atom_rows, related_rows = [], [], [], []
    for r in rules:
        sev = getattr(r.severity, "value", r.severity)
        rule_rows.append((
            r.id, r.corpus, _native_key(r.id), r.format, r.title, r.description,
            sev, r.license, r.source_ref, r.content_hash, r.dedup_key,
            json.dumps(r.data_sources), r.platform, r.raw,
        ))
        for t in r.technique_ids:
            tech_rows.append((r.id, t.upper()))
        for cls, value in r.atoms:
            atom_rows.append((r.id, cls, value))
        for related_key, rel_type in getattr(r, "related", ()) or ():
            related_rows.append((r.id, related_key, rel_type))

    # is_canonical defaults to 1; the ADR-0010 dedup pass (dedupe_store) runs after
    # the full rebuild and demotes duplicates. Newly-inserted rows start canonical.
    conn.executemany(
        "INSERT OR REPLACE INTO detection_rules "
        "(id,corpus,native_key,format,title,description,severity,license,"
        "source_ref,content_hash,dedup_key,data_sources,platform,raw,is_canonical) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        rule_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO rule_techniques (rule_id, technique_id) VALUES (?,?)",
        tech_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO rule_atoms (rule_id, atom_class, value) VALUES (?,?,?)",
        atom_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO rule_related (rule_id, related_key, rel_type) VALUES (?,?,?)",
        related_rows,
    )
    conn.commit()
    return len(rule_rows)


# ── Atom index queries (ADR-0014) ────────────────────────────────────────────

def replace_rule_atoms(conn: sqlite3.Connection, rows: Iterable[tuple[str, str, str]]) -> int:
    """Insert (rule_id, atom_class, value) atoms, replacing each rule's existing set.

    Used by the offline backfill (scripts/build_rule_atoms.py), which re-derives
    atoms from `detection_rules.raw` so an already-built store gains the index
    without re-cloning any corpus.
    """
    rows = list(rows)
    if not rows:
        return 0
    conn.executemany(
        "DELETE FROM rule_atoms WHERE rule_id=?",
        [(rid,) for rid in dict.fromkeys(r[0] for r in rows)],
    )
    conn.executemany(
        "INSERT OR IGNORE INTO rule_atoms (rule_id, atom_class, value) VALUES (?,?,?)",
        rows,
    )
    conn.commit()
    return len(rows)


def atom_hits(
    conn: sqlite3.Connection, values: Iterable[str], *, chunk: int = 400
) -> list[tuple[str, str, str]]:
    """(rule_id, atom_class, value) for every *canonical* rule holding one of
    these exact atom values.

    Values are chunked: a report can carry hundreds of observables and SQLite
    caps a statement at 999 bound parameters.

    The canonical filter is an EXISTS, not a JOIN, on purpose: given a JOIN the
    planner drives from `idx_detection_canon` — a near-constant column, so it
    scans all 11k rules and probes atoms by rule_id, taking ~2.7s. EXISTS leaves
    `idx_rule_atoms_value` as the only entry point (~8ms).
    """
    vals = sorted({v for v in values if v})
    if not vals:
        return []
    out: list[tuple[str, str, str]] = []
    for i in range(0, len(vals), chunk):
        batch = vals[i:i + chunk]
        placeholders = ",".join("?" * len(batch))
        out.extend(conn.execute(
            f"SELECT a.rule_id, a.atom_class, a.value FROM rule_atoms a "
            f"WHERE a.value IN ({placeholders}) AND EXISTS ("
            f"  SELECT 1 FROM detection_rules d WHERE d.id = a.rule_id AND d.is_canonical=1)",
            batch,
        ).fetchall())
    return [(r[0], r[1], r[2]) for r in out]


def atom_document_frequency(
    conn: sqlite3.Connection, values: Iterable[str], *, chunk: int = 400
) -> dict[str, int]:
    """How many canonical rules hold each value — the `df` of the IDF weight.

    A value present in thousands of rules (`cmd.exe`) says nothing about a
    specific report; one present in none-but-this-rule says almost everything.
    """
    vals = sorted({v for v in values if v})
    if not vals:
        return {}
    df: dict[str, int] = {}
    for i in range(0, len(vals), chunk):
        batch = vals[i:i + chunk]
        placeholders = ",".join("?" * len(batch))
        for value, n in conn.execute(
            f"SELECT a.value, COUNT(DISTINCT a.rule_id) FROM rule_atoms a "
            f"WHERE a.value IN ({placeholders}) AND EXISTS ("
            f"  SELECT 1 FROM detection_rules d WHERE d.id = a.rule_id AND d.is_canonical=1) "
            f"GROUP BY a.value",
            batch,
        ).fetchall():
            df[value] = n
    return df


def technique_document_frequency(
    conn: sqlite3.Connection, technique_ids: Iterable[str], *, chunk: int = 400
) -> dict[str, int]:
    """How many *canonical* rules carry each technique — the technique's DF (ADR-0018).

    The canonical filter is an EXISTS, not a JOIN, for the same reason as
    `atom_hits`: given a JOIN the planner drives from `idx_detection_canon`, a
    near-constant column, and scans every rule. EXISTS leaves `idx_rule_tech_tech`
    as the only entry point.

    Args:
        conn:          open store connection.
        technique_ids: technique ids, already upper-cased by the caller.
        chunk:         batch size — SQLite caps a statement at 999 bound params.

    Returns:
        technique_id → count. A technique carried by no canonical rule is absent
        from the mapping rather than present with 0, so callers use `.get(t, 0)`.
    """
    vals = sorted({v for v in technique_ids if isinstance(v, str) and v.strip()})
    if not vals:
        return {}
    out: dict[str, int] = {}
    for i in range(0, len(vals), chunk):
        batch = vals[i:i + chunk]
        placeholders = ",".join("?" * len(batch))
        for key, n in conn.execute(
            f"SELECT t.technique_id, COUNT(*) FROM rule_techniques t "
            f"WHERE t.technique_id IN ({placeholders}) AND EXISTS ("
            f"  SELECT 1 FROM detection_rules d WHERE d.id = t.rule_id AND d.is_canonical=1) "
            f"GROUP BY t.technique_id",
            batch,
        ):
            out[key] = n
    return out


def technique_counts_for_rules(
    conn: sqlite3.Connection, rule_ids: Iterable[str], *, chunk: int = 400
) -> dict[str, int]:
    """How many techniques each rule carries — its breadth (ADR-0018).

    No canonical filter: the caller only ever asks about rules already selected as
    candidates, so re-checking would cost an EXISTS for nothing.

    Args:
        conn:     open store connection.
        rule_ids: candidate rule ids.
        chunk:    batch size.

    Returns:
        rule_id → technique count. A rule with no techniques is absent.
    """
    vals = sorted({v for v in rule_ids if isinstance(v, str) and v.strip()})
    if not vals:
        return {}
    out: dict[str, int] = {}
    for i in range(0, len(vals), chunk):
        batch = vals[i:i + chunk]
        placeholders = ",".join("?" * len(batch))
        for key, n in conn.execute(
            f"SELECT rule_id, COUNT(*) FROM rule_techniques "
            f"WHERE rule_id IN ({placeholders}) GROUP BY rule_id",
            batch,
        ):
            out[key] = n
    return out


def canonical_rule_count(conn: sqlite3.Connection) -> int:
    """Total canonical rules in the store — the `N` of the IDF weight."""
    return int(conn.execute(
        "SELECT COUNT(*) FROM detection_rules WHERE is_canonical=1"
    ).fetchone()[0])


def atom_index_size(conn: sqlite3.Connection) -> int:
    """Number of rows in the atom index (0 = never built; proposals degrade to
    technique-only ranking)."""
    try:
        return int(conn.execute("SELECT COUNT(*) FROM rule_atoms").fetchone()[0])
    except sqlite3.OperationalError:
        return 0   # table absent on a database older than the ADR-0014 migration


def rule_details(conn: sqlite3.Connection, rule_ids: Iterable[str]) -> dict[str, dict]:
    """Metadata for the given rules, keyed by id (no raw bodies).

    One flat query — the proposal ranking touches hundreds of rules and cannot
    afford `rules_for_technique`'s per-rule `also_in` sub-query.
    """
    ids = sorted({i for i in rule_ids if i})
    if not ids:
        return {}
    out: dict[str, dict] = {}
    for i in range(0, len(ids), 400):
        batch = ids[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for r in conn.execute(
            f"SELECT id, corpus, title, description, severity, license, source_ref, platform "
            f"FROM detection_rules WHERE id IN ({placeholders})",
            batch,
        ).fetchall():
            out[r[0]] = {
                "id": r[0], "corpus": r[1], "title": r[2], "description": r[3],
                "severity": r[4], "license": r[5], "source_ref": r[6],
                "platform": r[7] or "",
            }
    return out


def techniques_for_rules(conn: sqlite3.Connection, rule_ids: Iterable[str]) -> dict[str, list[str]]:
    """ATT&CK technique tags per rule id, for the given rules."""
    ids = sorted({i for i in rule_ids if i})
    if not ids:
        return {}
    out: dict[str, list[str]] = {}
    for i in range(0, len(ids), 400):
        batch = ids[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for rid, tech in conn.execute(
            f"SELECT rule_id, technique_id FROM rule_techniques "
            f"WHERE rule_id IN ({placeholders})",
            batch,
        ).fetchall():
            out.setdefault(rid, []).append(tech)
    return {k: sorted(v) for k, v in out.items()}


def rule_refs_for_techniques(conn: sqlite3.Connection, technique_ids: Iterable[str]) -> list[tuple[str, str, str]]:
    """Return (technique_id, corpus, native_key) for every *canonical* rule covering
    the given techniques. Duplicates folded by the ADR-0010 dedup pass are excluded
    so cross-corpus copies never inflate the corroboration score."""
    ids = sorted({t.upper() for t in technique_ids})
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT rt.technique_id, d.corpus, d.native_key "
        f"FROM rule_techniques rt JOIN detection_rules d ON d.id = rt.rule_id "
        f"WHERE rt.technique_id IN ({placeholders}) AND d.is_canonical=1 "
        f"ORDER BY d.corpus, d.native_key",
        ids,
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def rules_for_technique(conn: sqlite3.Connection, technique_id: str) -> list[dict]:
    """Drill-down: canonical rule metadata covering one technique (no raw body).

    Each canonical rule carries `also_in` — the other corpora that shipped a
    duplicate folded into it (ADR-0010), so provenance survives deduplication.
    """
    rows = conn.execute(
        "SELECT d.id, d.corpus, d.title, d.severity, d.license, d.source_ref, d.dedup_key "
        "FROM rule_techniques rt JOIN detection_rules d ON d.id = rt.rule_id "
        "WHERE rt.technique_id=? AND d.is_canonical=1 ORDER BY d.corpus, d.title",
        (technique_id.upper(),),
    ).fetchall()
    out = []
    for r in rows:
        dups = conn.execute(
            "SELECT DISTINCT corpus FROM detection_rules "
            "WHERE dedup_key=? AND is_canonical=0 AND corpus != ? ORDER BY corpus",
            (r[6], r[1]),
        ).fetchall() if r[6] else []
        out.append({
            "id": r[0], "corpus": r[1], "title": r[2], "severity": r[3],
            "license": r[4], "source_ref": r[5],
            "also_in": [d[0] for d in dups],
        })
    return out


def canonical_rule_ids_for_techniques(
    conn: sqlite3.Connection, technique_ids: Iterable[str]
) -> list[tuple[str, str]]:
    """(technique_id, rule_id) for every *canonical* rule covering the given
    techniques, in a single indexed query.

    Unlike rules_for_technique (which computes per-rule `also_in` provenance via
    an N+1 subquery), this is a flat lookup — used by the bulk Sigma export and
    by the ADR-0014 proposal ranking, where only the rule ids matter.

    The canonical filter is an EXISTS for the same reason as `atom_hits`: as a
    JOIN, the planner enters through `idx_detection_canon` and scans every rule
    (~1s); as an EXISTS it drives off the technique index (~10ms)."""
    ids = sorted({t.upper() for t in technique_ids})
    if not ids:
        return []
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT rt.technique_id, rt.rule_id FROM rule_techniques rt "
        f"WHERE rt.technique_id IN ({placeholders}) AND EXISTS ("
        f"  SELECT 1 FROM detection_rules d WHERE d.id = rt.rule_id AND d.is_canonical=1)",
        ids,
    ).fetchall()
    return [(r[0], r[1]) for r in rows]


def canonical_rule_bodies(conn: sqlite3.Connection, rule_ids: Iterable[str]) -> dict[str, dict]:
    """Return raw rule bodies + provenance for the given canonical rule ids.

    Keyed by rule id: {corpus, native_key, title, license, source_ref, raw}.
    Used by the per-report Sigma export (ADR-0006). Unlike the metadata-only
    drill-down endpoints, this intentionally returns `raw` for local export —
    callers package each body with its license so provenance survives."""
    ids = sorted({i for i in rule_ids if i})
    if not ids:
        return {}
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT id, corpus, native_key, title, license, source_ref, raw "
        f"FROM detection_rules WHERE id IN ({placeholders})",
        ids,
    ).fetchall()
    return {
        r[0]: {
            "corpus": r[1], "native_key": r[2], "title": r[3],
            "license": r[4], "source_ref": r[5], "raw": r[6],
        }
        for r in rows
    }


def corpus_counts(conn: sqlite3.Connection) -> list[dict]:
    """Per-corpus rule counts — for the /api/detection-corpora endpoint.

    `rules` is the total ingested; `canonical` is what survives dedup (the rest
    are copies folded into another corpus' canonical rule — ADR-0010)."""
    rows = conn.execute(
        "SELECT corpus, license, COUNT(*), COALESCE(SUM(is_canonical),0) "
        "FROM detection_rules GROUP BY corpus, license ORDER BY corpus"
    ).fetchall()
    return [{"corpus": r[0], "license": r[1], "rules": r[2], "canonical": r[3]} for r in rows]
