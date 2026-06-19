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
        conn.execute("DELETE FROM detection_rules WHERE corpus=?", (corpus,))

    rule_rows, tech_rows = [], []
    for r in rules:
        sev = getattr(r.severity, "value", r.severity)
        rule_rows.append((
            r.id, r.corpus, _native_key(r.id), r.format, r.title, r.description,
            sev, r.license, r.source_ref, r.content_hash, r.dedup_key,
            json.dumps(r.data_sources), r.raw,
        ))
        for t in r.technique_ids:
            tech_rows.append((r.id, t.upper()))

    # is_canonical defaults to 1; the ADR-0010 dedup pass (dedupe_store) runs after
    # the full rebuild and demotes duplicates. Newly-inserted rows start canonical.
    conn.executemany(
        "INSERT OR REPLACE INTO detection_rules "
        "(id,corpus,native_key,format,title,description,severity,license,"
        "source_ref,content_hash,dedup_key,data_sources,raw,is_canonical) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        rule_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO rule_techniques (rule_id, technique_id) VALUES (?,?)",
        tech_rows,
    )
    conn.commit()
    return len(rule_rows)


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


def corpus_counts(conn: sqlite3.Connection) -> list[dict]:
    """Per-corpus rule counts — for the /api/detection-corpora endpoint.

    `rules` is the total ingested; `canonical` is what survives dedup (the rest
    are copies folded into another corpus' canonical rule — ADR-0010)."""
    rows = conn.execute(
        "SELECT corpus, license, COUNT(*), COALESCE(SUM(is_canonical),0) "
        "FROM detection_rules GROUP BY corpus, license ORDER BY corpus"
    ).fetchall()
    return [{"corpus": r[0], "license": r[1], "rules": r[2], "canonical": r[3]} for r in rows]
