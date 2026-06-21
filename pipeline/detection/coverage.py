"""Coverage scoring (ADR-0006).

Maps a report's extracted ATT&CK techniques to a 0–3 coverage score against the
detection-rule store. Explicitly NOT lab validation — it reports detection
*readiness*: whether rules (and from how many independent corpora) exist.

Corroboration policy (handles both independent and forked corpuses):
each logical rule is identified by its corpus-independent `native_key` and
attributed to the first corpus it's seen in. A rule forked across repos shares a
native_key, so it collapses to one corpus and never inflates the score.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class CoverageCell:
    technique_id: str
    score: int                              # 0–3
    corpora: list[str] = field(default_factory=list)   # distinct corpora contributing
    rule_count: int = 0                     # distinct logical rules


def score_techniques(
    technique_ids: Iterable[str],
    rule_refs: Iterable[tuple[str, str, str]],
    telemetry_techniques: set[str] | None = None,
) -> list[CoverageCell]:
    """Score each technique.

    Args:
        technique_ids: techniques extracted from the report.
        rule_refs:     (technique_id, corpus, native_key) for matching rules.
        telemetry_techniques: techniques with ATT&CK data-source mapping but no
            rule (score 1 fallback — lights up once the ADR-0005 index enrichment
            lands; pass None to disable).
    """
    telemetry = {t.upper() for t in (telemetry_techniques or set())}

    # Attribute each logical rule (native_key) to its first-seen corpus.
    rule_refs_list = list(rule_refs)
    owner: dict[str, str] = {}
    for _tech, corpus, key in rule_refs_list:
        owner.setdefault(key, corpus)

    tech_corpora: dict[str, set[str]] = {}
    tech_keys: dict[str, set[str]] = {}
    for tech, _corpus, key in rule_refs_list:
        t = tech.upper()
        tech_corpora.setdefault(t, set()).add(owner[key])
        tech_keys.setdefault(t, set()).add(key)

    cells: list[CoverageCell] = []
    for t in dict.fromkeys(x.upper() for x in technique_ids):
        corpora = sorted(tech_corpora.get(t, set()))
        n = len(corpora)
        if n >= 2:
            s = 3
        elif n == 1:
            s = 2
        elif t in telemetry:
            s = 1
        else:
            s = 0
        cells.append(CoverageCell(t, s, corpora, len(tech_keys.get(t, set()))))
    return cells


def _parent_technique(technique_id: str) -> str | None:
    """Return the parent technique of a sub-technique, or None.

    "T1059.001" → "T1059";  "T1059" → None.
    """
    return technique_id.split(".", 1)[0] if "." in technique_id else None


def compute_for_job(conn: sqlite3.Connection, job_id: str) -> dict:
    """Compute coverage for a job from its accepted technique entities."""
    from pipeline.detection.store import rule_refs_for_techniques

    rows = conn.execute(
        "SELECT DISTINCT mitre_id FROM entities "
        "WHERE job_id=? AND mitre_id IS NOT NULL AND mitre_id != '' "
        "AND entity_type IN ('technique','ttp','tactic','procedure') "
        "AND (accepted IS NULL OR accepted=1)",
        (job_id,),
    ).fetchall()
    technique_ids = [r[0].upper() for r in rows if r[0]]

    # Sub-technique → parent roll-up.  A detection rule tagged with the parent
    # technique (e.g. T1059) also provides coverage for its sub-techniques
    # (T1059.001) — detecting the generic behaviour catches the specific case.
    # We therefore (1) query rules for parents too, and (2) re-key each matching
    # rule to the report technique(s) it covers before scoring.  The reverse
    # (a sub-technique rule crediting the parent) is intentionally NOT done — a
    # rule for one sub-technique doesn't cover all siblings of the parent.
    query_ids = set(technique_ids)
    covers: dict[str, set[str]] = {}   # rule technique tag → report techniques covered
    for t in technique_ids:
        covers.setdefault(t, set()).add(t)            # exact match
        parent = _parent_technique(t)
        if parent:
            query_ids.add(parent)
            covers.setdefault(parent, set()).add(t)   # parent rule covers this sub-technique

    raw_refs = rule_refs_for_techniques(conn, query_ids)
    refs = [
        (report_t, corpus, key)
        for tag, corpus, key in raw_refs
        for report_t in covers.get(tag.upper(), ())
    ]
    cells = score_techniques(technique_ids, refs)

    by_score: dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0}
    for c in cells:
        by_score[c.score] = by_score.get(c.score, 0) + 1

    return {
        "job_id": job_id,
        "techniques_total": len(cells),
        "by_score": by_score,
        "validated": False,   # readiness, not lab validation (ADR-0005/0006)
        "cells": [
            {"technique_id": c.technique_id, "score": c.score,
             "corpora": c.corpora, "rule_count": c.rule_count}
            for c in sorted(cells, key=lambda c: (-c.score, c.technique_id))
        ],
    }
