"""Mesure de la pertinence des règles de détection sur les rapports réels.

Ce script compare, pour chaque rapport de la base `cti_stix.db`, les règles
proposées par la couverture ATT&CK (jointure par tag) aux règles réellement
adossées à une preuve technique du rapport. Il évalue également l'impact
d'un élargissement de la table `MATCHABLE` pour inclure les classes
`strlit` et `pipe`, actuellement indexées mais jamais interrogées.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.detection.coverage import job_technique_ids
from pipeline.detection.observables import Observable, observables_from_entities
from pipeline.detection.relevance import MATCHABLE, _parent, job_observable_rows
from pipeline.detection.store import atom_hits, canonical_rule_ids_for_techniques

WIDENED_EXTRA: dict[str, frozenset[str]] = {
    "hash":     frozenset({"strlit"}),
    "ip":       frozenset({"strlit"}),
    "domain":   frozenset({"strlit"}),
    "url":      frozenset({"strlit"}),
    "file":     frozenset({"strlit"}),
    "image":    frozenset({"strlit"}),
    "registry": frozenset({"strlit"}),
    "name":     frozenset({"strlit", "pipe"}),
    "user":     frozenset(),
    "port":     frozenset(),
}


def _technique_rule_ids(conn: sqlite3.Connection, job_id: str) -> set[str]:
    """Récupère les ids des règles canoniques jointes par tag ATT&CK."""
    technique_ids = job_technique_ids(conn, job_id)
    if not technique_ids:
        return set()
    all_techs = set(technique_ids)
    for tid in technique_ids:
        parent = _parent(tid)
        if parent:
            all_techs.add(parent)
    pairs = canonical_rule_ids_for_techniques(conn, list(all_techs))
    return {rule_id for _, rule_id in pairs}


def _evidence_by_rule(
    conn: sqlite3.Connection,
    observables: list[Observable],
    matchable: dict[str, frozenset[str]],
) -> dict[str, set[str]]:
    """Associe chaque règle aux observables distincts qu'elle porte."""
    if not observables:
        return {}
    values = list({obs.value for obs in observables})
    if not values:
        return {}
    hits = atom_hits(conn, values)
    if not hits:
        return {}
    value_index: dict[str, list[Observable]] = {}
    for obs in observables:
        value_index.setdefault(obs.value, []).append(obs)
    result: dict[str, set[str]] = {}
    for rule_id, atom_class, value in hits:
        for obs in value_index.get(value, []):
            if atom_class in matchable.get(obs.obs_class, frozenset()):
                result.setdefault(rule_id, set()).add(obs.display)
    return result


def _rule_formats(conn: sqlite3.Connection, rule_ids: set[str]) -> dict[str, str]:
    """Récupère le format de chaque règle par lots de 400 ids."""
    if not rule_ids:
        return {}
    ids = list(rule_ids)
    result: dict[str, str] = {}
    for i in range(0, len(ids), 400):
        chunk = ids[i:i + 400]
        placeholders = ",".join("?" * len(chunk))
        rows = conn.execute(
            f"SELECT id, format FROM detection_rules WHERE id IN ({placeholders})",
            chunk,
        ).fetchall()
        for rid, fmt in rows:
            result[rid] = fmt
    return result


def _widened(
    matchable: dict[str, frozenset[str]],
    extra: dict[str, frozenset[str]],
) -> dict[str, frozenset[str]]:
    """Construit la table élargie sans muter l'originale."""
    return {
        k: matchable.get(k, frozenset()) | extra.get(k, frozenset())
        for k in set(matchable) | set(extra)
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Mesure de pertinence des règles")
    parser.add_argument("--db", default="cti_stix.db")
    parser.add_argument("--job", action="append", default=None)
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(args.db, file=sys.stderr)
        sys.exit(1)

    try:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        conn = sqlite3.connect(args.db)

    if args.job:
        job_ids = args.job
    else:
        rows = conn.execute(
            "SELECT id FROM jobs ORDER BY created_at DESC"
        ).fetchall()
        job_ids = [r[0] for r in rows]

    if not job_ids:
        print("no jobs")
        sys.exit(0)

    widened_table = _widened(MATCHABLE, WIDENED_EXTRA)

    table1_rows = []
    all_evidence_current: dict[str, set[str]] = {}
    all_evidence_widened: dict[str, set[str]] = {}
    all_rule_formats: dict[str, str] = {}
    all_rule_corpora: dict[str, str] = {}
    all_rule_titles: dict[str, str] = {}
    job_widened_counts: list[tuple[str, int]] = []

    for job_id in job_ids:
        rows = job_observable_rows(conn, job_id)
        observables = observables_from_entities(rows)
        n_obs = len(observables)
        n_tech = len(job_technique_ids(conn, job_id))
        tag_rules = _technique_rule_ids(conn, job_id)
        n_tag = len(tag_rules)

        ev_current = _evidence_by_rule(conn, observables, MATCHABLE)
        ev_widened = _evidence_by_rule(conn, observables, widened_table)

        n_ev = len(ev_current)
        n_ev2 = sum(1 for v in ev_current.values() if len(v) >= 2)
        n_w = len(ev_widened)
        n_w2 = sum(1 for v in ev_widened.values() if len(v) >= 2)

        # Union, never update(): two reports can match the SAME rule, and a
        # dict update would drop the first report's observables for it.
        for rid, obs_set in ev_current.items():
            all_evidence_current.setdefault(rid, set()).update(obs_set)
        for rid, obs_set in ev_widened.items():
            all_evidence_widened.setdefault(rid, set()).update(obs_set)
        job_widened_counts.append((job_id, n_w))

        table1_rows.append((job_id, n_obs, n_tech, n_tag, n_ev, n_ev2, n_w, n_w2))

    all_rule_ids = set(all_evidence_current) | set(all_evidence_widened)
    all_rule_formats = _rule_formats(conn, all_rule_ids)

    if all_rule_ids:
        ids = list(all_rule_ids)
        for i in range(0, len(ids), 400):
            chunk = ids[i:i + 400]
            placeholders = ",".join("?" * len(chunk))
            rows = conn.execute(
                f"SELECT id, corpus, title FROM detection_rules WHERE id IN ({placeholders})",
                chunk,
            ).fetchall()
            for rid, corpus, title in rows:
                all_rule_corpora[rid] = corpus or ""
                all_rule_titles[rid] = title or ""

    # TABLEAU 1
    headers = ["report", "obs", "tech", "tagRules", "evRules", "ev2+", "wRules", "w2+"]
    widths = [34, 5, 5, 8, 7, 5, 6, 5]

    def fmt_row(cols: list[str]) -> str:
        return " ".join(c.ljust(w) for c, w in zip(cols, widths))

    print(fmt_row(headers))
    print("-" * sum(widths))

    total = [0] * 7
    for row in table1_rows:
        job_id = row[0]
        filename = conn.execute(
            "SELECT original_filename FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        name = filename[0] if filename and filename[0] else "(sans nom)"
        name = name[:34]
        cols = [name] + [str(v) for v in row[1:]]
        print(fmt_row(cols))
        for i in range(1, 8):
            total[i - 1] += row[i]

    total_cols = ["TOTAL"] + [str(v) for v in total]
    print(fmt_row(total_cols))

    # TABLEAU 2
    print()
    print("Histogramme des observables distincts par règle (MATCHABLE actuel):")
    hist_current = Counter(len(v) for v in all_evidence_current.values())
    for k in sorted(hist_current):
        print(f"n={k} : {hist_current[k]}")

    print()
    print("Histogramme des observables distincts par règle (table élargie):")
    hist_widened = Counter(len(v) for v in all_evidence_widened.values())
    for k in sorted(hist_widened):
        print(f"n={k} : {hist_widened[k]}")

    print()
    print("Répartition par format des règles à preuve:")
    fmt_current = Counter(all_rule_formats.get(rid, "?") for rid in all_evidence_current)
    fmt_widened = Counter(all_rule_formats.get(rid, "?") for rid in all_evidence_widened)
    all_fmts = sorted(set(fmt_current) | set(fmt_widened))
    for fmt in all_fmts:
        print(f"{fmt} : {fmt_current.get(fmt, 0)} -> {fmt_widened.get(fmt, 0)}")

    # TABLEAU 3
    print()
    top_jobs = sorted(job_widened_counts, key=lambda x: x[1], reverse=True)[:3]
    for job_id, _ in top_jobs:
        ev_w = _evidence_by_rule(conn, observables_from_entities(job_observable_rows(conn, job_id)), widened_table)
        if not ev_w:
            continue
        top_rules = sorted(ev_w.items(), key=lambda x: len(x[1]), reverse=True)[:15]
        print(f"Job {job_id}:")
        for rid, displays in top_rules:
            n = len(displays)
            fmt = all_rule_formats.get(rid, "?")
            corpus = all_rule_corpora.get(rid, "")
            title = all_rule_titles.get(rid, "")[:52]
            top3 = ", ".join(sorted(displays)[:3])
            print(f"{n} {fmt} {corpus} {title} :: {top3}")

    conn.close()


if __name__ == "__main__":
    main()
