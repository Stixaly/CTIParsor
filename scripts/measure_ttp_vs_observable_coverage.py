"""
measure_ttp_vs_observable_coverage.py

Purpose
-------
Quantify how much of the current ATT&CK-technique-indexed detection coverage is
actually backed by technical evidence (IoCs, malware, tools) found in the report.

The script is strictly read-only: it opens the SQLite database in read-only
mode, calls the project's detection APIs, and prints a plain-text report to
stdout. It never writes to the database or to any file.

How to read the output
----------------------
Section A  – Report profile: technique/observable counts, ATT&CK domain
             distribution, and non-matchable observable classes.
Section B  – Technique-driven rule selection (what coverage.py does today).
Section C  – Observable-driven rule selection (evidence-backed).
Section D  – Set overlap between B and C: which rules are covered by both,
             which are only by technique, which are only by evidence.
Section E  – Score audit: for every cell scored >= 2, check whether at least
             one of its rules is evidence-backed.
Section F  – Latency of compute_for_job and rank_rules.
Global     – Aggregated D and E statistics across all jobs.

Exit code 0 on success, 1 if no job could be measured.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

# Insert the repository root into sys.path before importing project modules.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.detection.coverage import (
    _parent_technique,
    compute_for_job,
    job_technique_ids,
)
from pipeline.detection.observables import observables_from_entities
from pipeline.detection.relevance import (
    MATCHABLE,
    job_observable_rows,
    rank_rules,
)
from pipeline.detection.store import (
    atom_hits,
    canonical_rule_count,
    canonical_rule_ids_for_techniques,
)

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_attack_domains(data_dir: Path) -> dict[str, str]:
    """Build a mapping technique_id (uppercase) -> ATT&CK domain.

    Reads three STIX bundle JSON files in the order enterprise, mobile, ics.
    A missing or unreadable file is silently skipped.  If the same technique
    id appears in more than one file, the first file read wins.
    """
    domains: dict[str, str] = {}
    file_specs: list[tuple[str, str]] = [
        ("enterprise", "enterprise-attack.json"),
        ("mobile", "mobile-attack.json"),
        ("ics", "ics-attack.json"),
    ]
    valid_sources = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}

    for domain, filename in file_specs:
        path = data_dir / filename
        try:
            with open(path, "r", encoding="utf-8") as fh:
                bundle: dict[str, Any] = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue

        objects = bundle.get("objects", [])
        if not isinstance(objects, list):
            continue

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "attack-pattern":
                continue
            refs = obj.get("external_references", [])
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                if ref.get("source_name") not in valid_sources:
                    continue
                ext_id = ref.get("external_id")
                if not ext_id:
                    continue
                tech_id = str(ext_id).upper()
                if tech_id not in domains:
                    domains[tech_id] = domain

    return domains


def _report_rows(
    conn: sqlite3.Connection, job_id: str
) -> list[dict[str, Any]]:
    """Delegate to job_observable_rows."""
    return job_observable_rows(conn, job_id)


def _technique_selection(
    conn: sqlite3.Connection, technique_ids: list[str]
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Reproduce the technique-based rule selection from coverage.py.

    The query set is the union of the report's technique ids and their parent
    technique ids (when a parent exists).  A single call to
    canonical_rule_ids_for_techniques is used.

    Returns (rules_by_tag, tags_by_rule).
    """
    query_set: set[str] = set(technique_ids)
    for tid in technique_ids:
        parent = _parent_technique(tid)
        if parent is not None:
            query_set.add(parent)

    rules_by_tag: dict[str, set[str]] = {tag: set() for tag in query_set}
    tags_by_rule: dict[str, set[str]] = {}

    if not query_set:
        return rules_by_tag, tags_by_rule

    pairs = canonical_rule_ids_for_techniques(conn, list(query_set))
    for tech_id, rule_id in pairs:
        rules_by_tag.setdefault(tech_id, set()).add(rule_id)
        tags_by_rule.setdefault(rule_id, set()).add(tech_id)

    return rules_by_tag, tags_by_rule


def _observable_selection(
    conn: sqlite3.Connection, observables: list[Any]
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Evidence-backed rule selection.

    Builds a value -> list[Observable] index for observables whose obs_class
    is in MATCHABLE, calls atom_hits once, and keeps only hits whose
    atom_class is in MATCHABLE[obs_class] for at least one observable carrying
    that value.

    Returns (rules_by_display, displays_by_rule).
    """
    # Index: value -> list of Observables (only matchable classes)
    value_to_obs: dict[str, list[Any]] = {}
    for obs in observables:
        obs_class = obs.obs_class
        if obs_class not in MATCHABLE:
            continue
        value_to_obs.setdefault(obs.value, []).append(obs)

    rules_by_display: dict[str, set[str]] = {}
    displays_by_rule: dict[str, set[str]] = {}

    if not value_to_obs:
        return rules_by_display, displays_by_rule

    all_values = list(value_to_obs.keys())
    hits = atom_hits(conn, all_values)

    for rule_id, atom_class, value in hits:
        obs_list = value_to_obs.get(value)
        if not obs_list:
            continue
        # Check if atom_class is matchable for at least one obs with this value
        matched = False
        for obs in obs_list:
            if atom_class in MATCHABLE[obs.obs_class]:
                matched = True
                break
        if not matched:
            continue
        for obs in obs_list:
            if atom_class in MATCHABLE[obs.obs_class]:
                display = obs.display
                rules_by_display.setdefault(display, set()).add(rule_id)
                displays_by_rule.setdefault(rule_id, set()).add(display)

    return rules_by_display, displays_by_rule


def _measure_job(
    conn: sqlite3.Connection,
    job_id: str,
    filename: str,
    domains: dict[str, str],
) -> dict[str, Any]:
    """Compute all measurements for a single job.  Returns a dict; prints nothing."""
    m: dict[str, Any] = {
        "job_id": job_id,
        "filename": filename,
        "failed": False,
        "error": None,
    }

    # --- A. Report profile ---
    technique_ids = job_technique_ids(conn, job_id)
    entity_rows = _report_rows(conn, job_id)
    observables = observables_from_entities(entity_rows)

    obs_class_counts: Counter[str] = Counter()
    for obs in observables:
        obs_class_counts[obs.obs_class] += 1

    non_matchable_classes: dict[str, int] = {}
    for cls, cnt in obs_class_counts.items():
        if cls not in MATCHABLE:
            non_matchable_classes[cls] = cnt

    domain_counts: Counter[str] = Counter()
    non_enterprise_ids: list[str] = []
    for tid in technique_ids:
        dom = domains.get(tid, "unknown")
        domain_counts[dom] += 1
        if dom != "enterprise":
            non_enterprise_ids.append(tid)

    m["technique_count"] = len(technique_ids)
    m["observable_count"] = len(observables)
    m["obs_class_counts"] = dict(obs_class_counts)
    m["non_matchable_classes"] = non_matchable_classes
    m["domain_counts"] = dict(domain_counts)
    m["non_enterprise_ids"] = non_enterprise_ids
    m["domains_empty"] = len(domains) == 0

    # --- B. Technique-driven selection ---
    rules_by_tag, tags_by_rule = _technique_selection(conn, technique_ids)
    all_technique_rules: set[str] = set()
    for tag in rules_by_tag:
        all_technique_rules |= rules_by_tag[tag]

    canon_count = canonical_rule_count(conn)
    tech_pct = (
        (len(all_technique_rules) / canon_count * 100.0) if canon_count > 0 else 0.0
    )

    tag_rule_counts: list[tuple[str, int]] = [
        (tag, len(rules)) for tag, rules in rules_by_tag.items()
    ]
    tag_rule_counts.sort(key=lambda x: (-x[1], x[0]))
    top10_tags = tag_rule_counts[:10]

    m["query_tag_count"] = len(rules_by_tag)
    m["technique_rule_count"] = len(all_technique_rules)
    m["canonical_rule_count"] = canon_count
    m["technique_pct"] = tech_pct
    m["top10_tags"] = top10_tags
    m["rules_by_tag"] = rules_by_tag
    m["tags_by_rule"] = tags_by_rule

    # --- C. Observable-driven selection ---
    rules_by_display, displays_by_rule = _observable_selection(conn, observables)
    all_obs_rules: set[str] = set()
    for disp in rules_by_display:
        all_obs_rules |= rules_by_display[disp]

    # Per obs_class rule count: collect each observable's rules, then aggregate
    # by class. Aggregating by display first would undercount a class whose
    # observables reach overlapping rule sets.
    obs_class_rule_counts: dict[str, int] = {}
    obs_class_rules: dict[str, set[str]] = {}
    for obs in observables:
        if obs.obs_class not in MATCHABLE:
            continue
        disp = obs.display
        if disp in rules_by_display:
            obs_class_rules.setdefault(obs.obs_class, set()).update(
                rules_by_display[disp]
            )
    for cls in obs_class_rules:
        obs_class_rule_counts[cls] = len(obs_class_rules[cls])

    # Top 10 observables by rule count
    obs_rule_list: list[tuple[str, str, int]] = []
    for obs in observables:
        disp = obs.display
        if disp in rules_by_display:
            obs_rule_list.append((disp, obs.obs_class, len(rules_by_display[disp])))
    obs_rule_list.sort(key=lambda x: (-x[2], x[0]))
    top10_obs = obs_rule_list[:10]

    m["obs_rule_count"] = len(all_obs_rules)
    m["obs_class_rule_counts"] = obs_class_rule_counts
    m["top10_obs"] = top10_obs
    m["rules_by_display"] = rules_by_display
    m["displays_by_rule"] = displays_by_rule

    # --- D. Overlap ---
    tech_rules = all_technique_rules
    obs_rules = all_obs_rules
    ratio = (
        (len(tech_rules - obs_rules) / len(tech_rules) * 100.0) if tech_rules else 0.0
    )

    m["T_size"] = len(tech_rules)
    m["O_size"] = len(obs_rules)
    m["T_inter_O"] = len(tech_rules & obs_rules)
    m["O_minus_T"] = len(obs_rules - tech_rules)
    m["T_minus_O"] = len(tech_rules - obs_rules)
    m["ratio"] = ratio

    # --- E. Score audit ---
    # Timed here rather than re-run in section F: compute_for_job is the
    # expensive call being measured, and calling it twice doubles the runtime
    # of the whole harness for no extra information.
    t_compute = time.perf_counter()
    try:
        coverage_result = compute_for_job(conn, job_id)
    except Exception as exc:
        m["latency_compute"] = time.perf_counter() - t_compute
        m["failed"] = True
        m["error"] = f"compute_for_job: {type(exc).__name__}: {exc}"
        m["score_audit_error"] = f"{type(exc).__name__}: {exc}"
        m["cells_score_ge2_no_evidence"] = 0
        m["cells_score_ge2_with_evidence"] = 0
        m["top10_cells"] = []
        m["by_score"] = {}
        m["latency_rank"] = 0.0
        m["rank_counts"] = {}
        m["rank_candidate_total"] = 0
        return m

    m["latency_compute"] = time.perf_counter() - t_compute
    cells = coverage_result.get("cells", [])
    by_score = coverage_result.get("by_score", {})

    cells_ge2 = [c for c in cells if c.get("score", 0) >= 2]
    no_evidence_count = 0
    with_evidence_count = 0
    cell_details: list[dict[str, Any]] = []

    for cell in cells_ge2:
        tech_id = cell.get("technique_id", "")
        # Determine the tag set for this cell: the technique itself and its parent
        tag_set: set[str] = {tech_id}
        parent = _parent_technique(tech_id)
        if parent is not None:
            tag_set.add(parent)

        # Collect rules for this cell from rules_by_tag
        cell_rules: set[str] = set()
        for tag in tag_set:
            if tag in rules_by_tag:
                cell_rules |= rules_by_tag[tag]

        evidence_rules = cell_rules & obs_rules
        if len(evidence_rules) == 0:
            no_evidence_count += 1
        else:
            with_evidence_count += 1

        cell_details.append({
            "technique_id": tech_id,
            "score": cell.get("score", 0),
            "rule_count": cell.get("rule_count", 0),
            "evidence_rules": len(evidence_rules),
        })

    # Sort: score descending, then rule_count descending
    cell_details.sort(key=lambda x: (-x["score"], -x["rule_count"]))
    top10_cells = cell_details[:10]

    m["cells_score_ge2_no_evidence"] = no_evidence_count
    m["cells_score_ge2_with_evidence"] = with_evidence_count
    m["top10_cells"] = top10_cells
    m["by_score"] = by_score

    # --- F. Latency ---
    t0 = time.perf_counter()
    try:
        rank_result = rank_rules(
            conn, entity_rows, technique_ids, limit=200
        )
    except Exception as exc:
        m["latency_rank"] = time.perf_counter() - t0
        m["rank_error"] = f"{type(exc).__name__}: {exc}"
        m["rank_counts"] = {}
        m["rank_candidate_total"] = 0
    else:
        m["latency_rank"] = time.perf_counter() - t0
        m["rank_counts"] = rank_result.get("counts", {})
        m["rank_candidate_total"] = rank_result.get("candidate_total", 0)

    return m


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

def _print_job(m: dict[str, Any]) -> None:
    """Print the measurement for a single job."""
    print(f"Job: {m['job_id']}  ({m['filename']})")
    print("=" * 72)

    # A. Report profile
    print("A. REPORT PROFILE")
    print(f"  Techniques: {m['technique_count']}")
    print(f"  Observables: {m['observable_count']}")
    print("  Observables by class:")
    for cls, cnt in sorted(
        m["obs_class_counts"].items(), key=lambda x: (-x[1], x[0])
    ):
        print(f"    {cls}: {cnt}")
    if m["non_matchable_classes"]:
        print("  Non-matchable observable classes:")
        for cls, cnt in sorted(
            m["non_matchable_classes"].items(), key=lambda x: (-x[1], x[0])
        ):
            print(f"    {cls}: {cnt}")
    else:
        print("  Non-matchable observable classes: (none)")

    if m["domains_empty"]:
        print("  ATT&CK domain: all techniques unknown (no bundle readable)")
    else:
        print("  ATT&CK domain distribution:")
        for dom, cnt in sorted(
            m["domain_counts"].items(), key=lambda x: (-x[1], x[0])
        ):
            print(f"    {dom}: {cnt}")
        if m["non_enterprise_ids"]:
            print(f"  Non-enterprise technique ids ({len(m['non_enterprise_ids'])}):")
            for tid in sorted(m["non_enterprise_ids"]):
                print(f"    {tid}")
        else:
            print("  Non-enterprise technique ids: (none)")

    # B. Technique-driven selection
    print("B. TECHNIQUE-DRIVEN SELECTION")
    print(f"  Query tags (techniques + parents): {m['query_tag_count']}")
    print(f"  Distinct rules selected: {m['technique_rule_count']}")
    print(
        f"  Share of canonical rules: {m['technique_pct']:.1f}%"
        f"  (canonical total: {m['canonical_rule_count']})"
    )
    print("  Top 10 tags by rule count:")
    for tag, cnt in m["top10_tags"]:
        print(f"    {tag:<10s} {cnt} rules")

    # C. Observable-driven selection
    print("C. OBSERVABLE-DRIVEN SELECTION")
    print(f"  Distinct rules reached: {m['obs_rule_count']}")
    print("  Rules reached by obs_class:")
    for cls, cnt in sorted(
        m["obs_class_rule_counts"].items(), key=lambda x: (-x[1], x[0])
    ):
        print(f"    {cls}: {cnt}")
    print("  Top 10 observables by rules reached:")
    for disp, cls, cnt in m["top10_obs"]:
        print(f"    {disp}  [{cls}]  {cnt} rules")

    # D. Overlap
    print("D. OVERLAP")
    print(f"  |T| = {m['T_size']}")
    print(f"  |O| = {m['O_size']}")
    print(f"  |T and O| = {m['T_inter_O']}")
    print(f"  |O \\ T| = {m['O_minus_T']}  (evidence-backed, missed by technique)")
    print(f"  |T \\ O| = {m['T_minus_O']}  (technique-only, no evidence)")
    print(f"  Ratio |T \\ O| / |T| = {m['ratio']:.1f}%")

    # E. Score audit
    print("E. SCORE AUDIT")
    if m.get("score_audit_error"):
        print(f"  ERROR: {m['score_audit_error']}")
    else:
        print(
            f"  Cells score >= 2, no evidence: {m['cells_score_ge2_no_evidence']}"
        )
        print(
            f"  Cells score >= 2, with evidence: {m['cells_score_ge2_with_evidence']}"
        )
        print("  Top 10 cells by score:")
        print(f"    {'technique_id':<12s} {'score':>5s} {'rule_count':>10s} {'evidence_rules':>14s}")
        for c in m["top10_cells"]:
            print(
                f"    {c['technique_id']:<12s} {c['score']:>5d} "
                f"{c['rule_count']:>10d} {c['evidence_rules']:>14d}"
            )
        print("  Score distribution:")
        for score in sorted(m["by_score"].keys()):
            print(f"    score {score}: {m['by_score'][score]}")

    # F. Latency
    print("F. LATENCY")
    print(f"  compute_for_job: {m['latency_compute']:.3f}s")
    if m.get("rank_error"):
        print(f"  rank_rules: ERROR: {m['rank_error']}")
    else:
        print(f"  rank_rules: {m['latency_rank']:.3f}s")
        counts = m["rank_counts"]
        print(
            f"    counts: direct={counts.get('direct', 0)}, "
            f"behavioural={counts.get('behavioural', 0)}, "
            f"weak={counts.get('weak', 0)}"
        )
        print(f"    candidate_total: {m['rank_candidate_total']}")

    print()


def _print_global(measures: list[dict[str, Any]]) -> None:
    """Print the aggregated D and E sections across all jobs."""
    print("GLOBAL AGGREGATE")
    print("=" * 72)

    sum_T = sum(m["T_size"] for m in measures)
    sum_O = sum(m["O_size"] for m in measures)
    sum_T_inter_O = sum(m["T_inter_O"] for m in measures)
    sum_O_minus_T = sum(m["O_minus_T"] for m in measures)
    sum_T_minus_O = sum(m["T_minus_O"] for m in measures)
    global_ratio = (
        (sum_T_minus_O / sum_T * 100.0) if sum_T > 0 else 0.0
    )

    total_no_evidence = sum(
        m.get("cells_score_ge2_no_evidence", 0) for m in measures
    )
    total_with_evidence = sum(
        m.get("cells_score_ge2_with_evidence", 0) for m in measures
    )

    print(f"  Sum |T| = {sum_T}")
    print(f"  Sum |O| = {sum_O}")
    print(f"  Sum |T and O| = {sum_T_inter_O}")
    print(f"  Sum |O \\ T| = {sum_O_minus_T}")
    print(f"  Sum |T \\ O| = {sum_T_minus_O}")
    print(f"  Global ratio |T \\ O| / |T| = {global_ratio:.1f}%")
    print(f"  Total cells score >= 2, no evidence: {total_no_evidence}")
    print(f"  Total cells score >= 2, with evidence: {total_with_evidence}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Measure TTP coverage vs observable-backed coverage."
    )
    parser.add_argument(
        "--db",
        default="cti_stix.db",
        help="Path to the SQLite database (default: cti_stix.db)",
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Directory containing ATT&CK STIX bundles (default: data)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    data_dir = Path(args.data_dir)

    # Load ATT&CK domains
    domains = _load_attack_domains(data_dir)

    # Open database in read-only mode
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT id, original_filename, status FROM jobs ORDER BY created_at"
        ).fetchall()
    except sqlite3.Error as exc:
        print(f"ERROR: cannot read jobs table: {exc}")
        conn.close()
        return 1

    if not rows:
        print("No jobs found in the database.")
        conn.close()
        return 1

    measures: list[dict[str, Any]] = []
    failed_count = 0

    for row in rows:
        job_id = row["id"]
        filename = row["original_filename"] or "(unknown)"
        try:
            m = _measure_job(conn, job_id, filename, domains)
        except Exception as exc:
            failed_count += 1
            print(f"Job: {job_id}  ({filename})")
            print(f"  ERROR: {type(exc).__name__}: {exc}")
            print()
            continue

        if m.get("failed"):
            failed_count += 1

        measures.append(m)
        _print_job(m)

    conn.close()

    if measures:
        _print_global(measures)

    if failed_count == len(rows):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
