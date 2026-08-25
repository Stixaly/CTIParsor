# pipeline/detection/phases.py
"""
Phase band generation for ADR-0025.

This module produces the two-row phase band that visualizes where an intrusion
sits in the kill chain. The two rows are strictly independent:

1. "report" row: Derived from ATT&CK techniques extracted from the report.
   This represents the TTPs claimed by the adversary (or the analyst).
   It is often "noisy" because reports may include mobile, ICS, or CAPEC
   techniques that do not map to the enterprise matrix.

2. "covered" row: Derived from the ATT&CK tags of detection rules that
   actually matched an artifact in the report.
   This represents the engineering reality of what the detection logic
   covers. It is sourced from rule tags, NOT from the report's TTPs, to
   ensure it reflects the detection capability rather than the report's
   narrative.

The gap between these two rows is the detection roadmap.

Deterministic, offline, no ML models.
"""

from __future__ import annotations

import sqlite3
from functools import lru_cache
from typing import Iterable

from pipeline.detection.store import techniques_for_rules
from pipeline.mitre_db import get_techniques

#: ATT&CK enterprise tactics in kill-chain order -- the column order of the
#: phase band.
#:
#: FIFTEEN columns, not the fourteen the classic matrix has. This index version
#: renamed TA0005 from `defense-evasion` to `stealth` and added TA0112
#: `defense-impairment`. Taking the fourteen-column list from
#: frontend/src/pages/Coverage.tsx sent 148 + 56 enterprise techniques to the
#: off-matrix bucket -- T1027.004, T1036, T1140, T1620 among them, all of which
#: are plainly on the enterprise matrix. That frontend list has the same defect
#: and buckets those techniques as "other".
#:
#: `test_every_enterprise_tactic_in_the_index_has_a_column` locks this against
#: the next ATT&CK version rather than against a hand-copied list.
TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
)

TACTIC_LABEL: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Dev",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Priv Esc",
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command & Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

#: ATT&CK domain of an index entry that counts as "on the enterprise matrix".
#: Anything else -- mobile, ICS, CAPEC, or an id absent from the index -- is
#: reported as off-matrix rather than silently placed in a column.
ENTERPRISE_DOMAIN = "enterprise-attack"


@lru_cache(maxsize=1)
def _technique_index() -> dict[str, dict]:
    """
    Build a single, cached index of technique IDs to their metadata.
    Keys are uppercase technique IDs.
    """
    index: dict[str, dict] = {}
    for entry in get_techniques():
        tid = entry.get("id")
        if not tid or not isinstance(tid, str):
            continue
        index[tid.upper()] = entry
    return index


def _empty_columns() -> dict[str, list]:
    """
    Return a dictionary mapping each tactic in TACTIC_ORDER to an empty list.
    """
    return {tactic: [] for tactic in TACTIC_ORDER}


def technique_domain(technique_id: str) -> str:
    """
    ATT&CK domain of a technique id: the index's `domain`, or "unknown".
    """
    if not technique_id or not isinstance(technique_id, str):
        return "unknown"
    index = _technique_index()
    entry = index.get(technique_id.upper())
    if not entry:
        return "unknown"
    return entry.get("domain", "unknown")


def tactics_for_technique(technique_id: str) -> list[str]:
    """
    Enterprise tactic shortnames of a technique; [] when off-matrix or absent.
    """
    if not technique_id or not isinstance(technique_id, str):
        return []
    index = _technique_index()
    entry = index.get(technique_id.upper())
    if not entry:
        return []

    if entry.get("domain") != ENTERPRISE_DOMAIN:
        return []

    tactics = entry.get("tactics")
    if not isinstance(tactics, list):
        return []

    # Filter to only enterprise tactics and order them according to TACTIC_ORDER
    valid_tactics = [t for t in tactics if t in TACTIC_ORDER]
    # Sort by TACTIC_ORDER index
    order_map = {t: i for i, t in enumerate(TACTIC_ORDER)}
    valid_tactics.sort(key=lambda t: order_map[t])
    return valid_tactics


def report_phases(technique_ids: Iterable[str]) -> dict:
    """
    Row 1 -- where the REPORT says the intrusion sits.
    """
    # Deduplicate and normalize to uppercase, preserving first occurrence order
    seen: set[str] = set()
    unique_ids: list[str] = []
    for tid in technique_ids:
        if not tid or not isinstance(tid, str):
            continue
        upper_tid = tid.upper()
        if upper_tid not in seen:
            seen.add(upper_tid)
            unique_ids.append(upper_tid)

    columns_data = _empty_columns()
    off_matrix: list[dict] = []
    on_matrix_techniques: set[str] = set()

    for tid in unique_ids:
        tactics = tactics_for_technique(tid)
        if tactics:
            on_matrix_techniques.add(tid)
            for tactic in tactics:
                columns_data[tactic].append(tid)
        else:
            # Off-matrix or no tactics
            domain = technique_domain(tid)
            off_matrix.append({
                "technique_id": tid,
                "domain": domain
            })

    # Sort techniques in each column
    for tactic in columns_data:
        columns_data[tactic].sort()

    # Sort off_matrix by technique_id
    off_matrix.sort(key=lambda x: x["technique_id"])

    # Build columns list in TACTIC_ORDER
    columns = []
    for tactic in TACTIC_ORDER:
        columns.append({
            "tactic": tactic,
            "label": TACTIC_LABEL[tactic],
            "techniques": columns_data[tactic]
        })

    return {
        "columns": columns,
        "off_matrix": off_matrix,
        "on_matrix_total": len(on_matrix_techniques),
        "off_matrix_total": len(off_matrix),
    }


def covered_phases(conn: sqlite3.Connection, rule_ids: Iterable[str]) -> dict:
    """
    Row 2 -- where the rules that actually matched an artifact sit.
    """
    # Normalize rule_ids
    unique_rule_ids: list[str] = []
    seen_rules: set[str] = set()
    for rid in rule_ids:
        if not rid or not isinstance(rid, str):
            continue
        if rid not in seen_rules:
            seen_rules.add(rid)
            unique_rule_ids.append(rid)

    if not unique_rule_ids:
        # Return empty structure without querying
        columns = []
        for tactic in TACTIC_ORDER:
            columns.append({
                "tactic": tactic,
                "label": TACTIC_LABEL[tactic],
                "rules": 0,
                "techniques": []
            })
        return {
            "columns": columns,
            "rules_total": 0,
            "rules_placed": 0,
            "rules_untagged": 0,
        }

    # Fetch techniques for rules
    rule_techs = techniques_for_rules(conn, unique_rule_ids)

    # Initialize data structures
    columns_data = _empty_columns()
    rules_in_column: dict[str, set[str]] = {tactic: set() for tactic in TACTIC_ORDER}
    rules_placed: set[str] = set()
    rules_untagged: set[str] = set()

    for rid in unique_rule_ids:
        techs = rule_techs.get(rid, [])
        if not techs:
            rules_untagged.add(rid)
            continue

        placed_in_any = False
        for tid in techs:
            tactics = tactics_for_technique(tid)
            if tactics:
                placed_in_any = True
                for tactic in tactics:
                    columns_data[tactic].append(tid)
                    rules_in_column[tactic].add(rid)

        if placed_in_any:
            rules_placed.add(rid)
        else:
            rules_untagged.add(rid)

    # Build columns list
    columns = []
    for tactic in TACTIC_ORDER:
        techs_in_col = sorted(set(columns_data[tactic]))
        rules_in_col = len(rules_in_column[tactic])
        columns.append({
            "tactic": tactic,
            "label": TACTIC_LABEL[tactic],
            "rules": rules_in_col,
            "techniques": techs_in_col
        })

    return {
        "columns": columns,
        "rules_total": len(unique_rule_ids),
        "rules_placed": len(rules_placed),
        "rules_untagged": len(rules_untagged),
    }


def phase_band(conn: sqlite3.Connection, technique_ids: Iterable[str],
               matched_rule_ids: Iterable[str]) -> dict:
    """
    Both rows plus their gap, ready to serialize (ADR-0025).
    """
    report = report_phases(technique_ids)
    covered = covered_phases(conn, matched_rule_ids)

    # Build gap
    gap = []
    report_cols = {c["tactic"]: c for c in report["columns"]}
    covered_cols = {c["tactic"]: c for c in covered["columns"]}

    for tactic in TACTIC_ORDER:
        r_col = report_cols[tactic]
        c_col = covered_cols[tactic]
        gap.append({
            "tactic": tactic,
            "label": TACTIC_LABEL[tactic],
            "report_techniques": len(r_col["techniques"]),
            "covered_rules": c_col["rules"]
        })

    return {
        "report": report,
        "covered": covered,
        "gap": gap,
    }
