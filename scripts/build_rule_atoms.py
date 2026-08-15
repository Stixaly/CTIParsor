#!/usr/bin/env python3
"""Backfill the detection-atom index from the stored rule bodies (ADR-0014).

`build_detection_index.py` populates `rule_atoms` and `detection_rules.platform`
as it parses corpus clones. This script derives the same data from
`detection_rules.raw`, so a store built before ADR-0014 gains observable-driven
proposals without re-cloning several gigabytes of Sigma repos.

Offline and idempotent — it only reads the local database.

Usage:
    python scripts/build_rule_atoms.py [--batch 500]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.db import get_conn, init_db  # noqa: E402
from pipeline.detection.atoms import extract_atoms, rule_platform  # noqa: E402


def backfill(conn, *, batch: int = 500, progress=print) -> dict:
    """Re-derive atoms + platform for every rule in the store.

    Returns a summary: rules seen, rules yielding atoms, atoms written, and how
    many rules got a platform.
    """
    rules_seen = rules_with_atoms = atoms_written = platformed = unparsed = 0
    atom_rows: list[tuple[str, str, str]] = []
    platform_rows: list[tuple[str, str]] = []

    conn.execute("DELETE FROM rule_atoms")

    cursor = conn.execute("SELECT id, raw FROM detection_rules")
    while True:
        chunk = cursor.fetchmany(batch)
        if not chunk:
            break
        for rule_id, raw in chunk:
            rules_seen += 1
            try:
                doc = yaml.safe_load(raw or "")
            except yaml.YAMLError:
                unparsed += 1
                continue           # a body we can't re-parse simply has no atoms
            atoms = extract_atoms(doc)
            if atoms:
                rules_with_atoms += 1
                atom_rows.extend((rule_id, cls, value) for cls, value in atoms)
            platform = rule_platform(doc)
            if platform:
                platformed += 1
                platform_rows.append((platform, rule_id))

        if len(atom_rows) >= 20_000:
            atoms_written += _flush(conn, atom_rows, platform_rows)
            atom_rows, platform_rows = [], []
            progress(f"[atoms] {rules_seen} rules… {atoms_written} atoms")

    atoms_written += _flush(conn, atom_rows, platform_rows)
    conn.commit()
    return {
        "rules_seen": rules_seen,
        "rules_with_atoms": rules_with_atoms,
        "atoms": atoms_written,
        "with_platform": platformed,
        "unparsed": unparsed,
    }


def _flush(conn, atom_rows: list[tuple[str, str, str]],
           platform_rows: list[tuple[str, str]]) -> int:
    """Write one buffered batch; returns the number of atom rows written."""
    if atom_rows:
        conn.executemany(
            "INSERT OR IGNORE INTO rule_atoms (rule_id, atom_class, value) VALUES (?,?,?)",
            atom_rows,
        )
    if platform_rows:
        conn.executemany("UPDATE detection_rules SET platform=? WHERE id=?", platform_rows)
    conn.commit()
    return len(atom_rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Backfill the detection-atom index from stored rule bodies.")
    ap.add_argument("--batch", type=int, default=500, help="rules read per DB fetch")
    args = ap.parse_args()

    init_db()
    conn = get_conn()

    total = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
    if not total:
        print("[atoms] the rule store is empty — run scripts/build_detection_index.py first.")
        return 0

    print(f"[atoms] re-deriving atoms for {total} rules…")
    s = backfill(conn, batch=args.batch)
    print("─" * 50)
    print(f"  rules scanned      {s['rules_seen']:>8}")
    print(f"  rules with atoms   {s['rules_with_atoms']:>8}")
    print(f"  atoms written      {s['atoms']:>8}")
    print(f"  platform resolved  {s['with_platform']:>8}")
    if s["unparsed"]:
        print(f"  unparsable bodies  {s['unparsed']:>8}")
    print("[atoms] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
