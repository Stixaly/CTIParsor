from __future__ import annotations

import argparse
import collections
import sqlite3
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.detection.atoms import extract_atoms  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Measure before/after atom counts on the real Sigma store (read-only)."""
    parser = argparse.ArgumentParser(description="Measure negated-atom removal.")
    parser.add_argument("db", nargs="?", default="cti_stix.db")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--examples", type=int, default=15)
    args = parser.parse_args(argv)

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    cur = conn.cursor()
    sql = "SELECT id, raw FROM detection_rules WHERE format='sigma'"
    params: list[object] = []
    if args.limit > 0:
        sql += " LIMIT ?"
        params.append(args.limit)
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()

    rules_parsed = 0
    unparseable = 0
    rules_changed = 0
    atoms_before_total = 0
    atoms_after_total = 0
    removed_values: collections.Counter[str] = collections.Counter()
    removed_classes: collections.Counter[str] = collections.Counter()

    for _rule_id, raw in rows:
        try:
            doc = yaml.safe_load(raw)
        except Exception:
            unparseable += 1
            continue
        if not isinstance(doc, dict):
            unparseable += 1
            continue
        detection = doc.get("detection")
        if not isinstance(detection, dict):
            unparseable += 1
            continue

        rules_parsed += 1

        after = set(extract_atoms(doc, max_atoms=10000))

        # Reproduce the OLD behaviour: strip the `condition` key so that
        # _negated_selections returns an empty set and the walk is unchanged.
        doc_old = dict(doc)
        detection_old = dict(detection)
        detection_old.pop("condition", None)
        doc_old["detection"] = detection_old
        before = set(extract_atoms(doc_old, max_atoms=10000))

        atoms_before_total += len(before)
        atoms_after_total += len(after)

        if before != after:
            rules_changed += 1
            removed = before - after
            for cls, val in removed:
                removed_values[val] += 1
                removed_classes[cls] += 1

    pct_changed = (rules_changed / rules_parsed * 100) if rules_parsed else 0.0
    removed_count = atoms_before_total - atoms_after_total
    pct_removed = (removed_count / atoms_before_total * 100) if atoms_before_total else 0.0

    print(f"rules parsed        : {rules_parsed}   (unparseable: {unparseable})")
    print(f"rules changed       : {rules_changed}  ({pct_changed:.1f}%)")
    print(f"atoms before        : {atoms_before_total}")
    print(f"atoms after         : {atoms_after_total}   (-{removed_count}, -{pct_removed:.1f}%)")

    print("top removed values:")
    for val, count in removed_values.most_common(args.examples):
        display = val if len(val) <= 70 else val[:67] + "..."
        print(f"  {count:6d}  {display}")

    print("removed by class:")
    for cls, count in sorted(removed_classes.items(), key=lambda x: x[1], reverse=True):
        print(f"  {count:6d}  {cls}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
