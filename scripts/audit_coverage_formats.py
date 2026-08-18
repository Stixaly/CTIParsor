#!/usr/bin/env python3
"""Read-only audit of the per-format coverage breakdown (ADR-0022).

Runs `compute_for_job` and `rules_for_technique` against the real store, prints
the per-format split, checks the invariants the frontend relies on, and times the
drill-down path that the coverage page selects over.

Usage:
    .venv/bin/python -m scripts.audit_coverage_formats --job <job_id>
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from collections import Counter

from pipeline.detection.coverage import (
    DETECTION_FORMATS,
    compute_for_job,
    job_technique_ids,
)
from pipeline.detection.store import rules_for_technique


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit the per-format coverage breakdown.")
    parser.add_argument("--db", default="cti_stix.db")
    parser.add_argument("--job", required=True)
    parser.add_argument("--technique", action="append", default=None,
                        help="Time these technique ids instead of the job's first 5.")
    args = parser.parse_args()

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    job_row = conn.execute(
        "SELECT original_filename FROM jobs WHERE id = ?", (args.job,)
    ).fetchone()
    if job_row is None:
        print(f"ERROR: job '{args.job}' not found in {args.db}", file=sys.stderr)
        conn.close()
        return 2

    tech_ids = job_technique_ids(conn, args.job)

    print("== JOB ==")
    print(f"job_id: {args.job}")
    print(f"original_filename: {job_row['original_filename']}")
    print(f"techniques: {len(tech_ids)}")

    print("\n== COMPUTE ==")
    t0 = time.perf_counter()
    result = compute_for_job(conn, args.job)
    elapsed = time.perf_counter() - t0
    print(f"elapsed: {elapsed:.2f}s")
    print(f"techniques_total: {result['techniques_total']}")
    print(f"by_score: {result['by_score']}")

    print("\n== PER-FORMAT BREAKDOWN ==")
    cells = sorted(result["cells"], key=lambda c: -c["rule_count"])
    header = f"{'technique_id':<14} {'score':>5} {'rule_count':>10}"
    for fmt in DETECTION_FORMATS:
        header += f" {fmt:>12}"
    print(header)
    print("-" * len(header))

    for cell in cells[:15]:
        line = f"{cell['technique_id']:<14} {cell['score']:>5} {cell['rule_count']:>10}"
        for fmt in DETECTION_FORMATS:
            bf = cell["by_format"].get(fmt, {"rule_count": 0, "corpora": []})
            cellstr = f"{bf['rule_count']}/{len(bf['corpora'])}"
            line += f" {cellstr:>12}"
        print(line)

    # Totals span EVERY cell, not just the 15 displayed — a total that silently
    # covered only the printed rows would understate the export volume.
    totals = {
        fmt: sum(c["by_format"].get(fmt, {}).get("rule_count", 0) for c in result["cells"])
        for fmt in DETECTION_FORMATS
    }
    total_line = f"{'TOTAL (all)':<14} {'':>5} {sum(totals.values()):>10}"
    for fmt in DETECTION_FORMATS:
        total_line += f" {totals[fmt]:>12}"
    print(total_line)

    print("\n== INVARIANTS ==")
    all_pass = True
    for cell in result["cells"]:
        bf = cell["by_format"]
        if set(bf.keys()) != set(DETECTION_FORMATS):
            print(f"FAIL: {cell['technique_id']} by_format keys mismatch")
            all_pass = False
            continue
        if sum(bf[f]["rule_count"] for f in DETECTION_FORMATS) != cell["rule_count"]:
            print(f"FAIL: {cell['technique_id']} rule_count sum mismatch")
            all_pass = False
            continue
        for fmt in DETECTION_FORMATS:
            if len(bf[fmt]["corpora"]) > bf[fmt]["rule_count"]:
                print(f"FAIL: {cell['technique_id']} {fmt} corpora > rule_count")
                all_pass = False
                break
        union_corpora: set[str] = set()
        for fmt in DETECTION_FORMATS:
            union_corpora.update(bf[fmt]["corpora"])
        if union_corpora != set(cell["corpora"]):
            print(f"FAIL: {cell['technique_id']} corpora union mismatch")
            all_pass = False
    if all_pass:
        print("PASS")

    print("\n== DRILL-DOWN LATENCY ==")
    selected = args.technique if args.technique else tech_ids[:5]
    total_elapsed = 0.0
    all_rules: list[dict] = []
    for tech in selected:
        t0 = time.perf_counter()
        rules = rules_for_technique(conn, tech)
        elapsed = time.perf_counter() - t0
        total_elapsed += elapsed
        counter = Counter(r["format"] for r in rules)
        print(f"{tech:<14} {len(rules):>6} rules  {elapsed:>7.3f}s  formats={dict(counter)}")
        all_rules.extend(rules)
    print(f"{'TOTAL':<14} {len(all_rules):>6} rules  {total_elapsed:>7.3f}s")

    print("\n== ALSO_IN SPOT CHECK ==")
    also_in_rules = [r for r in all_rules if r["also_in"]][:5]
    spot_check_pass = True
    if not also_in_rules:
        print("(none in this sample)")
    else:
        for r in also_in_rules:
            print(f"{r['id']}  corpus={r['corpus']}  also_in={r['also_in']}")
            if r["corpus"] in r["also_in"]:
                print(f"FAIL: {r['id']} corpus in own also_in")
                spot_check_pass = False
        if spot_check_pass:
            print("PASS")

    conn.close()
    return 0 if (all_pass and spot_check_pass) else 1


if __name__ == "__main__":
    raise SystemExit(main())
