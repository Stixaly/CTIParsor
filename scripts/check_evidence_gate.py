#!/usr/bin/env python3
import argparse
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.detection.coverage import rules_for_job


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate evidence gate (ADR-0030)")
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
        jobs = []
        for jid in args.job:
            row = conn.execute("SELECT id, created_at FROM jobs WHERE id = ?", (jid,)).fetchone()
            if row:
                jobs.append(row)
    else:
        jobs = conn.execute("SELECT id, created_at FROM jobs ORDER BY created_at DESC").fetchall()

    if not jobs:
        print("no jobs")
        sys.exit(0)

    header = (f"{'report':<34} | {'tagRules':>8} | {'gated':>6} | {'untagged':>8}"
              f" | {'ev2+':>4} | {'msTag':>6} | {'msGated':>7}")
    print(header)
    print("-" * len(header))

    results = []
    for job_id, _created_at in jobs:
        t0 = time.perf_counter()
        res_tag = rules_for_job(conn, job_id, evidence_only=False)
        t1 = time.perf_counter()
        res_gated = rules_for_job(conn, job_id, evidence_only=True)
        t2 = time.perf_counter()

        ms_tag = int((t1 - t0) * 1000)
        ms_gated = int((t2 - t1) * 1000)

        tag_rules = res_tag["rule_total"]
        gated = res_gated["rule_total"]
        untagged = 0
        ev2_plus = 0
        for group in res_gated["techniques"]:
            if group["technique_id"] == "(untagged)":
                untagged = len(group["rules"])
            for rule in group["rules"]:
                if rule["evidence_count"] >= 2:
                    ev2_plus += 1

        report_name = job_id[:34]
        print(f"{report_name:<34} | {tag_rules:>8} | {gated:>6} | {untagged:>8}"
              f" | {ev2_plus:>4} | {ms_tag:>6} | {ms_gated:>7}")
        results.append((gated, job_id, res_gated, tag_rules, ev2_plus, untagged,
                        ms_tag, ms_gated))

    total_tag = sum(r[3] for r in results)
    total_gated = sum(r[0] for r in results)
    total_untagged = sum(r[5] for r in results)
    total_ev2 = sum(r[4] for r in results)
    total_ms_tag = sum(r[6] for r in results)
    total_ms_gated = sum(r[7] for r in results)

    print("-" * len(header))
    print(f"{'TOTAL':<34} | {total_tag:>8} | {total_gated:>6} | {total_untagged:>8}"
          f" | {total_ev2:>4} | {total_ms_tag:>6} | {total_ms_gated:>7}")

    # Top 3 jobs by gated count
    results.sort(key=lambda x: -x[0])
    top3 = results[:3]

    for gated_count, job_id, res, *_rest in top3:
        if gated_count == 0:
            continue
        print(f"\nTop rules for {job_id}:")
        all_rules = []
        for group in res["techniques"]:
            all_rules.extend(group["rules"])
        all_rules.sort(key=lambda r: (-r["evidence_count"], -len(r["matches"]), r["corpus"], r["title"] or ""))

        for rule in all_rules[:10]:
            title = (rule["title"] or "")[:46]
            displays = [e["display"] for e in rule["matches"][:3]]
            disp_str = ", ".join(displays)
            print(f"  {rule['evidence_count']} {rule['format']} {rule['corpus']} {title} :: {disp_str}")

    conn.close()


if __name__ == "__main__":
    main()
