"""Build the rule_text search index over each canonical rule's title and
description (ADR-0031, ADR-0053).

A brand token is looked up here in 0.4ms; the same lookup as a scan of
`detection_rules` measured 4.1s, and two such sweeps cost 12.8s on one report
against a panel that answers in 2.9s. Rebuild whenever the rule corpora change —
a stale index under-reports, and every hit is re-checked against the live row.

Since #363 the rule-store rebuild (scripts/build_detection_index.py and the
Settings page) rebuilds this index too, so running this script by hand is only
needed to refresh it without re-reading the corpora. The work is done by
pipeline.detection.brands.rebuild_rule_text.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.db import DB_ERRORS, get_rule_conn, init_db
from pipeline.detection.brands import rebuild_rule_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the rule_text search index.")
    parser.add_argument("--batch", type=int, default=2000)
    args = parser.parse_args()

    init_db()
    conn = get_rule_conn()

    cur = conn.execute("SELECT COUNT(*) FROM detection_rules WHERE is_canonical=1")
    total = cur.fetchone()[0]
    if total == 0:
        print("[rule-text] the rule store is empty — run scripts/build_detection_index.py first.")
        return 0

    try:
        conn.execute("BEGIN")
    except DB_ERRORS as exc:
        print(f"[rule-text] cannot start the rebuild: {exc}")
        return 1

    print(f"[rule-text] indexing {total} canonical rules…")
    print("─" * 50)

    start = time.perf_counter()
    try:
        result = rebuild_rule_text(conn, batch=args.batch)
    except DB_ERRORS as exc:
        conn.rollback()
        print(f"[rule-text] the rebuild failed, the index is unchanged: {exc}")
        return 1
    conn.commit()
    elapsed = time.perf_counter() - start

    print(f"  rules scanned         {total}")
    print(f"  rows written          {result['rows']}")
    print(f"  empty bodies            {result['empty_bodies']}")
    print(f"  elapsed                 {elapsed:.1f}s")
    print("[rule-text] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
