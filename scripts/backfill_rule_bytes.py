#!/usr/bin/env python3
"""Backfill the `rule_bytes` side table on an already-built store (ADR-0022, ADR-0053).

The coverage selection UI shows live archive sizes. Deriving them with
LENGTH(raw) forces a walk of the rule bodies' overflow storage on every pass;
storing the count as a column on `detection_rules` was no better since a
column added after `raw` still has to be read past it. Held in its own table,
keyed by rule id, the same read is fast.

Rules ingested from now on get their row written by `replace_corpus_rules`;
this script fills in a store that was built before the table existed, so no
corpus re-clone is needed (the same approach as ADR-0014's rule_atoms).

Usage:
    .venv/bin/python -m scripts.backfill_rule_bytes
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.db import DB_ERRORS, get_rule_conn, init_db


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill the rule_bytes side table."
    )
    parser.add_argument(
        "--batch",
        type=int,
        default=5000,
        help="Number of rows to update per transaction (default: 5000)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Recalculate every row, not just the missing ones",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write, only count and display",
    )
    args = parser.parse_args()

    try:
        init_db()
        conn = get_rule_conn()

        total = conn.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
        if args.force:
            todo = total
        else:
            todo = conn.execute(
                "SELECT COUNT(*) FROM detection_rules d "
                "WHERE NOT EXISTS (SELECT 1 FROM rule_bytes b WHERE b.rule_id = d.id)"
            ).fetchone()[0]

        print(f"total rows: {total}")
        print(f"to backfill: {todo}")

        if todo == 0:
            print("nothing to backfill")
            return 0

        if args.dry_run:
            return 0

        start = time.perf_counter()
        done = 0
        last_id = ""

        while True:
            if args.force:
                where = "1=1 AND d.id > ?"
                params = [last_id, args.batch]
            else:
                where = ("NOT EXISTS "
                         "(SELECT 1 FROM rule_bytes b WHERE b.rule_id = d.id)")
                params = [args.batch]

            sql = (
                "SELECT d.id, LENGTH(COALESCE(d.raw, '')) FROM detection_rules d "
                f"WHERE {where} ORDER BY d.id LIMIT ?"
            )
            rows = conn.execute(sql, params).fetchall()
            if not rows:
                break

            conn.executemany(
                "INSERT INTO rule_bytes (rule_id, bytes) VALUES (?, ?) "
                "ON CONFLICT (rule_id) DO UPDATE SET bytes = EXCLUDED.bytes",
                [(i, n) for i, n in rows],
            )
            conn.commit()

            done += len(rows)
            if args.force:
                last_id = rows[-1][0]

            print(f"  {done}/{todo} rows ({done * 100 // todo}%)")

        elapsed = time.perf_counter() - start
        print(f"elapsed: {elapsed:.2f}s")

        remaining = conn.execute(
            "SELECT COUNT(*) FROM detection_rules d "
            "WHERE NOT EXISTS (SELECT 1 FROM rule_bytes b WHERE b.rule_id = d.id)"
        ).fetchone()[0]
        if remaining == 0:
            print("PASS")
        else:
            print(f"FAIL: {remaining} rows still missing")
            return 1

        total_bytes = conn.execute(
            "SELECT SUM(bytes) FROM rule_bytes"
        ).fetchone()[0] or 0
        print(f"total body bytes: {total_bytes / (1024 * 1024):.1f} MB")

        return 0

    except DB_ERRORS as e:
        print(f"Database error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
