#!/usr/bin/env python3
"""Backfill the `rule_bytes` side table on an already-built store (ADR-0022).

The coverage selection UI shows live archive sizes. Deriving them with
LENGTH(raw) cost 8.78s per pass over one report's 10,372 rules, because SQLite
must read the rule bodies' overflow pages; storing the count as a column on
`detection_rules` was no better (8.19s) since ALTER TABLE appends it *after*
`raw`, so the record still has to be walked past the body. Held in its own
table, keyed by rule id, the same read is ~0.1s.

Rules ingested from now on get their row written by `replace_corpus_rules`;
this script fills in a store that was built before the table existed, so no
corpus re-clone is needed (the same approach as ADR-0014's rule_atoms).

Usage:
    .venv/bin/python -m scripts.backfill_rule_bytes [--db cti_stix.db]
"""

import argparse
import sqlite3
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill the rule_bytes side table."
    )
    parser.add_argument(
        "--db",
        default="cti_stix.db",
        help="Path to the SQLite database (default: cti_stix.db)",
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

    conn = None
    try:
        if args.dry_run:
            conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        else:
            conn = sqlite3.connect(args.db)

        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        if "rule_bytes" not in tables:
            print(
                "Error: table 'rule_bytes' not found. "
                "Start the API once to apply the additive migration in api/db.py.",
                file=sys.stderr,
            )
            return 2

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
                "INSERT OR REPLACE INTO rule_bytes (rule_id, bytes) VALUES (?, ?)",
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

    except sqlite3.Error as e:
        print(f"SQLite error: {e}", file=sys.stderr)
        return 2
    finally:
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
