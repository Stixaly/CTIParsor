"""Build the FTS5 index over each canonical rule's title and description (ADR-0031).

A brand token is looked up here in 0.4ms; the same lookup as a scan of
`detection_rules` measured 4.1s, and two such sweeps cost 12.8s on one report
against a panel that answers in 2.9s. Rebuild whenever the rule corpora change —
a stale index under-reports, and every hit is re-checked against the live row.
"""
import argparse
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.db import get_conn, init_db


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the rule_text FTS5 index.")
    parser.add_argument("--batch", type=int, default=2000)
    args = parser.parse_args()

    init_db()
    conn = get_conn()

    cur = conn.execute("SELECT COUNT(*) FROM detection_rules WHERE is_canonical=1")
    total = cur.fetchone()[0]
    if total == 0:
        print("[rule-text] the rule store is empty — run scripts/build_detection_index.py first.")
        return 0

    # ONE transaction for the whole rebuild. `get_conn()` is in autocommit, so
    # without this each batch commits separately and appends to the WAL — and
    # while the API server holds readers, SQLite can never auto-checkpoint, so
    # the WAL simply grows. Measured on the live store: 2.3 GB of WAL for a
    # 30 MB index before the run was killed.
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM rule_text")
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc) or "fts5" in str(exc).lower():
            print("[rule-text] FTS5 is not available in this SQLite build.")
            return 1
        print(f"[rule-text] cannot start the rebuild: {exc}")
        print("[rule-text] stop the API server and retry — it holds the write lock.")
        return 1

    print(f"[rule-text] indexing {total} canonical rules…")
    print("─" * 50)

    start = time.perf_counter()
    rows_written = 0
    empty_bodies = 0
    batch: list[tuple[str, str]] = []

    cur = conn.execute(
        "SELECT id, COALESCE(title,''), COALESCE(description,'') "
        "FROM detection_rules WHERE is_canonical=1"
    )
    for rule_id, title, description in cur:
        body = f"{title} {description}".strip().lower()
        if not body:
            empty_bodies += 1
            continue
        batch.append((rule_id, body))
        if len(batch) >= args.batch:
            conn.executemany("INSERT INTO rule_text (rule_id, body) VALUES (?,?)", batch)
            rows_written += len(batch)
            batch = []

    if batch:
        conn.executemany("INSERT INTO rule_text (rule_id, body) VALUES (?,?)", batch)
        rows_written += len(batch)

    conn.commit()
    # Fold the WAL back into the database file. Without it the 30 MB index
    # leaves a WAL of comparable size sitting next to it until some later
    # writer happens to checkpoint.
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.OperationalError:
        pass          # a reader is holding the WAL open; harmless, just larger
    elapsed = time.perf_counter() - start

    print(f"  rules scanned         {total}")
    print(f"  rows written          {rows_written}")
    print(f"  empty bodies            {empty_bodies}")
    print(f"  elapsed                 {elapsed:.1f}s")
    print("[rule-text] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
