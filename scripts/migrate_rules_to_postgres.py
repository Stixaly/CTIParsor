#!/usr/bin/env python3
"""
Migrate the detection-rule corpus from an existing cti_stix.db into
PostgreSQL (ADR-0053).

This script copies the rule-store tables (detection_rules, rule_bytes,
rule_techniques, rule_atoms, rule_related, rule_text) from a SQLite database
into a PostgreSQL database. It is the sibling of
scripts/migrate_jobs_to_postgres.py (ADR-0045), which covers the job store —
run that one too if this installation has never moved its job store either.

The source SQLite file is opened read-only and is never modified.
`rule_text.body_tsv` is a PostgreSQL GENERATED column (a tsvector derived
from `body`) and is never copied — it recomputes itself from the copied
`body` on insert.

Usage:
    python scripts/migrate_rules_to_postgres.py [--sqlite PATH] [--postgres URL]
                                                 [--dry-run] [--append] [--batch N]

    --sqlite    source cti_stix.db (default: ./cti_stix.db)
    --postgres  target URL (default: $DATABASE_URL); required one way or the other
    --dry-run   do everything inside one transaction, print the counts, then ROLLBACK
    --append    allow a target that already holds rules (rows whose key exists are skipped)
    --batch     rows per executemany (default 500)
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from api.db import _RULE_STORE_DDL_POSTGRES  # noqa: E402
from pipeline.regex_safety import compile_pattern

# api.db no longer knows about SQLite (ADR-0053) -- this is the legacy,
# pre-migration single-file layout's historical location, used only as this
# script's own default source path.
_DEFAULT_SQLITE_PATH = _ROOT / "cti_stix.db"

# FK order: rule_text references detection_rules(id); the others have no
# declared FK but logically depend on a rule existing first.
TABLES: tuple[str, ...] = (
    "detection_rules",
    "rule_bytes",
    "rule_techniques",
    "rule_atoms",
    "rule_related",
    "rule_text",
)

_IDENT_RE = compile_pattern(r"^[a-z_][a-z0-9_]*$")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate the detection-rule corpus from SQLite to PostgreSQL")
    parser.add_argument("--sqlite", type=str, default=None,
                         help="Source cti_stix.db path (default: ./cti_stix.db)")
    parser.add_argument("--postgres", type=str, default=None, help="Target PostgreSQL URL")
    parser.add_argument("--dry-run", action="store_true", help="Rollback after printing counts")
    parser.add_argument("--append", action="store_true", help="Allow appending to existing target")
    parser.add_argument("--batch", type=int, default=500, help="Rows per executemany batch")
    return parser.parse_args(argv)


def open_source(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise SystemExit(f"[migrate] source not found: {path}")
    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def source_tables(src: sqlite3.Connection) -> set[str]:
    cur = src.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in cur.fetchall()}


def source_columns(src: sqlite3.Connection, table: str) -> list[str]:
    if not _IDENT_RE.match(table):
        raise RuntimeError(f"Invalid table name: {table}")
    cur = src.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cur.fetchall()]


def target_columns(pg_cur, table: str) -> list[str]:
    if not _IDENT_RE.match(table):
        raise RuntimeError(f"Invalid table name: {table}")
    cur = pg_cur.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = %s "
        "AND is_generated = 'NEVER' "
        "ORDER BY ordinal_position",
        (table,),
    )
    return [row[0] for row in cur.fetchall()]


def copy_table(src: sqlite3.Connection, pg_cur, table: str, *, batch: int) -> tuple[int, int]:
    src_cols = source_columns(src, table)
    tgt_cols = target_columns(pg_cur, table)
    tgt_set = set(tgt_cols)
    common_cols = [c for c in src_cols if c in tgt_set]

    if not common_cols:
        return (0, 0)

    cols_str = ",".join(common_cols)
    placeholders = ",".join(["%s"] * len(common_cols))
    insert_sql = f"INSERT INTO {table} ({cols_str}) VALUES ({placeholders}) ON CONFLICT DO NOTHING"

    cur = src.execute(f"SELECT {cols_str} FROM {table}")
    source_rows = 0
    inserted_rows = 0
    while True:
        batch_rows = cur.fetchmany(batch)
        if not batch_rows:
            break
        source_rows += len(batch_rows)
        rows = [tuple(r) for r in batch_rows]
        pg_cur.executemany(insert_sql, rows)
        inserted_rows += pg_cur.rowcount
        if source_rows % 10000 < len(batch_rows):
            print(f"[migrate] {table}: {source_rows} rows processed", file=sys.stderr)

    return (source_rows, inserted_rows)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    url = args.postgres or os.getenv("DATABASE_URL")
    if not url:
        print("[migrate] --postgres or DATABASE_URL is required", file=sys.stderr)
        return 2
    if not (url.startswith("postgresql://") or url.startswith("postgres://")):
        print(f"[migrate] not a PostgreSQL URL: {url}", file=sys.stderr)
        return 2

    sqlite_path = Path(args.sqlite) if args.sqlite else _DEFAULT_SQLITE_PATH
    src = open_source(sqlite_path)
    pg = None

    try:
        import psycopg

        pg = psycopg.connect(url, autocommit=False)
        cur = pg.cursor()
        # _RULE_STORE_DDL_POSTGRES is a tuple of individual statements, same
        # reasoning as _JOB_STORE_DDL_POSTGRES in migrate_jobs_to_postgres.py:
        # run each in turn so a duplicate-object race on one doesn't abort the
        # rest. All still land in this one transaction, matching the
        # --dry-run rollback contract below.
        for _ddl_stmt in _RULE_STORE_DDL_POSTGRES:
            cur.execute(_ddl_stmt)

        cur.execute("SELECT COUNT(*) FROM detection_rules")
        existing_rules = cur.fetchone()[0]
        if existing_rules > 0 and not args.append:
            print(
                f"[migrate] target already holds {existing_rules} rules - use --append to add "
                "the missing rows (existing keys are skipped)",
                file=sys.stderr,
            )
            pg.rollback()
            return 1

        src_tables = source_tables(src)
        results: list[tuple[str, int, int]] = []

        for table in TABLES:
            if table not in src_tables:
                print(f"[migrate] {table:<20} absent in source - skipped")
                continue
            source_rows, inserted = copy_table(src, cur, table, batch=args.batch)
            results.append((table, source_rows, inserted))

        print(f"{'table':<20} {'source':>10} {'inserted':>10} {'target':>10}")
        print("-" * 52)
        ok = True
        total_source = 0
        total_inserted = 0
        total_target = 0

        for table, source_rows, inserted in results:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            target_count = cur.fetchone()[0]
            print(f"{table:<20} {source_rows:>10} {inserted:>10} {target_count:>10}")
            total_source += source_rows
            total_inserted += inserted
            total_target += target_count
            if target_count < source_rows:
                ok = False

        print("-" * 52)
        print(f"{'TOTAL':<20} {total_source:>10} {total_inserted:>10} {total_target:>10}")

        if args.dry_run:
            pg.rollback()
            print("[migrate] dry run - rolled back, nothing written")
        else:
            pg.commit()
            print("[migrate] committed")

        if not ok:
            print(
                "[migrate] WARNING: some target counts are below the source - "
                "inspect before deleting the SQLite rule store",
                file=sys.stderr,
            )
            return 1

        return 0

    except Exception:
        if pg is not None:
            try:
                pg.rollback()
            except Exception:
                pass
        raise
    finally:
        if pg is not None:
            try:
                pg.close()
            except Exception:
                pass
        src.close()


if __name__ == "__main__":
    raise SystemExit(main())
