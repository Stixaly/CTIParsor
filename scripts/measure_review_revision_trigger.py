#!/usr/bin/env python3
"""What the `review_revision` trigger costs a write, per row or per statement (ADR-0086).

Usage:
    python scripts/measure_review_revision_trigger.py [--url URL] [--rows 5000] [--repeat 5]

Creates a throwaway schema on a disposable PostgreSQL server (default:
CTIPARSOR_TEST_DATABASE_URL), migrates it, and times the same writes under
three triggers: none, v12's row trigger (`bump_review_revision()`, one
`UPDATE jobs` per row written), and a statement trigger with transition
tables (one `UPDATE jobs` per statement, for the jobs it touched).  The
schema is dropped at the end; no other schema is touched, and the migration's
`db-identity.json` goes to a temporary directory, not the state volume.

The writes are the store's own: the run's persistence (`executemany`, which
psycopg sends as one statement per row in one implicit transaction), the same
inside an explicit BEGIN, one UPDATE and one DELETE of every row of a job
(auto-accept, bulk accept, job deletion), and one multi-row INSERT for
comparison.
"""
from __future__ import annotations

import argparse
import os
import statistics
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api import migrate
from api.db import transaction
from api.db_backend import PgConnection

TABLES = ("entities", "relationships")
VARIANTS = ("none", "row", "statement")

_STATEMENT_FUNCTION = """CREATE OR REPLACE FUNCTION measure_bump_per_statement() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        EXECUTE format('UPDATE %I.jobs SET review_revision = review_revision + 1 '
                       'WHERE id IN (SELECT job_id FROM new_rows)', TG_TABLE_SCHEMA);
    ELSIF TG_OP = 'DELETE' THEN
        EXECUTE format('UPDATE %I.jobs SET review_revision = review_revision + 1 '
                       'WHERE id IN (SELECT job_id FROM old_rows)', TG_TABLE_SCHEMA);
    ELSE
        EXECUTE format('UPDATE %I.jobs SET review_revision = review_revision + 1 '
                       'WHERE id IN (SELECT job_id FROM new_rows UNION SELECT job_id FROM old_rows)',
                       TG_TABLE_SCHEMA);
    END IF;
    RETURN NULL;
END
$$"""

_INSERT = ("INSERT INTO entities (id, job_id, value, entity_type, confidence, accepted, source) "
           "VALUES (?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING")


def _use(conn: PgConnection, variant: str) -> None:
    for t in TABLES:
        conn.execute(f"DROP TRIGGER IF EXISTS {t}_review_revision ON {t}")
        for op in ("insert", "update", "delete"):
            conn.execute(f"DROP TRIGGER IF EXISTS {t}_measure_{op} ON {t}")
    if variant == "row":
        for t in TABLES:
            conn.execute(f"CREATE TRIGGER {t}_review_revision AFTER INSERT OR UPDATE OR DELETE ON {t} "
                         "FOR EACH ROW EXECUTE FUNCTION bump_review_revision()")
    elif variant == "statement":
        # A trigger with transition tables takes one event: three per table.
        conn.execute(_STATEMENT_FUNCTION)
        for t in TABLES:
            for op, tables in (("insert", "NEW TABLE AS new_rows"),
                               ("update", "OLD TABLE AS old_rows NEW TABLE AS new_rows"),
                               ("delete", "OLD TABLE AS old_rows")):
                conn.execute(f"CREATE TRIGGER {t}_measure_{op} AFTER {op.upper()} ON {t} "
                             f"REFERENCING {tables} FOR EACH STATEMENT "
                             "EXECUTE FUNCTION measure_bump_per_statement()")


def _job(conn: PgConnection) -> str:
    job_id = uuid.uuid4().hex
    conn.execute("INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
                 "VALUES (?, 'report.txt', 'reviewing', 'now', 'now')", (job_id,))
    return job_id


def _rows(job_id: str, n: int) -> list[tuple]:
    return [(f"{job_id}-{i}", job_id, f"value-{i}", "domain", 0.5, None, "llm") for i in range(n)]


def _revision(conn: PgConnection, job_id: str) -> int:
    return conn.execute("SELECT review_revision FROM jobs WHERE id=?", (job_id,)).fetchone()["review_revision"]


def _timed(fn: Callable[[], object]) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


SCENARIOS = (
    "executemany INSERT (the run's write)",
    "executemany INSERT inside BEGIN",
    "one UPDATE of every row",
    "one DELETE of every row",
    "one multi-row INSERT",
)


def _round(conn: PgConnection, n: int) -> tuple[list[float], list[int]]:
    """One pass of every scenario; the times, and the revision each left."""
    conn.execute("VACUUM jobs")
    conn.execute("VACUUM entities")
    times: list[float] = []
    revisions: list[int] = []

    job = _job(conn)
    rows = _rows(job, n)
    times.append(_timed(lambda: conn.executemany(_INSERT, rows)))
    revisions.append(_revision(conn, job))

    other = _job(conn)
    other_rows = _rows(other, n)

    def inside_begin() -> None:
        with transaction(conn):
            conn.executemany(_INSERT, other_rows)

    times.append(_timed(inside_begin))
    revisions.append(_revision(conn, other))

    before = _revision(conn, job)
    times.append(_timed(lambda: conn.execute("UPDATE entities SET accepted=1 WHERE job_id=?", (job,))))
    revisions.append(_revision(conn, job) - before)
    before = _revision(conn, job)
    times.append(_timed(lambda: conn.execute("DELETE FROM entities WHERE job_id=?", (job,))))
    revisions.append(_revision(conn, job) - before)

    third = _job(conn)
    ids = [f"{third}-{i}" for i in range(n)]
    values = [f"value-{i}" for i in range(n)]
    times.append(_timed(lambda: conn.execute(
        "INSERT INTO entities (id, job_id, value, entity_type, confidence, source) "
        "SELECT i, ?, v, 'domain', 0.5, 'llm' FROM unnest(?::text[], ?::text[]) AS u(i, v)",
        (third, ids, values))))
    revisions.append(_revision(conn, third))

    conn.execute("DELETE FROM entities WHERE job_id = ANY(?)", ([other, third],))
    return times, revisions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.getenv("CTIPARSOR_TEST_DATABASE_URL"),
                        help="a disposable PostgreSQL server (default: CTIPARSOR_TEST_DATABASE_URL)")
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--repeat", type=int, default=5)
    args = parser.parse_args(argv)
    if not args.url:
        parser.error("no --url and no CTIPARSOR_TEST_DATABASE_URL")
    if args.rows < 1 or args.repeat < 1:
        parser.error("--rows and --repeat must be at least 1")

    import psycopg

    schema = "measure_" + uuid.uuid4().hex[:8]
    admin = psycopg.connect(args.url, autocommit=True)
    admin.execute(f'CREATE SCHEMA "{schema}"')
    conn: PgConnection | None = None
    try:
        with tempfile.TemporaryDirectory() as state:
            # The migration records the database it migrated (db_identity): a
            # throwaway schema has no place in the real state file.
            os.environ["CTIPARSOR_STATE_DIR"] = state
            conn = PgConnection(args.url, schema=schema)
            migrate.upgrade(conn)
        times: dict[tuple[str, str], list[float]] = {(v, s): [] for v in VARIANTS for s in SCENARIOS}
        revisions: dict[str, list[int]] = {}
        for _ in range(args.repeat):
            for variant in VARIANTS:          # interleaved, so drift spreads over all three
                _use(conn, variant)
                round_times, revisions[variant] = _round(conn, args.rows)
                for scenario, t in zip(SCENARIOS, round_times, strict=True):
                    times[(variant, scenario)].append(t)
    finally:
        if conn is not None:
            conn.close()
        admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        admin.close()

    print(f"{args.rows} rows, {args.repeat} rounds: median seconds (min-max), revision bumps")
    for scenario_index, scenario in enumerate(SCENARIOS):
        print(f"\n{scenario}")
        for variant in VARIANTS:
            ts = times[(variant, scenario)]
            print(f"  {variant:<10} {statistics.median(ts):7.3f}  ({min(ts):.3f}-{max(ts):.3f})"
                  f"  bumps={revisions[variant][scenario_index]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
