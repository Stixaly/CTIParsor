"""Bring the database to this code's schema version (ADR-0077).

At every start of the API, of a worker and of `bootstrap` (`api.db.init_db`):

1. take a PostgreSQL advisory lock, so two processes never migrate at once —
   the second waits, then finds nothing left to do;
2. read `schema_migrations`, the record of every version this database has;
3. refuse a database whose version is newer than this code knows (an older
   image started after a newer one migrated), and a database where an applied
   migration's checksum no longer matches its file (an applied migration was
   edited);
4. on a database created before this history existed (CTIParsor's tables, no
   record), recognise how far it had got: each migration whose check
   (`is_applied`) sees its changes is recorded as `recognised`;
5. apply every other migration in order, each in one transaction — snapshot
   of the tables it declares, statements, data step, then its own check, then
   the record; a failure rolls the whole version back and stops the start.

    python -m api.migrate status     # where the database is, what is pending
    python -m api.migrate up         # apply what is pending
    python -m api.migrate check      # exit 1 unless the database is at this code's version
"""
from __future__ import annotations

import argparse
import functools
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from api import migrations as history
from api.logging_config import get_logger
from pipeline.env_flags import env_int

logger = get_logger(__name__)

VERSION_TABLE = "schema_migrations"
_VERSION_TABLE_DDL = """CREATE TABLE IF NOT EXISTS schema_migrations (
    version      INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    checksum     TEXT NOT NULL,
    how          TEXT NOT NULL,
    applied_at   TEXT NOT NULL,
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    app_revision TEXT
)"""
# Only CTIParsor creates these: present without a record, they mean a database
# from before ADR-0077 whose version has to be recognised, not assumed empty.
_OWN_TABLES = ("jobs", "detection_rules")
# One lock per schema: the application uses one, every test its own.
_LOCK_KEY = "hashtext('ctiparsor.migrations'), hashtext(current_schema())"


class MigrationError(RuntimeError):
    """The database cannot be brought to this code's version; the process stops."""


class DatabaseNewerThanCode(MigrationError):
    pass


class ChecksumMismatch(MigrationError):
    pass


class VerificationFailed(MigrationError):
    pass


@dataclass
class Report:
    before: int                                       # version found
    after: int                                        # version left
    target: int                                       # this code's version
    applied: list[int] = field(default_factory=list)
    recognised: list[int] = field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@functools.cache
def _revision() -> str | None:
    """The code revision recorded with each version; one `git` call per process."""
    from api.run_config import _resolve_git_rev
    return _resolve_git_rev()


def _records(conn: Any) -> dict[int, Any]:
    if not history.table_exists(conn, VERSION_TABLE):
        return {}
    rows = conn.execute(f"SELECT version, name, checksum, how FROM {VERSION_TABLE} ORDER BY version").fetchall()
    return {row["version"]: row for row in rows}


def _verify_records(records: dict[int, Any], known: list[history.Migration]) -> None:
    target = len(known)
    newer = sorted(v for v in records if v > target)
    if newer:
        top = records[newer[-1]]
        raise DatabaseNewerThanCode(
            f"the database is at schema version {newer[-1]} ({top['name']}) and this code knows up to "
            f"{target}: an older image was started after a newer one migrated it. Deploy the newer image, "
            f"or restore the backup taken before that migration.")
    for mg in known:
        row = records.get(mg.version)
        if row is not None and row["checksum"] != mg.checksum:
            raise ChecksumMismatch(
                f"schema version {mg.version} ({mg.name}) was {row['how']} with other statements than "
                f"api/migrations now holds for it: an applied migration was edited. Restore the file as "
                f"it was and put the change in a new migration.")


def _record(conn: Any, mg: history.Migration, how: str, duration_ms: int, revision: str | None) -> None:
    conn.execute(f"INSERT INTO {VERSION_TABLE} (version, name, checksum, how, applied_at, duration_ms, "
                 "app_revision) VALUES (?,?,?,?,?,?,?)",
                 (mg.version, mg.name, mg.checksum, how, _now(), duration_ms, revision))


def _apply(conn: Any, mg: history.Migration, revision: str | None) -> None:
    from api.db import transaction

    t0 = time.monotonic()
    with transaction(conn):
        for table in mg.snapshot_tables:
            snapshot = f"_pre_v{mg.version:04d}_{table}"
            conn.execute_script(f'DROP TABLE IF EXISTS "{snapshot}"')
            conn.execute_script(f'CREATE TABLE "{snapshot}" AS TABLE "{table}"')
        for statement in mg.statements:
            conn.execute_script(statement)
        if mg.data is not None:
            mg.data(conn)
        if not mg.is_applied(conn):
            raise VerificationFailed(f"schema version {mg.version} ({mg.name}) ran, but its check does not "
                                     f"find its changes: rolled back")
        _record(conn, mg, "applied", int((time.monotonic() - t0) * 1000), revision)
    logger.info(f"[db] schema version {mg.version} applied: {mg.name} ({int((time.monotonic() - t0) * 1000)} ms)")


def upgrade(conn: Any = None) -> Report:
    """Apply every migration this database lacks.  Raises MigrationError when
    it cannot be brought to this code's version."""
    if conn is None:
        from api.db import _postgres_conn
        conn = _postgres_conn()
    known = history.load()
    conn.execute(f"SET lock_timeout = '{env_int('DB_MIGRATION_LOCK_TIMEOUT_S', default=600)}s'")
    conn.execute(f"SELECT pg_advisory_lock({_LOCK_KEY})")
    conn.execute("RESET lock_timeout")
    try:
        conn.execute_script(_VERSION_TABLE_DDL)
        records = _records(conn)
        _verify_records(records, known)
        report = Report(before=max(records, default=0), after=0, target=len(known))
        unversioned = not records and any(history.table_exists(conn, t) for t in _OWN_TABLES)
        revision = _revision() if len(records) < len(known) else None
        for mg in known:
            if mg.version in records:
                continue
            if unversioned and mg.is_applied(conn):
                _record(conn, mg, "recognised", 0, revision)
                report.recognised.append(mg.version)
                continue
            _apply(conn, mg, revision)
            report.applied.append(mg.version)
        report.after = report.target
    finally:
        conn.execute(f"SELECT pg_advisory_unlock({_LOCK_KEY})")
    if report.recognised:
        logger.info(f"[db] database from before versioned migrations: recognised versions "
                    f"{_span(report.recognised)}")
    if report.applied or report.recognised:
        logger.info(f"[db] schema version {report.before} -> {report.after}")
    else:
        logger.info(f"[db] schema at version {report.after}, nothing to migrate")
    return report


def status(conn: Any = None) -> dict:
    """Where the database is and what this code would do; changes nothing."""
    if conn is None:
        from api.db import _postgres_conn
        conn = _postgres_conn()
    known = history.load()
    records = _records(conn)
    current = max(records, default=0)
    return {
        "current": current,
        "target": len(known),
        "unversioned": not records and any(history.table_exists(conn, t) for t in _OWN_TABLES),
        "pending": [mg.version for mg in known if mg.version not in records],
        "newer_than_code": sorted(v for v in records if v > len(known)),
        "edited": [mg.version for mg in known
                   if mg.version in records and records[mg.version]["checksum"] != mg.checksum],
        "history": [{"version": mg.version, "name": mg.name, "description": mg.description,
                     "how": records[mg.version]["how"] if mg.version in records else "pending"}
                    for mg in known],
    }


def _span(versions: list[int]) -> str:
    """[1, 2, 3, 5, 7, 8] -> '1-3, 5, 7-8': a gap in what was recognised shows."""
    runs: list[list[int]] = []
    for v in versions:
        if runs and v == runs[-1][-1] + 1:
            runs[-1].append(v)
        else:
            runs.append([v])
    return ", ".join(f"{r[0]}-{r[-1]}" if len(r) > 1 else str(r[0]) for r in runs)


def main(argv: list[str] | None = None) -> int:
    from api.logging_config import setup_logging

    parser = argparse.ArgumentParser(prog="python -m api.migrate", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["status", "up", "check"])
    args = parser.parse_args(argv)
    setup_logging()
    if args.command == "up":
        try:
            report = upgrade()
        except MigrationError as exc:
            print(f"migration refused: {exc}", file=sys.stderr)
            return 1
        print(f"schema version {report.before} -> {report.after}; applied {report.applied or '-'}, "
              f"recognised {report.recognised or '-'}")
        return 0
    st = status()
    if args.command == "status":
        for row in st["history"]:
            print(f"  {row['version']:>4}  {row['how']:<10}  {row['name']:<40} {row['description']}")
        print(f"database at version {st['current']}, this code at {st['target']}"
              + (" (unversioned: versions will be recognised)" if st["unversioned"] else ""))
        for key in ("newer_than_code", "edited"):
            if st[key]:
                print(f"  {key.replace('_', ' ')}: {st[key]}")
        return 0
    ok = st["current"] == st["target"] and not st["pending"] and not st["newer_than_code"] and not st["edited"]
    print("up to date" if ok else f"not at this code's version: {st['current']} / {st['target']}, "
                                  f"pending {st['pending']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
