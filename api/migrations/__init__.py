"""The history of the PostgreSQL schema, one module per version (ADR-0077).

Each `vNNNN_<name>.py` module defines one `MIGRATION`: the statements that
took the schema from version NNNN-1 to NNNN, an optional Python step for the
data, and `is_applied`, the check that tells whether a database already has
that version's changes.  `api.migrate` applies them in order, once each, and
uses `is_applied` both to verify what it just applied and to recognise how far
a database created before this history existed had got.

Version 1 is the first PostgreSQL job store (ADR-0045, 2026-09-16); the
SQLite prototype before it has no place here.  Rules for a new migration:
docs/development.md, "Database migrations".  An applied migration is never
edited — its checksum is recorded — a change is always a new file.
"""
from __future__ import annotations

import functools
import hashlib
import importlib
import inspect
import pkgutil
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

Store = Literal["jobs", "rules"]


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    store: Store                                   # which store its tables belong to
    statements: tuple[str, ...]                     # SQL, run in order, inside the transaction
    is_applied: Callable[[Any], bool]               # does this database have this version's changes?
    data: Callable[[Any], None] | None = None       # Python step after the statements (backfills)
    # Tables copied to `_pre_vNNNN_<table>` before a migration that drops,
    # renames, retypes or rewrites data in place: the way back without a dump.
    snapshot_tables: tuple[str, ...] = ()
    description: str = field(default="", compare=False)

    @property
    def checksum(self) -> str:
        """What was applied: the statements and the data step, whitespace
        normalised.  Comments and docstrings around them do not count."""
        parts = [" ".join(s.split()) for s in self.statements]
        if self.data is not None:
            parts.append(" ".join(inspect.getsource(self.data).split()))
        return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


# ── Checks a migration's `is_applied` is written with ────────────────────────
# All are scoped to current_schema(): the application, and every test, uses
# its own schema through search_path (api.db._PG_SCHEMA).

def _one(conn: Any, sql: str, params: tuple) -> bool:
    return conn.execute(sql, params).fetchone() is not None


def table_exists(conn: Any, table: str) -> bool:
    return _one(conn, "SELECT 1 FROM information_schema.tables "
                      "WHERE table_schema = current_schema() AND table_name = ?", (table,))


def column_exists(conn: Any, table: str, column: str) -> bool:
    return _one(conn, "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
                      "AND table_name = ? AND column_name = ?", (table, column))


def index_exists(conn: Any, index: str) -> bool:
    return _one(conn, "SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ?",
                (index,))


def constraint_exists(conn: Any, table: str, constraint: str) -> bool:
    return _one(conn, "SELECT 1 FROM information_schema.table_constraints "
                      "WHERE table_schema = current_schema() AND table_name = ? AND constraint_name = ?",
                (table, constraint))


def tables_exist(conn: Any, *tables: str) -> bool:
    return all(table_exists(conn, t) for t in tables)


def columns_exist(conn: Any, table: str, *columns: str) -> bool:
    return all(column_exists(conn, table, c) for c in columns)


def indexes_exist(conn: Any, *indexes: str) -> bool:
    return all(index_exists(conn, i) for i in indexes)


# ── The registry ─────────────────────────────────────────────────────────────

_MODULE = re.compile(r"^v(\d{4})_[a-z0-9_]+$")


def load() -> list[Migration]:
    """Every migration of this package, in version order.  Raises if a
    module's number and its MIGRATION.version disagree, or if a version is
    missing or doubled: the history must be one unbroken line."""
    return list(_load())


@functools.cache
def _load() -> tuple[Migration, ...]:
    # Read once per process: the files do not change under a running
    # process, and every start of every test schema would rescan them.
    found: list[Migration] = []
    for info in pkgutil.iter_modules(__path__):
        m = _MODULE.match(info.name)
        if not m:
            continue
        migration = importlib.import_module(f"{__name__}.{info.name}").MIGRATION
        if migration.version != int(m.group(1)):
            raise RuntimeError(f"{info.name} declares version {migration.version}")
        found.append(migration)
    found.sort(key=lambda mg: mg.version)
    expected = list(range(1, len(found) + 1))
    if [mg.version for mg in found] != expected:
        raise RuntimeError(f"migration versions are not 1..{len(found)}: {[mg.version for mg in found]}")
    return tuple(found)


def latest_version() -> int:
    return len(load())


def store_statements(store: Store) -> tuple[str, ...]:
    """Every statement of one store's history, in order — for the one-shot
    SQLite import scripts, which create the target tables themselves.  A
    database they fill is unversioned; the runner recognises its version at
    the next start (`is_applied`)."""
    return tuple(s for mg in load() if mg.store == store for s in mg.statements)
