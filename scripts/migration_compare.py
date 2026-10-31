"""Is every row a database held still there, with the same values, after this
code's migrations (ADR-0094 item 2)?

`snapshot` reads every table of a schema: every column, every row, keyed by
the primary key (by all the columns of a table that has none).  `compare`
matches the snapshots taken before and after `python -m api.migrate up`: a
table or a column dropped, a column retyped, a row gone, a value changed is a
difference, and every one is reported — unless `expected` (EXPECTED_CHANGES in
scripts/check_migration_from.py) declares it for a migration this run applied:
{version: {"table.column" or "table.*": why}}.  Tables, columns and rows the
migration added are listed, not compared.  `sequence_differences`: an identity
or serial column whose sequence would give the next row a value already used.

Values are compared as the database returns them, made comparable: json and
jsonb as their canonical text, dates and times in ISO 8601 (the snapshot's
session in UTC, whatever the server's zone), bytes in hex.  A TEXT column is
compared as text, byte for byte: the store serves its bundles and baselines as
they were written, and a baseline is checked against its sha256.  A column's
type is compared too: integer 1 and boolean true are equal values in Python.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any

from scripts.migration_seed import RUNNER_TABLES, primary_keys, quote, schema_columns

VERSION_TABLE = RUNNER_TABLES[0]


def comparable(value: Any) -> Any:
    """A value as the database returned it, in a form `==` and `repr` agree on."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, Decimal):
        return str(value)
    return str(value)


@dataclass
class Table:
    columns: dict[str, str]                       # column: data type
    key: tuple[str, ...]                          # the primary key; () when there is none
    rows: dict[tuple, dict[str, Any]] = field(default_factory=dict)


Snapshot = dict[str, Table]


def _row_key(row: dict[str, Any], columns: tuple[str, ...]) -> tuple:
    return tuple(row.get(c) for c in columns)


def _keyed(rows: list[dict[str, Any]], key: tuple[str, ...], columns: tuple[str, ...]) -> dict[tuple, dict]:
    """Rows by `key`; without one, by all of `columns`, each copy of a row numbered."""
    out: dict[tuple, dict] = {}
    copies: Counter = Counter()
    for row in rows:
        if key:
            out[_row_key(row, key)] = row
        else:
            values = _row_key(row, columns)
            copies[values] += 1
            out[(*values, copies[values])] = row
    return out


def snapshot(conn: Any) -> Snapshot:
    """Every table of the connection's schema, every row.  Sets the session's
    time zone to UTC, so a timestamptz reads the same on any server."""
    conn.execute("SET TIME ZONE 'UTC'")
    keys = primary_keys(conn)
    out: Snapshot = {}
    for table, cols in schema_columns(conn).items():
        names = tuple(cols)
        fetched = conn.execute(f"SELECT {', '.join(map(quote, names))} FROM {quote(table)}").fetchall()
        rows = [{c: comparable(r[c]) for c in names} for r in fetched]
        key = keys.get(table, ())
        out[table] = Table({c: col.data_type for c, col in cols.items()}, key, _keyed(rows, key, names))
    return out


def versions(snap: Snapshot) -> set[int]:
    """The migrations a snapshot's database records."""
    table = snap.get(VERSION_TABLE)
    return {row["version"] for row in table.rows.values()} if table else set()


def _short(value: Any, width: int = 60) -> str:
    text = repr(value)
    if len(text) <= width:
        return text
    return f"{text[:width]}... ({len(value) if isinstance(value, str) else len(text)} chars)"


@dataclass(frozen=True)
class Difference:
    table: str
    key: str           # the row, "id='...'"; "" for a table or a column
    column: str        # "" for a table or a row
    before: Any
    after: Any
    why: str = ""      # the expected change that explains it

    def line(self) -> str:
        if not self.key:
            what = f"{self.table}.{self.column}" if self.column else self.table
            text = f"{what}: {self.after}"
        elif not self.column:
            text = f"{self.table} [{self.key}]: {self.after}"
        else:
            text = f"{self.table} [{self.key}] {self.column}: {_short(self.before)} -> {_short(self.after)}"
        return f"{text}  (expected, {self.why})" if self.why else text


@dataclass
class Comparison:
    applied: list[int] = field(default_factory=list)
    differences: list[Difference] = field(default_factory=list)
    expected: list[Difference] = field(default_factory=list)
    new_tables: list[str] = field(default_factory=list)
    new_columns: dict[str, list[str]] = field(default_factory=dict)
    new_rows: dict[str, int] = field(default_factory=dict)
    tables: int = 0
    rows: int = 0
    values: int = 0

    @property
    def ok(self) -> bool:
        return not self.differences


def _key_text(table: Table, key: tuple) -> str:
    if table.key:
        return ", ".join(f"{c}={v!r}" for c, v in zip(table.key, key, strict=True))
    return "row " + ", ".join(_short(v, 30) for v in key[:-1])


def compare(before: Snapshot, after: Snapshot, expected: dict[int, dict[str, str]] | None = None) -> Comparison:
    """What the migration did to the rows of `before`: every difference, and
    what it added."""
    out = Comparison(applied=sorted(versions(after) - versions(before)))
    allowed = {target: f"version {v}: {why}"
               for v in out.applied for target, why in (expected or {}).get(v, {}).items()}

    def report(diff: Difference) -> None:
        why = (allowed.get(f"{diff.table}.{diff.column}") if diff.column else None) or allowed.get(f"{diff.table}.*")
        if why:
            out.expected.append(replace(diff, why=why))
        else:
            out.differences.append(diff)

    for name, old in before.items():
        out.tables += 1
        new = after.get(name)
        if new is None:
            report(Difference(name, "", "", f"{len(old.rows)} rows", "table dropped"))
            out.rows += len(old.rows)
            continue
        kept = [c for c in old.columns if c in new.columns]
        for column, data_type in old.columns.items():
            if column not in new.columns:
                report(Difference(name, "", column, f"{len(old.rows)} rows", "column dropped"))
            elif new.columns[column] != data_type:
                report(Difference(name, "", column, data_type, f"retyped {data_type} -> {new.columns[column]}"))
        added = [c for c in new.columns if c not in old.columns]
        if added:
            out.new_columns[name] = added
        # The rows after, keyed as the rows before were: a key that changed still matches.
        rows_after = _keyed(list(new.rows.values()), old.key, tuple(old.columns))
        for key, row in old.rows.items():
            out.rows += 1
            got = rows_after.pop(key, None)
            if got is None:
                report(Difference(name, _key_text(old, key), "", "present", "row missing"))
                continue
            for column in kept:
                out.values += 1
                if got.get(column) != row[column]:
                    report(Difference(name, _key_text(old, key), column, row[column], got.get(column)))
        if rows_after:
            out.new_rows[name] = len(rows_after)
    out.new_tables = sorted(set(after) - set(before))
    return out


def summary(result: Comparison, label: str = "content") -> list[str]:
    """The comparison, as the report prints it, its first line headed `label`."""
    lines = [f"{label}: {result.tables} tables, {result.rows} rows, {result.values} values compared"
             + ("; every one kept" if result.ok else f"; {len(result.differences)} difference(s)")]
    lines += [f"  DIFF {d.line()}" for d in result.differences]
    lines += [f"  expected {d.line()}" for d in result.expected]
    if result.new_tables:
        lines.append(f"  new tables: {', '.join(result.new_tables)}")
    for table, columns in sorted(result.new_columns.items()):
        lines.append(f"  new columns in {table}: {', '.join(columns)}")
    for table, n in sorted(result.new_rows.items()):
        lines.append(f"  new rows in {table}: {n}")
    return lines


def sequence_differences(conn: Any, tables: Iterable[str]) -> tuple[int, list[Difference]]:
    """(columns checked, differences): every identity or serial column of
    `tables` whose sequence would give the next row a value at or below the
    highest one stored — the next write collides (a table rebuilt with its rows
    copied, a sequence restarted).  Always a difference: no EXPECTED_CHANGES."""
    wanted = set(tables)
    columns = conn.execute(
        "SELECT c.table_name, c.column_name, pg_get_serial_sequence("
        "quote_ident(c.table_schema) || '.' || quote_ident(c.table_name), c.column_name) AS seq "
        "FROM information_schema.columns c JOIN information_schema.tables t "
        "ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
        "WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' "
        "ORDER BY c.table_name, c.ordinal_position").fetchall()
    checked, out = 0, []
    for r in columns:
        table, column, seq = r["table_name"], r["column_name"], r["seq"]
        if seq is None or table not in wanted:
            continue
        checked += 1
        top = conn.execute(f"SELECT max({quote(column)}) AS top FROM {quote(table)}").fetchone()["top"]
        # `seq` is the name PostgreSQL gave back, quoted as it must be.
        state = conn.execute(f"SELECT last_value, is_called FROM {seq}").fetchone()
        step = conn.execute("SELECT seqincrement AS step FROM pg_sequence WHERE seqrelid = ?::regclass",
                            (seq,)).fetchone()["step"]
        following = state["last_value"] + step if state["is_called"] else state["last_value"]
        if top is not None and step > 0 and following <= top:
            out.append(Difference(table, "", column, top, f"its sequence gives {following} next, not above the "
                                                          f"highest value stored ({top}): the next row collides"))
    return checked, out
