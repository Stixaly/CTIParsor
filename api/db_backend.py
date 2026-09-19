from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from functools import lru_cache
from typing import Any, Protocol


class DBConnection(Protocol):
    """What routes, the worker and the pipeline rely on — satisfied by both
    sqlite3.Connection and PgConnection."""

    # Parameter types are Any on purpose: typeshed's sqlite3.Connection.execute
    # takes SupportsLenAndGetItem | Mapping, and a Protocol member must accept
    # at least what its implementations accept for them to satisfy it.
    def execute(self, sql: str, params: Any = ..., /) -> Any: ...
    def executemany(self, sql: str, seq_of_params: Any, /) -> Any: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...
    def __enter__(self) -> Any: ...
    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any: ...


def backend_from_url(url: str | None) -> str:
    """Determine the backend type from the database URL.

    CTIParsor no longer supports SQLite (ADR-0053): DATABASE_URL is mandatory
    and must be a postgresql:// URL, for both the job store and the rule
    store. An unset or malformed value fails loudly here rather than
    silently falling back to a file that is no longer maintained.
    """
    if url is None or not url.strip():
        raise RuntimeError(
            "DATABASE_URL is not set. CTIParsor requires PostgreSQL — "
            "postgresql://user@host:5432/dbname — see ADR-0053; SQLite is no "
            "longer supported."
        )
    stripped = url.strip()
    if stripped.startswith("postgresql://") or stripped.startswith("postgres://"):
        return "postgresql"
    raise ValueError(f"Unsupported DATABASE_URL scheme: {url!r} (expected postgresql://...)")


@lru_cache(maxsize=1024)
def translate_placeholders(sql: str) -> str:
    """Convert sqlite3 qmark placeholders to psycopg format placeholders.

    psycopg's placeholder scanner is a plain text scan for '%s'/'%b'/'%t' (see
    psycopg._queries._split_query) -- it is NOT aware of SQL string quoting, so
    a literal '%' must be doubled to '%%' everywhere in the query text,
    including inside a quoted string literal (e.g. `LIKE '%foo%'`), or psycopg
    raises "only '%s', '%b', '%t' are allowed as placeholders". Quote tracking
    below is only needed to decide whether a '?' is a real placeholder (outside
    quotes) or a literal question mark (inside one) -- '%' escaping applies
    unconditionally.
    """
    result = []
    in_single = False
    in_double = False
    for char in sql:
        if char == "'" and not in_double:
            in_single = not in_single
            result.append(char)
        elif char == '"' and not in_single:
            in_double = not in_double
            result.append(char)
        elif char == "%":
            result.append("%%")
        elif char == "?" and not in_single and not in_double:
            result.append("%s")
        else:
            result.append(char)
    return "".join(result)


@lru_cache(maxsize=256)
def row_class(names: tuple[str, ...]) -> type:
    """Create a row class with name-based access."""
    class Row(tuple):
        __slots__ = ()
        _names = names
        _index = {name: i for i, name in enumerate(names)}

        def __getitem__(self, key):
            if isinstance(key, str):
                try:
                    return tuple.__getitem__(self, self._index[key])
                except KeyError:
                    raise IndexError("No item with that key") from None
            return tuple.__getitem__(self, key)

        def keys(self) -> list[str]:
            return list(self._names)

    return Row


def pg_row_factory(cursor: Any) -> Callable[[Sequence[Any]], Any]:
    """Row factory for psycopg cursors."""
    if cursor.description is None:
        return tuple
    names = tuple(col.name for col in cursor.description)
    return row_class(names)


class PgConnection:
    """One PostgreSQL connection with the calling conventions of sqlite3.Connection.

    - `?` placeholders are translated to `%s` (only when parameters are passed;
      a bare DDL string goes through untouched, so `%` in it is not special).
    - rows come back as Row (tuple + name access), like sqlite3.Row.
    - autocommit, like the sqlite3 connection this replaces (isolation_level=None);
      `transaction()` in api.db issues explicit BEGIN/COMMIT.
    - `with conn:` never closes the connection — psycopg's own context manager
      does, which would destroy the per-thread cache on the first route.
    - a connection the server dropped is reopened transparently on next use.
    """

    def __init__(self, url: str, *, schema: str | None = None, application_name: str = "ctiparsor"):
        self.url = url
        self.schema = schema
        self.application_name = application_name
        self._conn = None
        self._connect()

    def _connect(self):
        try:
            import psycopg
        except ImportError:
            raise RuntimeError(
                "DATABASE_URL points at PostgreSQL but psycopg is not installed - "
                "pip install 'psycopg[binary]'"
            ) from None
        kwargs = {"autocommit": True, "row_factory": pg_row_factory, "application_name": self.application_name}
        if self.schema:
            kwargs["options"] = f"-c search_path={self.schema}"
        self._conn = psycopg.connect(self.url, **kwargs)

    def _ensure(self):
        if self._conn is None or self._conn.closed or self._conn.broken:
            self._connect()
        return self._conn

    @property
    def closed(self) -> bool:
        return self._conn is None or self._conn.closed

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> Any:
        conn = self._ensure()
        if params is None:
            return conn.execute(sql)
        return conn.execute(translate_placeholders(sql), tuple(params) if not isinstance(params, dict) else params)

    def executemany(self, sql: str, seq_of_params: Iterable[Sequence[Any]]) -> Any:
        cur = self._ensure().cursor()
        cur.executemany(translate_placeholders(sql), [tuple(p) for p in seq_of_params])
        return cur

    def execute_script(self, sql: str) -> None:
        self._ensure().execute(sql)

    def cursor(self) -> Any:
        return self._ensure().cursor()

    def commit(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.commit()

    def rollback(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.rollback()

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
        self._conn = None

    def __enter__(self) -> Any:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> Any:
        if exc_type is not None:
            try:
                self.rollback()
            except Exception:
                pass
        return False
