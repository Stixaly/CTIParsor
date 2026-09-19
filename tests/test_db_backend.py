from __future__ import annotations

import types

import pytest

from api.db_backend import PgConnection, backend_from_url, pg_row_factory, row_class, translate_placeholders


def test_translate_placeholders_table():
    cases = [
        ("SELECT ? FROM t WHERE a=? AND b='x?y'", "SELECT %s FROM t WHERE a=%s AND b='x?y'"),
        # A literal '%' inside a quoted string must be doubled too: psycopg's
        # placeholder scanner is a plain text scan, not quote-aware (see
        # test_translate_placeholders_survives_psycopg_parsing below).
        ("c LIKE '%z' AND d=?", "c LIKE '%%z' AND d=%s"),
        ('e = 100 % ? AND f="q?"', "e = 100 %% %s AND f=\"q?\""),
        ("a='it''s ?' AND b=?", "a='it''s ?' AND b=%s"),
        ("SELECT 1", "SELECT 1"),
    ]
    for sql, expected in cases:
        assert translate_placeholders(sql) == expected


def test_translate_placeholders_survives_psycopg_parsing():
    """Every translated query must actually parse as psycopg3 sees it.

    A prior version of `translate_placeholders` only doubled '%' outside
    quotes, which round-tripped fine through this module's own logic but
    raised `psycopg.errors.ProgrammingError` the moment a real psycopg
    connection tried to parse a query with a LIKE-style '%' wildcard hardcoded
    in a quoted string next to a '?' placeholder. Asserting against
    `_split_query` (the actual scanner) rather than a hand-picked expected
    string is what would have caught that regression.
    """
    from psycopg._queries import _split_query

    queries_with_params = [
        "SELECT ? FROM t WHERE a=? AND b='x?y'",
        "SELECT * FROM t WHERE name LIKE '%foo%' AND id = ?",
        "SELECT * FROM t WHERE a=? AND b LIKE '%x' AND c=?",
        'e = 100 % ? AND f="q?"',
        "a='it''s ?' AND b=?",
    ]
    for sql in queries_with_params:
        translated = translate_placeholders(sql)
        _split_query(translated.encode())  # raises psycopg.errors.ProgrammingError if malformed


def test_backend_from_url():
    """ADR-0053: SQLite is no longer a valid backend — DATABASE_URL is
    mandatory and must be postgresql://."""
    with pytest.raises(RuntimeError):
        backend_from_url(None)
    with pytest.raises(RuntimeError):
        backend_from_url("")
    with pytest.raises(RuntimeError):
        backend_from_url("   ")
    assert backend_from_url("postgresql://u:p@h/db") == "postgresql"
    assert backend_from_url("postgres://h/db") == "postgresql"
    assert backend_from_url("  postgresql://h/db  ") == "postgresql"
    with pytest.raises(ValueError):
        backend_from_url("mysql://h/db")
    with pytest.raises(ValueError):
        backend_from_url("sqlite:///x.db")


def test_row_supports_index_and_name_access():
    R = row_class(("id", "name"))
    r = R((1, "x"))
    assert r[0] == 1
    assert r["name"] == "x"
    assert r.keys() == ["id", "name"]
    assert dict(r) == {"id": 1, "name": "x"}
    assert len(r) == 2
    assert tuple(r) == (1, "x")
    a, b = r
    assert a == 1 and b == "x"
    assert r == (1, "x")
    with pytest.raises(IndexError):
        _ = r["nope"]
    assert row_class(("id", "name")) is R


def test_pg_row_factory_without_description_returns_tuple():
    cur = types.SimpleNamespace(description=None)
    assert pg_row_factory(cur) is tuple

    cur2 = types.SimpleNamespace(description=[types.SimpleNamespace(name="a"), types.SimpleNamespace(name="b")])
    factory = pg_row_factory(cur2)
    row = factory((1, 2))
    assert row["b"] == 2


class FakeCursor:
    def __init__(self, fake_conn):
        self._fake_conn = fake_conn

    def executemany(self, sql, seq):
        self._fake_conn.executed.append((sql, list(seq)))


class FakeConn:
    def __init__(self):
        self.executed = []
        self.closed = False
        self.broken = False
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        return "cursor"

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1
        self.closed = True


def _wrapper(fake):
    pg = PgConnection.__new__(PgConnection)
    pg.url = "postgresql://x"
    pg.schema = None
    pg.application_name = "t"
    pg._conn = fake
    return pg


def test_wrapper_translates_only_when_params_are_given():
    fake = FakeConn()
    pg = _wrapper(fake)
    pg.execute("SELECT ? FROM t", (1,))
    assert fake.executed[-1] == ("SELECT %s FROM t", (1,))

    pg.execute("CREATE TABLE x (a TEXT DEFAULT '%')")
    assert fake.executed[-1] == ("CREATE TABLE x (a TEXT DEFAULT '%')", None)


def test_wrapper_executemany_translates_and_materialises():
    fake = FakeConn()
    pg = _wrapper(fake)
    pg.executemany("INSERT INTO t VALUES (?, ?)", ((1, 2), [3, 4]))
    assert fake.executed[-1] == ("INSERT INTO t VALUES (%s, %s)", [(1, 2), (3, 4)])


def test_wrapper_context_manager_never_closes():
    fake = FakeConn()
    with _wrapper(fake) as c:
        c.execute("SELECT 1")
    assert fake.closes == 0
    assert fake.rollbacks == 0

    fake2 = FakeConn()
    with pytest.raises(RuntimeError):
        with _wrapper(fake2):
            raise RuntimeError("boom")
    assert fake2.rollbacks == 1
    assert fake2.closes == 0


def test_wrapper_reconnects_when_dropped(monkeypatch):
    fake = FakeConn()
    pg = _wrapper(fake)
    fake.closed = True

    def fake_connect():
        pg._conn = FakeConn()

    monkeypatch.setattr(pg, "_connect", fake_connect)
    pg.execute("SELECT 1")
    assert pg._conn is not fake


def test_get_conn_requires_database_url(monkeypatch):
    """ADR-0053: no more SQLite fallback — an unset DATABASE_URL fails loudly."""
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    db.reset_connections()
    with pytest.raises(RuntimeError):
        db.backend()
    with pytest.raises(RuntimeError):
        db.get_conn()


def test_get_conn_and_get_rule_conn_share_the_postgres_backend(monkeypatch):
    """get_conn() and get_rule_conn() are both PostgreSQL now (ADR-0053) — kept
    as two accessors for a future split, not two engines today."""
    import api.db as db

    class FakePg:
        def __init__(self, url, *, schema=None, application_name="ctiparsor"):
            self.url = url
            self.schema = schema
            self.application_name = application_name

        def close(self):
            pass

    monkeypatch.setattr(db, "DATABASE_URL", "postgresql://u:p@localhost/db")
    monkeypatch.setattr(db, "PgConnection", FakePg)
    db.reset_connections()
    assert db.backend() == "postgresql"
    c = db.get_conn()
    assert isinstance(c, FakePg) and c.url.startswith("postgresql://")
    assert db.get_rule_conn() is c
    assert db.get_conn() is c

    monkeypatch.setattr(db, "_PG_SCHEMA", "t_abc")
    assert db.get_conn() is not c and db.get_conn().schema == "t_abc"
    db.reset_connections()


def test_transaction_uses_plain_begin_on_postgres():
    import api.db as db

    fake = FakeConn()
    with db.transaction(_wrapper(fake)):
        pass
    assert fake.executed[0][0] == "BEGIN"
    assert fake.commits == 1

    fake2 = FakeConn()
    with pytest.raises(RuntimeError):
        with db.transaction(_wrapper(fake2)):
            raise RuntimeError("boom")
    assert fake2.rollbacks == 1
