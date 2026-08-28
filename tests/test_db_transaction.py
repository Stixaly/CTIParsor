"""`api.db.transaction` gives the atomicity a bare `with conn:` does not."""
from __future__ import annotations

import sqlite3

import pytest

from api.db import transaction


def _conn(tmp_path) -> sqlite3.Connection:
    """An autocommit connection with one table holding a single row."""
    conn = sqlite3.connect(str(tmp_path / "t.db"), isolation_level=None)
    conn.execute("CREATE TABLE t (x INTEGER)")
    conn.execute("INSERT INTO t VALUES (1)")
    return conn


def _rows(conn) -> list[int]:
    """The values currently in t, sorted."""
    return sorted(r[0] for r in conn.execute("SELECT x FROM t"))


def test_bare_with_block_is_not_a_transaction(tmp_path):
    """A bare `with conn:` does not roll back under autocommit."""
    conn = _conn(tmp_path)
    # Under isolation_level=None every statement is already committed; the
    # sqlite3 context-manager rollback has nothing to undo. This is why
    # `transaction` exists.
    with pytest.raises(RuntimeError):
        with conn:
            conn.execute("DELETE FROM t")
            conn.execute("INSERT INTO t VALUES (2)")
            raise RuntimeError("boom")
    assert _rows(conn) == [2]


def test_transaction_rolls_back_on_exception(tmp_path):
    """transaction must roll back when the block raises."""
    conn = _conn(tmp_path)
    with pytest.raises(RuntimeError):
        with transaction(conn):
            conn.execute("DELETE FROM t")
            conn.execute("INSERT INTO t VALUES (2)")
            raise RuntimeError("boom")
    assert _rows(conn) == [1]


def test_transaction_commits_on_success(tmp_path):
    """transaction must commit when the block completes without error."""
    conn = _conn(tmp_path)
    with transaction(conn):
        conn.execute("DELETE FROM t")
        conn.execute("INSERT INTO t VALUES (2)")
    assert _rows(conn) == [2]

    # A second connection on the same file must see the committed value.
    conn2 = sqlite3.connect(str(tmp_path / "t.db"), isolation_level=None)
    assert _rows(conn2) == [2]
    conn2.close()


def test_transaction_reraises_the_original_exception(tmp_path):
    """The original exception must propagate unchanged."""
    conn = _conn(tmp_path)
    with pytest.raises(ValueError, match="specific"):
        with transaction(conn):
            raise ValueError("specific")


def test_transaction_yields_the_connection(tmp_path):
    """The context manager must yield the same connection object."""
    conn = _conn(tmp_path)
    with transaction(conn) as c:
        assert c is conn


def test_transaction_rolls_back_on_keyboardinterrupt(tmp_path):
    """KeyboardInterrupt (BaseException) must also trigger a rollback."""
    conn = _conn(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        with transaction(conn):
            conn.execute("DELETE FROM t")
            conn.execute("INSERT INTO t VALUES (2)")
            raise KeyboardInterrupt
    assert _rows(conn) == [1]
