import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from api.db_backend import DBConnection, PgConnection, backend_from_url

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

_ROOT = Path(__file__).parent.parent

# Every standalone script under scripts/ imports this module directly rather
# than going through run_api.py (the only other place that calls
# load_dotenv()) -- without this, DATABASE_URL in .env would be invisible to
# any of them unless the shell had already exported it. load_dotenv() never
# overrides a variable already set in the environment, so an explicit export
# still wins.
load_dotenv()

# ADR-0053 — CTIParsor no longer supports SQLite. DATABASE_URL is mandatory
# for both the job store and the rule store; backend_from_url() raises a clear
# error at first use if it is unset. Read once at import; tests monkeypatch
# the module attribute.
DATABASE_URL: str | None = (os.getenv("DATABASE_URL") or "").strip() or None

# PostgreSQL schema to use instead of `public` — set by the test fixture so each
# test gets a disposable namespace; None in production.
_PG_SCHEMA: str | None = None


# The exception classes a "must not fail the job" guard has to catch. psycopg
# is optional at import time (some tooling imports api.db without ever opening
# a connection); without it there is nothing that can raise a DB error here.
try:
    import psycopg as _psycopg
    DB_ERRORS: tuple[type[Exception], ...] = (_psycopg.Error,)
except ImportError:  # pragma: no cover - exercised only where psycopg is absent
    DB_ERRORS = ()


def backend() -> str:
    """'postgresql' — the only engine CTIParsor supports (ADR-0053).

    Raises if DATABASE_URL is unset or malformed; see backend_from_url().
    """
    return backend_from_url(DATABASE_URL)

# RLock (not Lock) so the same thread can re-acquire inside nested with-blocks
# (e.g. set_job_status called from inside another _lock-protected section).
#
# Scope note: this lock only serialises writers WITHIN a single process. The
# pipeline runs in a `spawn`ed subprocess (see api/worker.py) which imports its
# own copy of this module and therefore its own _lock — it does NOT coordinate
# with the uvicorn process via this object. Cross-process write safety comes
# from PostgreSQL itself. Don't rely on _lock for inter-process exclusion.
_lock = threading.RLock()

# Per-thread connection cache — reuses the same connection within a thread
# instead of creating a new one on every get_conn() call. Avoids the handle
# leak that occurs when connections are opened but never explicitly closed
# (relying on GC instead).
_local = threading.local()


def _postgres_conn() -> PgConnection:
    """Return a per-thread PostgreSQL connection, creating it on first access."""
    pg_conn = getattr(_local, "pg_conn", None)
    if pg_conn is None or pg_conn.url != DATABASE_URL or pg_conn.schema != _PG_SCHEMA:
        if pg_conn is not None:
            try:
                pg_conn.close()
            except Exception as exc:
                logger.debug("closing a stale PostgreSQL connection failed: %s", exc)
        if backend() != "postgresql":  # raises if DATABASE_URL is unset/malformed
            raise RuntimeError("DATABASE_URL is not set")
        pg_conn = PgConnection(DATABASE_URL, schema=_PG_SCHEMA)  # type: ignore[arg-type]
        _local.pg_conn = pg_conn
    return pg_conn


def get_conn() -> DBConnection:
    """The JOB store: PostgreSQL (ADR-0053 — SQLite is no longer supported).

    Per-thread, cached, autocommit — see _postgres_conn / PgConnection.
    """
    return _postgres_conn()


def get_rule_conn() -> DBConnection:
    """The RULE store (detection corpus): PostgreSQL, same as the job store.

    A separate accessor from get_conn() even though both hit the same
    DATABASE_URL today (ADR-0053) — kept distinct in case the corpus ever
    needs its own database, and to preserve the `jobs_conn=` split already
    used throughout pipeline/detection/.
    """
    return _postgres_conn()


def reset_connections() -> None:
    """Close and forget this thread's cached connection (tests, forks)."""
    pg_conn = getattr(_local, "pg_conn", None)
    if pg_conn is not None:
        try:
            pg_conn.close()
        except Exception as exc:
            logger.debug("closing this thread's PostgreSQL connection failed: %s", exc)
    _local.pg_conn = None


@contextmanager
def transaction(conn: DBConnection) -> Iterator[DBConnection]:
    """Run a block as ONE transaction, rolling back on any exception.

    `get_conn()`/`get_rule_conn()` are autocommit, so under autocommit
    `with conn:` is **not** a transaction on its own — every statement inside
    has already been committed individually, so a rollback on exception has
    nothing left to undo. Every multi-statement write that must be
    all-or-nothing uses this instead.
    """
    conn.execute("BEGIN")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    conn.commit()


def backup_db() -> None:
    """Log where the real backup tool is.

    PostgreSQL holds both stores now (ADR-0053) — there is no local file left
    for this process to copy. `pg_dump`/`pg_basebackup` is the operator's
    tool, same guidance the job store already gave when it moved to
    PostgreSQL (ADR-0045).
    """
    logger.info(
        "[db] both stores are PostgreSQL - back them up with pg_dump "
        "(see docs/docker.md); this function no longer copies a local file"
    )


# The schema is versioned (ADR-0077): api/migrations/ holds one module per
# version since the first PostgreSQL job store, and api.migrate applies what a
# database lacks.  These two tuples are only the concatenation of that history
# per store, for the one-shot SQLite import scripts that create their target
# tables themselves; nothing else should run DDL.
from api.migrations import store_statements as _store_statements  # noqa: E402

_RULE_STORE_DDL_POSTGRES: tuple[str, ...] = _store_statements("rules")
_JOB_STORE_DDL_POSTGRES: tuple[str, ...] = _store_statements("jobs")


def init_db() -> None:
    """Bring both stores to this code's schema version (ADR-0077).

    Runs at every start of the API, of a worker and of `bootstrap`: under an
    advisory lock, applies each migration the database lacks, in order, once,
    in its own transaction; recognises the version of a database created
    before migrations were versioned; refuses a database newer than this code
    (api.migrate.MigrationError stops the process)."""
    from api import migrate
    migrate.upgrade(_postgres_conn())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_progress(job_id: str, event_type: str, data: dict) -> None:
    import json
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO progress_events (job_id, event_type, data, created_at) VALUES (?,?,?,?)",
                (job_id, event_type, json.dumps(data), now_iso()),
            )
            conn.commit()


def set_job_status(job_id: str, status: str) -> None:
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "UPDATE jobs SET status=?, updated_at=? WHERE id=?",
                (status, now_iso(), job_id),
            )
            conn.commit()


def load_relationship_policy() -> dict | None:
    """The saved relationship policy, or None when none has been saved.

    Shared by the worker and the CLI (ADR-0059): the two must build a bundle
    under the same policy, and it is this row the Policy page writes.  Raises
    when the store cannot be read — the caller decides what that costs.
    """
    import json
    with get_conn() as conn:
        row = conn.execute("SELECT policy_json FROM relationship_policy WHERE id=1").fetchone()
    if row and row["policy_json"] not in ("", "{}"):
        return json.loads(row["policy_json"])
    return None
