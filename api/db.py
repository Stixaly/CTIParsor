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
            except Exception:
                pass
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
        except Exception:
            pass
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


# Detection-rule store (ADR-0006, moved to PostgreSQL by ADR-0053) —
# corpus-derived, NOT per-job. Populated by scripts/build_detection_index.py
# from local corpus clones. Same table set as the pre-ADR-0053 SQLite layout,
# with `rule_text` now an ordinary table instead of an FTS5 virtual one: a
# generated `tsvector` column plus a GIN index replaces FTS5's tokenizer, and
# gives the same word-boundary semantics the match needs (substring matching
# put `reat` inside 52,775 rules, which is why FTS5 was chosen originally —
# `to_tsvector('simple', ...)` does not stem and does not substring-match
# either). One statement per tuple entry, applied through
# _apply_postgres_ddl() exactly like _JOB_STORE_DDL_POSTGRES below.
_RULE_STORE_DDL_POSTGRES: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS detection_rules (
    id           TEXT PRIMARY KEY,
    corpus       TEXT NOT NULL,
    native_key   TEXT NOT NULL,
    format       TEXT NOT NULL DEFAULT 'sigma',
    title        TEXT NOT NULL,
    description  TEXT DEFAULT '',
    severity     TEXT DEFAULT 'unknown',
    license      TEXT DEFAULT 'unknown',
    source_ref   TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    dedup_key    TEXT DEFAULT '',
    is_canonical INTEGER DEFAULT 1,
    data_sources TEXT DEFAULT '[]',
    platform     TEXT DEFAULT '',
    raw          TEXT DEFAULT ''
)""",
    # Byte length of each rule body, in its own table (ADR-0022) rather than a
    # column on detection_rules, so reading it never walks the multi-kilobyte
    # `raw` body.
    """CREATE TABLE IF NOT EXISTS rule_bytes (
    rule_id TEXT PRIMARY KEY,
    bytes   INTEGER NOT NULL DEFAULT 0
)""",
    """CREATE TABLE IF NOT EXISTS rule_techniques (
    rule_id      TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, technique_id)
)""",
    # ADR-0031 / ADR-0053 — full-text index over each canonical rule's title
    # and description. `body_tsv` is GENERATED so it is always in sync with
    # `body` — no separate "is the index built" state to track the way FTS5's
    # virtual table needed rule_text_built() to guard against.
    """CREATE TABLE IF NOT EXISTS rule_text (
    rule_id  TEXT PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    body     TEXT NOT NULL,
    body_tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', body)) STORED
)""",
    "CREATE INDEX IF NOT EXISTS idx_rule_text_tsv ON rule_text USING GIN (body_tsv)",
    # Detection atoms (ADR-0014) — the literal values a rule looks for,
    # extracted from its `detection:` block.
    """CREATE TABLE IF NOT EXISTS rule_atoms (
    rule_id    TEXT NOT NULL,
    atom_class TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (rule_id, atom_class, value)
)""",
    # Declared rule provenance (ADR-0017) — the Sigma `related:` block.
    """CREATE TABLE IF NOT EXISTS rule_related (
    rule_id     TEXT NOT NULL,
    related_key TEXT NOT NULL,
    rel_type    TEXT NOT NULL,
    PRIMARY KEY (rule_id, related_key, rel_type)
)""",
    "CREATE INDEX IF NOT EXISTS idx_rule_related_key ON rule_related(related_key)",
    "CREATE INDEX IF NOT EXISTS idx_rule_tech_tech   ON rule_techniques(technique_id)",
    "CREATE INDEX IF NOT EXISTS idx_detection_corpus ON detection_rules(corpus)",
    "CREATE INDEX IF NOT EXISTS idx_detection_dedup  ON detection_rules(dedup_key)",
    "CREATE INDEX IF NOT EXISTS idx_detection_canon  ON detection_rules(is_canonical)",
    "CREATE INDEX IF NOT EXISTS idx_rule_atoms_value ON rule_atoms(value)",
)

# Job store on PostgreSQL (ADR-0045).  Same eight tables as the SQLite layout,
# with the dialect differences that matter: IDENTITY instead of AUTOINCREMENT,
# DOUBLE PRECISION instead of REAL (PostgreSQL's REAL is a 4-byte float and
# would round every confidence score), and IF NOT EXISTS on everything so this
# list is the migration mechanism too.
#
# A tuple of INDIVIDUAL statements, not one script string: PostgreSQL's simple-
# query protocol runs a multi-statement string as one implicit transaction, so
# a duplicate-object race on any ONE statement (two processes both calling
# init_db() against a fresh database) used to roll back every statement in the
# whole script together -- including a later ALTER TABLE a newer code revision
# added, silently leaving its column missing even though init_db() reported
# success. Applied one at a time (_apply_postgres_ddl), a race on one
# statement no longer touches any other.
_JOB_STORE_DDL_POSTGRES: tuple[str, ...] = (
    """CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'uploaded',
    report_text TEXT,
    bundle_json TEXT,
    llm_result_json TEXT,
    tlp_level TEXT,
    pap_level TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    run_config_json TEXT,
    worker_id TEXT,
    heartbeat_at TEXT
)""",
    # ADR-0046 lease columns for a store created before them; no-ops on a fresh one.
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS worker_id TEXT",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS heartbeat_at TEXT",
    """CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    context TEXT DEFAULT '',
    confidence DOUBLE PRECISION DEFAULT 1.0,
    mitre_id TEXT,
    accepted INTEGER,
    source TEXT DEFAULT 'auto',
    evidence_text TEXT,
    evidence_label TEXT,
    evidence_start INTEGER,
    evidence_end INTEGER
)""",
    """CREATE TABLE IF NOT EXISTS relationships (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    source_value TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    confidence DOUBLE PRECISION DEFAULT 0.8,
    accepted INTEGER DEFAULT 1,
    evidence_text TEXT,
    evidence_label TEXT DEFAULT 'reported',
    start_time TEXT,
    stop_time TEXT
)""",
    # STIX 2.1 SRO optional properties for a store created before them.
    "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS start_time TEXT",
    "ALTER TABLE relationships ADD COLUMN IF NOT EXISTS stop_time TEXT",
    """CREATE TABLE IF NOT EXISTS progress_events (
    id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    job_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS idx_entities_job ON entities(job_id)",
    "CREATE INDEX IF NOT EXISTS idx_relationships_job ON relationships(job_id)",
    "CREATE INDEX IF NOT EXISTS idx_progress_job ON progress_events(job_id)",
    # Relationship Policy - single-row JSON store (id always = 1)
    """CREATE TABLE IF NOT EXISTS relationship_policy (
    id INTEGER PRIMARY KEY DEFAULT 1,
    policy_json TEXT NOT NULL DEFAULT '{}'
)""",
    # ADR-0032 - provenance for figure-derived evidence (see the SQLite twin).
    """CREATE TABLE IF NOT EXISTS report_figures (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    page INTEGER NOT NULL,
    bbox TEXT NOT NULL,
    kind TEXT NOT NULL,
    char_start INTEGER NOT NULL,
    char_end INTEGER NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    UNIQUE (job_id, ordinal)
)""",
    "CREATE INDEX IF NOT EXISTS idx_report_figures_span ON report_figures(job_id, char_start)",
    # ADR-0033 - the figure read cache, keyed on the crop bytes.
    """CREATE TABLE IF NOT EXISTS figure_reads (
    sha256 TEXT NOT NULL,
    model TEXT NOT NULL,
    prompt_version INTEGER NOT NULL,
    read_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (sha256, model, prompt_version)
)""",
    # CVE metadata fetched from CIRCL; a row with NULL description AND cvss_score
    # is a remembered miss.
    """CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score DOUBLE PRECISION,
    cvss_vector TEXT,
    fetched_at TEXT NOT NULL
)""",
    # ADR-0051 - calibrated NER confidence cutoffs (see the SQLite twin).
    """CREATE TABLE IF NOT EXISTS model_thresholds (
    source TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    threshold DOUBLE PRECISION NOT NULL,
    sample_size INTEGER NOT NULL DEFAULT 0,
    target_precision DOUBLE PRECISION,
    precision_at DOUBLE PRECISION,
    recall_retained DOUBLE PRECISION,
    origin TEXT NOT NULL DEFAULT 'calibrated',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source, entity_type)
)""",
    # ADR-0052 - deny / promote lists grown from analyst decisions (see the SQLite twin).
    """CREATE TABLE IF NOT EXISTS entity_overrides (
    id TEXT PRIMARY KEY,
    term TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate',
    display TEXT,
    accepted_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    job_count INTEGER NOT NULL DEFAULT 0,
    origin TEXT NOT NULL DEFAULT 'auto',
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (term, entity_type, action)
)""",
    "CREATE INDEX IF NOT EXISTS idx_entity_overrides_status ON entity_overrides(status)",
)


def _apply_postgres_ddl(pg, statements: tuple[str, ...]) -> None:
    """Run each PostgreSQL DDL statement in its own request, logging rather
    than crashing on the one error that is expected rather than tolerated:
    two processes racing IF-NOT-EXISTS DDL against a fresh database. One
    statement's race no longer rolls back or masks any of the others (see
    the module-level comment on _JOB_STORE_DDL_POSTGRES).
    """
    import psycopg.errors as _pg_errors

    _benign = (
        _pg_errors.DuplicateTable,
        _pg_errors.DuplicateObject,
        _pg_errors.DuplicateColumn,
        _pg_errors.DuplicateFunction,
        _pg_errors.DuplicateSchema,
    )
    for stmt in statements:
        try:
            pg.execute_script(stmt)
        except _benign as exc:
            logger.warning(f"[db] PostgreSQL schema init: benign duplicate-object race: {exc}")


def init_db() -> None:
    """Create or migrate both stores — both PostgreSQL (ADR-0053)."""
    pg = _postgres_conn()
    _apply_postgres_ddl(pg, _RULE_STORE_DDL_POSTGRES)
    _apply_postgres_ddl(pg, _JOB_STORE_DDL_POSTGRES)


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
