import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

DB_PATH = Path(__file__).parent.parent / "cti_stix.db"
BACKUP_DIR = Path(__file__).parent.parent / "db_backups"
# RLock (not Lock) so the same thread can re-acquire inside nested with-blocks
# (e.g. set_job_status called from inside another _lock-protected section).
#
# Scope note: this lock only serialises writers WITHIN a single process.  The
# pipeline runs in a `spawn`ed subprocess (see api/worker.py) which imports its
# own copy of this module and therefore its own _lock — it does NOT coordinate
# with the uvicorn process via this object.  Cross-process write safety comes
# from SQLite itself: WAL mode (one writer + concurrent readers) plus the
# busy_timeout set below.  Don't rely on _lock for inter-process exclusion.
_lock = threading.RLock()

# Per-thread connection cache — reuses the same connection within a thread
# instead of creating a new one on every get_conn() call.  Avoids the file
# handle leak that occurs when connections are opened but never explicitly
# closed (relying on GC instead).
_local = threading.local()

# Connection timeout in seconds
_CONNECTION_TIMEOUT = 30
# Busy timeout in milliseconds (wait for locks)
_BUSY_TIMEOUT = 5000


def get_conn() -> sqlite3.Connection:
    """
    Return a per-thread SQLite connection, creating it on first access.

    Using thread-local storage means each worker thread (FastAPI, pipeline)
    gets exactly one connection for its lifetime — no new handles are opened
    per-request, and no handles are left unclosed when the caller's with-block
    exits (the context manager commits/rolls back but keeps the connection open
    for the next call on the same thread).

    PRAGMAs are set once per connection rather than on every call.

    Security: Uses check_same_thread=False for FastAPI compatibility but
    ensures thread-safety via thread-local storage.
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        # timeout prevents "database is locked" under concurrent requests
        # busy_timeout waits for locks to clear (in milliseconds)
        conn = sqlite3.connect(
            str(DB_PATH),
            check_same_thread=False,
            timeout=_CONNECTION_TIMEOUT,
            isolation_level=None  # Autocommit mode for better control
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT}")
        # Bound WAL growth: checkpoint every 1000 pages (~4 MB at the default
        # 4 KB page size).  Note: there is no "PRAGMA wal_max_size" in SQLite —
        # wal_autocheckpoint is the supported mechanism for capping WAL size.
        conn.execute("PRAGMA wal_autocheckpoint=1000")
        _local.conn = conn
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block as ONE SQLite transaction, rolling back on any exception.

    `get_conn()` opens with `isolation_level=None`, and under autocommit
    `with conn:` is **not** a transaction: sqlite3's context manager commits on
    exit, but every statement inside has already been committed on its own, so
    the rollback it performs on an exception has nothing left to undo.

    Verified rather than assumed — a DELETE followed by an INSERT inside
    `with conn:`, with an exception raised between them, leaves the INSERT
    committed and the original row gone.

    Every multi-statement write that must be all-or-nothing uses this instead.
    `BEGIN IMMEDIATE` takes the write lock up front, so two writers queue on
    `busy_timeout` rather than one failing at COMMIT with SQLITE_BUSY.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    conn.commit()


def backup_db() -> None:
    """
    Create a consistent backup of the database file.

    Creates timestamped single-file backups in db_backups/ and keeps the last 7.

    Uses SQLite's online backup API (sqlite3.Connection.backup) instead of a
    filesystem copy.  In WAL mode the live database is spread across the .db,
    .db-wal, and .db-shm files; copying them with shutil while another
    connection (or the worker subprocess) is mid-write can capture a torn state
    where the WAL holds committed frames the main file doesn't.  The backup API
    takes a read transaction and produces a single self-contained, consistent
    .db file with no sidecar files required.
    """
    import glob
    from datetime import datetime

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"cti_stix_{timestamp}.db"

    try:
        src = get_conn()
        dest = sqlite3.connect(str(backup_path))
        try:
            with dest:
                src.backup(dest)
        finally:
            dest.close()

        # Clean up old backups (keep last 7)
        backup_files = sorted(glob.glob(str(BACKUP_DIR / "cti_stix_*.db")), reverse=True)
        for old_backup in backup_files[7:]:
            try:
                os.remove(old_backup)
            except OSError:
                pass
            # Remove any legacy WAL/SHM sidecar backups left by the old
            # copy-based scheme (no-op for backups created by this function).
            for sidecar in (old_backup + "-wal", old_backup + "-shm"):
                try:
                    os.remove(sidecar)
                except OSError:
                    pass
    except Exception as e:
        logger.error(f"[db] Backup failed: {e}")


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'uploaded',
                report_text TEXT,
                bundle_json TEXT,
                llm_result_json TEXT,
                tlp_level TEXT,
                pap_level TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                context TEXT DEFAULT '',
                confidence REAL DEFAULT 1.0,
                mitre_id TEXT,
                accepted INTEGER,
                source TEXT DEFAULT 'auto',
                FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS relationships (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL,
                source_value TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                confidence REAL DEFAULT 0.8,
                accepted INTEGER DEFAULT 1,
                FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS progress_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_entities_job ON entities(job_id);
            CREATE INDEX IF NOT EXISTS idx_relationships_job ON relationships(job_id);
            CREATE INDEX IF NOT EXISTS idx_progress_job ON progress_events(job_id);

            -- Relationship Policy — single-row JSON store (id always = 1)
            CREATE TABLE IF NOT EXISTS relationship_policy (
                id      INTEGER PRIMARY KEY DEFAULT 1,
                policy_json TEXT NOT NULL DEFAULT '{}'
            );

            -- Detection-rule store (ADR-0006) — corpus-derived, NOT per-job.
            -- Populated by scripts/build_detection_index.py from local corpus clones.
            -- May contain private rule content; cti_stix.db is gitignored.
            CREATE TABLE IF NOT EXISTS detection_rules (
                id           TEXT PRIMARY KEY,   -- corpus:native_key
                corpus       TEXT NOT NULL,
                native_key   TEXT NOT NULL,      -- Sigma id or content-hash16 (cross-corpus dedup)
                format       TEXT NOT NULL DEFAULT 'sigma',
                title        TEXT NOT NULL,
                description  TEXT DEFAULT '',
                severity     TEXT DEFAULT 'unknown',
                license      TEXT DEFAULT 'unknown',
                source_ref   TEXT DEFAULT '',
                content_hash TEXT DEFAULT '',
                dedup_key    TEXT DEFAULT '',  -- sha256 of normalized detection logic (ADR-0010)
                is_canonical INTEGER DEFAULT 1, -- 0 = duplicate folded by the dedup pass
                data_sources TEXT DEFAULT '[]',  -- JSON array
                raw          TEXT DEFAULT ''
            );

            -- Byte length of each rule body, in its own table (ADR-0022). It is
            -- NOT a column on detection_rules: any column added there lands
            -- after `raw`, and SQLite must walk the multi-kilobyte body and its
            -- overflow pages to reach it — measured 8.2s to read one integer
            -- for 10,372 rules, versus 0.1s from this side table.
            CREATE TABLE IF NOT EXISTS rule_bytes (
                rule_id TEXT PRIMARY KEY,
                bytes   INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS rule_techniques (
                rule_id      TEXT NOT NULL,
                technique_id TEXT NOT NULL,
                PRIMARY KEY (rule_id, technique_id)
            );

            -- ADR-0031 — full-text index over each canonical rule's title and
            -- description. A brand token is looked up here in 0.4ms; the same
            -- lookup as a scan of `detection_rules` measured 4.1s, and FTS5's
            -- tokenizer gives the word-boundary semantics the match needs
            -- anyway (substring matching put `reat` inside 52,775 rules).
            CREATE VIRTUAL TABLE IF NOT EXISTS rule_text USING fts5(
                rule_id UNINDEXED,
                body
            );

            -- Detection atoms (ADR-0014) — the literal values a rule looks for,
            -- extracted from its `detection:` block. Lets a report's observables
            -- rank rules by content instead of by ATT&CK tag alone.
            CREATE TABLE IF NOT EXISTS rule_atoms (
                rule_id    TEXT NOT NULL,
                atom_class TEXT NOT NULL,   -- image|cmdline|file|registry|hash|domain|ip|url|pipe|service|port|user
                value      TEXT NOT NULL,   -- normalized, lowercase, wildcard-free
                PRIMARY KEY (rule_id, atom_class, value)
            );

            -- Declared rule provenance (ADR-0017) — the Sigma `related:` block.
            -- Cross-corpus dedup clusters on this as well as on dedup_key: a
            -- converted corpus (hayabusa) rewrites field names and injects a
            -- Channel/EventID binding, so the detection hash differs even though
            -- the rule is the same. 4,758 of hayabusa's 4,759 rules declare a
            -- `related:` id that exists in sigmahq; exactly 1 shares a dedup_key.
            -- `related_key` is a BARE Sigma id, not a corpus-prefixed rule id.
            CREATE TABLE IF NOT EXISTS rule_related (
                rule_id     TEXT NOT NULL,
                related_key TEXT NOT NULL,
                rel_type    TEXT NOT NULL,   -- derived|renamed|similar|obsolete|merged
                PRIMARY KEY (rule_id, related_key, rel_type)
            );

            CREATE INDEX IF NOT EXISTS idx_rule_related_key ON rule_related(related_key);
            CREATE INDEX IF NOT EXISTS idx_rule_tech_tech   ON rule_techniques(technique_id);
            CREATE INDEX IF NOT EXISTS idx_detection_corpus ON detection_rules(corpus);
            CREATE INDEX IF NOT EXISTS idx_detection_dedup  ON detection_rules(dedup_key);
            CREATE INDEX IF NOT EXISTS idx_detection_canon  ON detection_rules(is_canonical);
            CREATE INDEX IF NOT EXISTS idx_rule_atoms_value ON rule_atoms(value);
        """)

        # ── Migrations — safe to run on already-initialised databases ──
        _migrations = [
            "ALTER TABLE relationships ADD COLUMN evidence_text TEXT",
            "ALTER TABLE relationships ADD COLUMN evidence_label TEXT DEFAULT 'reported'",
            "ALTER TABLE jobs ADD COLUMN tlp_level TEXT",
            "ALTER TABLE jobs ADD COLUMN pap_level TEXT",
            # ADR-0010 — cross-corpus rule deduplication
            "ALTER TABLE detection_rules ADD COLUMN dedup_key TEXT DEFAULT ''",
            "ALTER TABLE detection_rules ADD COLUMN is_canonical INTEGER DEFAULT 1",
            "CREATE INDEX IF NOT EXISTS idx_detection_dedup ON detection_rules(dedup_key)",
            "CREATE INDEX IF NOT EXISTS idx_detection_canon ON detection_rules(is_canonical)",
            # ADR-0014 — observable-driven proposals. `platform` is derived from
            # the rule's logsource; rule_atoms is backfillable offline from
            # detection_rules.raw (scripts/build_rule_atoms.py), so an existing
            # database needs no corpus re-clone.
            "ALTER TABLE detection_rules ADD COLUMN platform TEXT DEFAULT ''",
            "CREATE INDEX IF NOT EXISTS idx_rule_atoms_value ON rule_atoms(value)",
            # ADR-0017 — provenance-based dedup. Populated on the next index
            # rebuild; dedupe_store falls back to ADR-0010 behaviour while the
            # table is absent or empty, so an existing database stays correct.
            "CREATE TABLE IF NOT EXISTS rule_related ("
            " rule_id TEXT NOT NULL, related_key TEXT NOT NULL, rel_type TEXT NOT NULL,"
            " PRIMARY KEY (rule_id, related_key, rel_type))",
            "CREATE INDEX IF NOT EXISTS idx_rule_related_key ON rule_related(related_key)",
            # ADR-0024 — run configuration snapshot, so a bundle can be
            # reproduced and attributed.  The relationship policy is a single
            # mutable row, so without this a bundle cannot be explained after the
            # policy changes: the 872 unlabelled edges in job 32b5475b were made
            # by pinned rules the policy no longer contains.
            "ALTER TABLE jobs ADD COLUMN run_config_json TEXT",
            # ADR-0022 — body size for the coverage selection UI, in a side table
            # (a column on detection_rules would sit after `raw` and cost 8.2s to
            # read). Written on ingest; an already-built store is backfilled
            # offline by scripts/backfill_rule_bytes.py — no corpus re-clone.
            "CREATE TABLE IF NOT EXISTS rule_bytes ("
            " rule_id TEXT PRIMARY KEY, bytes INTEGER NOT NULL DEFAULT 0)",
            # ADR-0028 — evidence for entities, kept apart from `context`.
            # `context` holds a summary the extractor writes: measured over 280
            # stored TTPs, only 36.8% of it can be found in the report, against
            # 79.4% for the verbatim quotes the relationship contract already
            # asks for.  These columns carry the quote and its resolved offset
            # so a technique can be located in the text it came from.
            "ALTER TABLE entities ADD COLUMN evidence_text TEXT",
            "ALTER TABLE entities ADD COLUMN evidence_label TEXT",
            "ALTER TABLE entities ADD COLUMN evidence_start INTEGER",
            # `evidence_start` alone does not delimit the quote.  `evidence_text`
            # is what the model wrote; the offsets are in report coordinates, and
            # `evidence_span._normalise` folds curly quotes and whitespace runs,
            # so the two differ in LENGTH.  Measured over 313 stored quotes, 68
            # (21.7%) had report_text[start:start+len(text)] != text — every one
            # of them a normalisation difference, not a wrong offset.  `locate()`
            # already returns the end; it was simply being dropped.
            "ALTER TABLE entities ADD COLUMN evidence_end INTEGER",
            # ADR-0031 — full-text index over rule title+description. Populated
            # offline by scripts/build_rule_text.py; brand evidence is simply
            # absent while the table is empty, exactly as proposals degrade
            # while the atom index is unbuilt. No corpus re-clone.
            "CREATE VIRTUAL TABLE IF NOT EXISTS rule_text USING fts5("
            " rule_id UNINDEXED, body)",
            # ADR-0032 — provenance for figure-derived evidence.  A side table
            # rather than columns on `jobs`, because `jobs.report_text` is a
            # large blob and a column added after it is paid for on every read
            # (the same reason ADR-0022 put rule body sizes in `rule_bytes`).
            #
            # `char_start`/`char_end` index into `jobs.report_text`, so a range
            # lookup answers "was this evidence read from an image?" for
            # entities, relationships and coverage alike — no per-entity
            # provenance column anywhere.
            "CREATE TABLE IF NOT EXISTS report_figures ("
            " id TEXT PRIMARY KEY,"
            " job_id TEXT NOT NULL,"
            " ordinal INTEGER NOT NULL,"
            " page INTEGER NOT NULL,"
            " bbox TEXT NOT NULL,"
            " kind TEXT NOT NULL,"
            " char_start INTEGER NOT NULL,"
            " char_end INTEGER NOT NULL,"
            " provider TEXT NOT NULL DEFAULT '',"
            " model TEXT NOT NULL DEFAULT '',"
            " sha256 TEXT NOT NULL DEFAULT '',"
            " UNIQUE (job_id, ordinal),"
            " FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE)",
            "CREATE INDEX IF NOT EXISTS idx_report_figures_span"
            " ON report_figures(job_id, char_start)",
            # ADR-0033 — the figure read cache, keyed on the crop bytes rather
            # than on the figure's position: re-ingesting a report, or A/B-ing
            # two models, must not pay for the same crop twice.  `prompt_version`
            # is in the key so a stored read is never served against a contract
            # it did not answer.  Not FK'd to jobs — a crop outlives the job that
            # first read it, which is the whole point.
            "CREATE TABLE IF NOT EXISTS figure_reads ("
            " sha256 TEXT NOT NULL,"
            " model TEXT NOT NULL,"
            " prompt_version INTEGER NOT NULL,"
            " read_json TEXT NOT NULL,"
            " created_at TEXT NOT NULL,"
            " PRIMARY KEY (sha256, model, prompt_version))",
            # CVE metadata fetched from CIRCL, cached here rather than in a second
            # SQLite file: same shape as figure_reads above — a cache of external
            # calls, keyed on the thing fetched, outliving the job that asked.
            # A row whose description AND cvss_score are both NULL is a remembered
            # miss, so an unknown CVE is not re-fetched on every run.
            "CREATE TABLE IF NOT EXISTS cve_cache ("
            " cve_id TEXT PRIMARY KEY,"
            " description TEXT,"
            " cvss_score REAL,"
            " cvss_vector TEXT,"
            " fetched_at TEXT NOT NULL)",
        ]
        for stmt in _migrations:
            try:
                conn.execute(stmt)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Column / index already exists — safe to skip
            except Exception as exc:
                # Unexpected migration error — log it but don't crash the server
                logger.warning(f"[db] Migration warning ({stmt[:60]}...): {exc}")


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
