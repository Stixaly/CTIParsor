import os
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

DB_PATH = Path(__file__).parent.parent / "cti_stix.db"
BACKUP_DIR = Path(__file__).parent.parent / "db_backups"
# RLock (not Lock) so the same thread can re-acquire inside nested with-blocks
# (e.g. set_job_status called from inside another _lock-protected section).
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
        # Limit WAL file size to prevent disk exhaustion
        conn.execute("PRAGMA wal_autocheckpoint=1000")  # Checkpoint every 1000 pages
        conn.execute("PRAGMA wal_max_size=100000000")  # 100MB max WAL size
        _local.conn = conn
    return conn


def backup_db() -> None:
    """
    Create a backup of the database file.

    Creates timestamped backups in db_backups/ directory.
    Keeps last 7 backups, deletes older ones.
    """
    import glob
    from datetime import datetime

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    # Create backup filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"cti_stix_{timestamp}.db"

    # Also backup WAL and SHM files if they exist
    wal_file = DB_PATH.with_suffix(".db-wal")
    shm_file = DB_PATH.with_suffix(".db-shm")

    try:
        # Copy main DB
        shutil.copy2(str(DB_PATH), str(backup_path))

        # Copy WAL file if exists
        if wal_file.exists():
            shutil.copy2(str(wal_file), str(backup_path) + "-wal")

        # Copy SHM file if exists
        if shm_file.exists():
            shutil.copy2(str(shm_file), str(backup_path) + "-shm")

        # Clean up old backups (keep last 7)
        backup_files = sorted(glob.glob(str(BACKUP_DIR / "cti_stix_*.db")), reverse=True)
        for old_backup in backup_files[7:]:
            try:
                os.remove(old_backup)
                # Also remove corresponding WAL/SHM backups
                os.remove(old_backup + "-wal")
                os.remove(old_backup + "-shm")
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
        """)

        # ── Migrations — safe to run on already-initialised databases ──
        _migrations = [
            "ALTER TABLE relationships ADD COLUMN evidence_text TEXT",
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
