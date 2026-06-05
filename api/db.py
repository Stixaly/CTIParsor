import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent.parent / "cti_stix.db"
# RLock (not Lock) so the same thread can re-acquire inside nested with-blocks
# (e.g. set_job_status called from inside another _lock-protected section).
_lock = threading.RLock()

# Per-thread connection cache — reuses the same connection within a thread
# instead of creating a new one on every get_conn() call.  Avoids the file
# handle leak that occurs when connections are opened but never explicitly
# closed (relying on GC instead).
_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """
    Return a per-thread SQLite connection, creating it on first access.

    Using thread-local storage means each worker thread (FastAPI, pipeline)
    gets exactly one connection for its lifetime — no new handles are opened
    per-request, and no handles are left unclosed when the caller's with-block
    exits (the context manager commits/rolls back but keeps the connection open
    for the next call on the same thread).

    PRAGMAs are set once per connection rather than on every call.
    """
    conn = getattr(_local, "conn", None)
    if conn is None:
        # timeout=30 prevents "database is locked" under concurrent requests
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        # Set once — WAL mode persists in the DB file after the first call
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn
    return conn


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
                print(f"[db] Migration warning ({stmt[:60]}…): {exc}")


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
