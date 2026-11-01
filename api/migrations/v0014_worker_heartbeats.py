"""Version 14 — every running queue loop is listed, idle or busy (ADR-0094 item 7).

`worker_heartbeats` holds one row per queue loop that runs now: the
`worker_id` it claims jobs with (`host:pid:hex`, api/queue_loop.py), its role
(`all`: the API's own loop; `worker`: `python -m api.queue_loop`), its
`max_concurrent`, the CTIParsor version it runs, when it started, and its last
heartbeat.  The loop writes its row at start and every WORKER_HEARTBEAT_S,
idle or busy, and deletes it when it stops cleanly; a row whose heartbeat is
older than an hour is deleted by any loop that runs (a worker that crashed).
GET /api/queue/status reads it.  Process state, not report data: no key to
`jobs`.  A new table, nothing else changes, so a worker of the previous
revision keeps running; it writes no row, and the route lists it from the
jobs it holds."""
from api.migrations import Migration, columns_exist, table_exists

MIGRATION = Migration(
    version=14,
    name="worker_heartbeats",
    store="jobs",
    description="worker_heartbeats: one row per running queue loop",
    is_applied=lambda conn: (
        table_exists(conn, "worker_heartbeats")
        and columns_exist(conn, "worker_heartbeats", "worker_id", "role", "max_concurrent", "app_version",
                          "started_at", "heartbeat_at")),
    statements=(
        "CREATE TABLE IF NOT EXISTS worker_heartbeats ("
        " worker_id TEXT PRIMARY KEY, role TEXT NOT NULL, max_concurrent INTEGER NOT NULL,"
        " app_version TEXT NOT NULL, started_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL)",
    ),
)
