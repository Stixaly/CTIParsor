"""Job-queue supervisor (ADR-0046).

Claims `queued` jobs from the `jobs` table, runs each in the isolated
subprocess that `api.worker._spawn_job` starts, heartbeats the rows it owns,
and requeues jobs whose lease expired.  One loop per process: the same loop
serves an API process in role `all` (a background thread, the host-install
default) and a worker container in role `worker` (foreground,
`python -m api.queue_loop`).  In role `api` no loop runs and the routes only
enqueue.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from api.db import emit_progress, get_conn, now_iso, set_job_status
from api.logging_config import get_logger, setup_logging

logger = get_logger(__name__)

HEARTBEAT_S = int(os.getenv("WORKER_HEARTBEAT_S", "30"))
LEASE_TIMEOUT_S = int(os.getenv("WORKER_LEASE_TIMEOUT_S", "180"))
POLL_S = float(os.getenv("WORKER_POLL_S", "2"))
DRAIN_S = int(os.getenv("WORKER_DRAIN_S", "60"))
ALIVE_FILE = Path(os.getenv("WORKER_ALIVE_FILE", "/tmp/ctiparsor-worker.alive"))
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
_VALID_ROLES = ("all", "api", "worker")

if LEASE_TIMEOUT_S < 3 * HEARTBEAT_S:
    logger.warning("A lease shorter than three heartbeats requeues jobs that are still running")


def role() -> str:
    """`all`, `api` or `worker` from CTIPARSOR_ROLE, read on every call.

    Empty means `all`; an unknown value is logged and treated as `all`, which
    is the behaviour a host install had before roles existed.
    """
    raw = os.getenv("CTIPARSOR_ROLE", "").strip().lower()
    if not raw:
        return "all"
    if raw not in _VALID_ROLES:
        logger.warning(f"Unknown CTIPARSOR_ROLE={raw!r}; falling back to 'all'")
        return "all"
    return raw


def count_queued() -> int:
    """How many jobs wait in the queue (0, with a warning, if the store is unreachable)."""
    try:
        conn = get_conn()
        cur = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='queued'")
        row = cur.fetchone()
        return int(row[0]) if row else 0
    except Exception as exc:
        logger.warning(f"Failed to count queued jobs: {exc}")
        return 0


def lease_cutoff(now: datetime | None = None) -> str:
    """The ISO timestamp before which a `heartbeat_at` means the lease has expired."""
    if now is None:
        now = datetime.now(timezone.utc)
    return (now - timedelta(seconds=LEASE_TIMEOUT_S)).isoformat()


def claim_next_queued(worker_id: str = WORKER_ID) -> tuple[str, str, str] | None:
    """Claim the oldest queued job for *worker_id*: (job_id, file_path, original_filename), or None.

    The claim is a conditional UPDATE with a rowcount check, atomic on SQLite
    (single writer) and on PostgreSQL (read committed re-evaluates the
    predicate, so a concurrent loser updates zero rows and retries).  A job
    whose uploaded file is gone is marked failed and skipped.
    """
    _MAX_CLAIM_ATTEMPTS = 10
    try:
        for _ in range(_MAX_CLAIM_ATTEMPTS):
            conn = get_conn()
            cur = conn.execute(
                "SELECT id, original_filename FROM jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                return None

            job_id, original_filename = row[0], row[1]
            now = now_iso()
            update_cur = conn.execute(
                "UPDATE jobs SET status='processing', worker_id=?, heartbeat_at=?, updated_at=? "
                "WHERE id=? AND status='queued'",
                (worker_id, now, now, job_id),
            )

            if update_cur.rowcount != 1:
                continue

            from api.worker import _upload_path_for

            file_path = _upload_path_for(job_id)
            if file_path is None:
                set_job_status(job_id, "failed")
                emit_progress(job_id, "done", {"status": "failed", "error": "uploaded file is missing"})
                continue

            # Every other status transition in this module pairs a DB write
            # with an emit_progress call; this one didn't, so a client polling
            # the SSE stream saw the queue wait end with no event -- the UI
            # kept showing stale "queued, position N" until the subprocess's
            # own first stage event arrived, which can be tens of seconds
            # away during a model cold start. No `stage` number: this isn't
            # one of the 5 pipeline stages, and ProgressModal.tsx uses a
            # present `stage` key to drive its 1-5 stage tracker.
            emit_progress(job_id, "stage", {"label": "Processing started"})
            return (job_id, file_path, original_filename)

        logger.warning("Failed to claim next queued job after 10 attempts")
        return None
    except Exception as exc:
        logger.error(f"Exception in claim_next_queued: {exc}")
        return None


def requeue_orphans(*, unconditional: bool = False) -> int:
    """Put orphaned `processing` jobs back in the queue; returns how many.

    Lease-based by default: only rows whose heartbeat is older than
    WORKER_LEASE_TIMEOUT_S (or missing) are touched, so a job another worker
    is running stays with it.  `unconditional=True` resets every `processing`
    row — correct only in role `all`, where no other process can be running one.
    """
    try:
        conn = get_conn()
        now = now_iso()
        if unconditional:
            where = "status='processing'"
            params: tuple = ()
        else:
            cutoff = lease_cutoff()
            where = "status='processing' AND (heartbeat_at IS NULL OR heartbeat_at < ?)"
            params = (cutoff,)

        # Read the affected ids first so each can get its own emit_progress
        # below -- every other status transition in this module pairs a DB
        # write with one, and without it a client polling a requeued job's
        # SSE stream sees it simply stop producing events across a restart
        # instead of an explicit signal that it is back in the queue.
        ids = [r[0] for r in conn.execute(f"SELECT id FROM jobs WHERE {where}", params).fetchall()]

        cur = conn.execute(
            f"UPDATE jobs SET status='queued', worker_id=NULL, heartbeat_at=NULL, updated_at=? "
            f"WHERE {where}",
            (now, *params),
        )
        count = cur.rowcount
        if count > 0:
            logger.info(
                f"Requeued {count} orphaned job(s) "
                f"({'unconditional' if unconditional else 'lease expired'})"
            )
            for jid in ids:
                emit_progress(jid, "stage", {"label": "Requeued after a restart"})
        return count
    except Exception as exc:
        logger.error(f"Exception in requeue_orphans: {exc}")
        return 0


def heartbeat(job_ids: Iterable[str], worker_id: str = WORKER_ID) -> int:
    """Stamp `heartbeat_at` on the `processing` rows this worker owns; returns how many."""
    ids = list(job_ids)
    if not ids:
        return 0
    try:
        conn = get_conn()
        placeholders = ",".join("?" * len(ids))
        cur = conn.execute(
            f"UPDATE jobs SET heartbeat_at=? WHERE status='processing' AND worker_id=? "
            f"AND id IN ({placeholders})",
            (now_iso(), worker_id, *ids),
        )
        return cur.rowcount
    except Exception as exc:
        logger.error(f"Exception in heartbeat: {exc}")
        return 0


def _default_spawn(job_id: str, file_path: str, original_filename: str, on_exit: Callable[[str], None]) -> Any:
    """Start the pipeline subprocess (api.worker._spawn_job); resolved late so tests can replace it."""
    from api.worker import _spawn_job

    return _spawn_job(job_id, file_path, original_filename, on_exit)


def touch_alive(path: Path | None = None) -> None:
    """Refresh the liveness file the container healthcheck watches; never raises."""
    try:
        (path or ALIVE_FILE).touch()
    except OSError:
        pass


class WorkerLoop:
    """Claims, spawns, heartbeats.

    Thread-safe: kick() is called from the request thread (role all), the poll
    thread and the watcher threads, and is serialised so a free slot is
    taken once.
    """

    def __init__(
        self,
        *,
        max_concurrent: int,
        worker_id: str = WORKER_ID,
        poll_s: float = POLL_S,
        heartbeat_s: float = HEARTBEAT_S,
        spawn: Callable[..., Any] | None = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.worker_id = worker_id
        self.poll_s = poll_s
        self.heartbeat_s = heartbeat_s
        self._handles: dict[str, Any] = {}
        self._lock = threading.Lock()
        # Serialises kick(): the poll thread, a request thread (role all) and
        # the watcher threads all call it, and has_slot()+claim must be one step.
        self._kick_lock = threading.Lock()
        self._stop = threading.Event()
        self._last_heartbeat = 0.0
        self._spawn = spawn

    @property
    def running_ids(self) -> list[str]:
        with self._lock:
            return list(self._handles.keys())

    @property
    def running_count(self) -> int:
        with self._lock:
            return len(self._handles)

    def has_slot(self) -> bool:
        return self.max_concurrent <= 0 or self.running_count < self.max_concurrent

    def kick(self) -> int:
        with self._kick_lock:
            return self._kick_locked()

    def _kick_locked(self) -> int:
        started = 0
        while self.has_slot() and not self._stop.is_set():
            claimed = claim_next_queued(self.worker_id)
            if claimed is None:
                break
            job_id, file_path, original_filename = claimed
            with self._lock:
                self._handles[job_id] = None
            try:
                handle = (self._spawn or _default_spawn)(job_id, file_path, original_filename, self._on_exit)
                with self._lock:
                    # Absent means the watcher already reported the exit (a
                    # subprocess can die before start() returns): keep it gone.
                    if job_id in self._handles:
                        self._handles[job_id] = handle
                started += 1
                logger.info(f"Started job {job_id}")
            except Exception as exc:
                with self._lock:
                    self._handles.pop(job_id, None)
                set_job_status(job_id, "failed")
                emit_progress(job_id, "done", {
                    "status": "failed", "error": f"could not start the pipeline process: {exc}",
                })
                logger.error(f"Failed to start job {job_id}: {exc}")
                continue
        return started

    def _on_exit(self, job_id: str) -> None:
        with self._lock:
            self._handles.pop(job_id, None)
        if not self._stop.is_set():
            try:
                self.kick()
            except Exception as exc:
                logger.error(f"Exception in _on_exit kick: {exc}")

    def heartbeat_if_due(self, now: float | None = None) -> bool:
        now = now or time.monotonic()
        if now - self._last_heartbeat >= self.heartbeat_s:
            heartbeat(self.running_ids, self.worker_id)
            self._last_heartbeat = now
            return True
        return False

    def run_once(self) -> int:
        # touch_alive() below is what the worker container's HEALTHCHECK
        # watches (a stale file after WORKER_POLL_S x ~60 means "wedged"). It
        # must not fire when a DB call above it failed -- e.g. a bad
        # DATABASE_URL, a firewalled Postgres, or a schema that was never
        # created -- or the container reports healthy forever while it can
        # never actually claim or process a job.
        db_ok = True
        try:
            requeue_orphans()
        except Exception as exc:
            logger.error(f"Exception in run_once requeue_orphans: {exc}")
            db_ok = False
        n = 0
        try:
            n = self.kick()
        except Exception as exc:
            logger.error(f"Exception in run_once kick: {exc}")
            db_ok = False
        try:
            self.heartbeat_if_due()
        except Exception as exc:
            logger.error(f"Exception in run_once heartbeat_if_due: {exc}")
            db_ok = False
        if not db_ok:
            logger.warning("run_once: not touching the alive file -- a DB call failed this cycle")
            return n
        try:
            touch_alive()
        except Exception as exc:
            logger.error(f"Exception in run_once touch_alive: {exc}")
        return n

    def run_forever(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.poll_s)

    def stop(self) -> None:
        self._stop.set()

    def drain(self, timeout_s: float) -> list[str]:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                if not self._handles:
                    return []
            time.sleep(0.5)
        with self._lock:
            return list(self._handles.keys())

    def terminate_and_requeue(self, job_ids: Iterable[str]) -> int:
        count = 0
        for job_id in job_ids:
            with self._lock:
                handle = self._handles.pop(job_id, None)
            if handle is not None:
                try:
                    handle.terminate()
                except Exception as exc:
                    logger.error(f"Failed to terminate handle for {job_id}: {exc}")
            try:
                conn = get_conn()
                cur = conn.execute(
                    "UPDATE jobs SET status='queued', worker_id=NULL, heartbeat_at=NULL, updated_at=? "
                    "WHERE id=? AND status='processing'",
                    (now_iso(), job_id),
                )
                if cur.rowcount > 0:
                    count += 1
            except Exception as exc:
                logger.error(f"Failed to requeue {job_id}: {exc}")
        if count > 0:
            logger.info(f"Terminated and requeued {count} job(s)")
        return count


_embedded: WorkerLoop | None = None
_embedded_thread: threading.Thread | None = None
_embedded_lock = threading.Lock()


def start_embedded(*, max_concurrent: int | None = None) -> WorkerLoop:
    """Start (once) the in-process loop of role `all` on a daemon thread and return it."""
    global _embedded, _embedded_thread
    with _embedded_lock:
        if _embedded is not None:
            return _embedded
        if max_concurrent is None:
            from api.worker import _MAX_CONCURRENT_JOBS

            max_concurrent = _MAX_CONCURRENT_JOBS
        _embedded = WorkerLoop(max_concurrent=max_concurrent)
        _embedded_thread = threading.Thread(target=_embedded.run_forever, name="queue-loop", daemon=True)
        _embedded_thread.start()
        return _embedded


def embedded() -> WorkerLoop | None:
    return _embedded


def stop_embedded(timeout_s: float = 5.0) -> None:
    """Stop the in-process loop and forget it (a no-op when none was started)."""
    global _embedded, _embedded_thread
    with _embedded_lock:
        if _embedded is not None:
            _embedded.stop()
        if _embedded_thread is not None:
            _embedded_thread.join(timeout=timeout_s)
        _embedded = None
        _embedded_thread = None


def main(argv: list[str] | None = None) -> int:
    """Entry point of a worker process (`python -m api.queue_loop`).

    Runs the loop until SIGTERM/SIGINT, then gives running reports
    WORKER_DRAIN_S to finish and requeues the rest.  `--once` runs a single
    pass and exits, for diagnostics and tests.
    """
    setup_logging()
    parser = argparse.ArgumentParser(description="Job-queue supervisor (role worker)")
    from api.worker import _MAX_CONCURRENT_JOBS

    parser.add_argument("--max-concurrent", type=int, default=_MAX_CONCURRENT_JOBS)
    parser.add_argument("--once", action="store_true", help="Run a single pass and exit")
    args = parser.parse_args(argv)

    logger.info(
        f"[queue] worker {WORKER_ID} starting: max_concurrent={args.max_concurrent}, "
        f"poll={POLL_S}s, heartbeat={HEARTBEAT_S}s, lease={LEASE_TIMEOUT_S}s"
    )

    loop = WorkerLoop(max_concurrent=args.max_concurrent)

    if args.once:
        loop.run_once()
        return 0

    def _signal_handler(signum: int, frame: Any) -> None:
        logger.info("[queue] stop requested")
        loop.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    loop.run_forever()

    still = loop.drain(DRAIN_S)
    if still:
        loop.terminate_and_requeue(still)
        logger.warning(f"Drain timeout: {len(still)} job(s) still running, requeued")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
