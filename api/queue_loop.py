"""Job-queue supervisor (ADR-0046).

Claims `queued` jobs from the `jobs` table, runs each in the isolated
subprocess that `api.worker._spawn_job` starts, heartbeats the rows it owns,
and requeues jobs whose lease expired.  It also keeps its own row in
`worker_heartbeats`, busy or idle, so that GET /api/queue/status lists every
loop that runs (ADR-0094 item 7).  One loop per process: the same loop
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
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from api.db import EVENT_DONE, EVENT_STAGE, emit_progress, get_conn, now_iso, set_job_status
from api.logging_config import get_logger, setup_logging
from pipeline import __version__
from pipeline.env_flags import env_float, env_int

logger = get_logger(__name__)

HEARTBEAT_S = env_int("WORKER_HEARTBEAT_S", default=30)
LEASE_TIMEOUT_S = env_int("WORKER_LEASE_TIMEOUT_S", default=180)
# A job whose lease expired is requeued while it has been claimed fewer times than this (ADR-0097 item 20).
JOB_MAX_ATTEMPTS = env_int("JOB_MAX_ATTEMPTS", default=3)
POLL_S = env_float("WORKER_POLL_S", default=2.0)
DRAIN_S = env_int("WORKER_DRAIN_S", default=60)
# How often to check for expired jobs (JOB_RETENTION_DAYS, api/routes/jobs.py).
# A DB query on every ~2s poll tick would be wasteful for something that only
# needs to run a few times a day; this is a separate, much coarser interval.
RETENTION_SWEEP_S = env_int("JOB_RETENTION_SWEEP_S", default=3600)
# /tmp is the container's own tmpfs; touch_alive never follows a symlink there.
ALIVE_FILE = Path(os.getenv("WORKER_ALIVE_FILE", "/tmp/ctiparsor-worker.alive"))  # noqa: S108 — see above
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
_VALID_ROLES = ("all", "api", "worker")
# A loop that stops cleanly deletes its worker_heartbeats row; one that crashed
# leaves it, listed `stale` by GET /api/queue/status.  Every running loop
# deletes, at each heartbeat, the rows silent for longer than this: twenty
# leases at the defaults, so a crash stays listed long after its jobs were
# requeued, and a worker that crashes over and over (a new id at each restart)
# leaves at most an hour of rows.  What happened before is in the logs.
WORKER_ROW_RETENTION_S = 3600

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


# The worker_id this loop wrote when it claimed the job being launched.  _kick_locked sets it around the
# spawn call; api.worker._spawn_job passes it to the child instead of the owner the row carries by then, and
# abandons the launch when the row is no longer this claim's (#491).
claimed_by: ContextVar[str | None] = ContextVar("claimed_by", default=None)


class ClaimLost(RuntimeError):
    """The job was reclaimed or requeued between its claim and its launch: the launch is abandoned."""


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
                "UPDATE jobs SET status='processing', worker_id=?, heartbeat_at=?, updated_at=?, "
                "attempts = attempts + 1 WHERE id=? AND status='queued'",
                (worker_id, now, now, job_id),
            )

            if update_cur.rowcount != 1:
                continue

            from api.worker import _upload_path_for

            file_path = _upload_path_for(job_id)
            if file_path is None:
                set_job_status(job_id, "failed")
                emit_progress(job_id, EVENT_DONE, {"status": "failed", "error": "uploaded file is missing"})
                continue

            # Every other status transition in this module pairs a DB write
            # with an emit_progress call; this one didn't, so a client polling
            # the SSE stream saw the queue wait end with no event -- the UI
            # kept showing stale "queued, position N" until the subprocess's
            # own first stage event arrived, which can be tens of seconds
            # away during a model cold start. No `stage` number: this isn't
            # one of the 5 pipeline stages, and ProgressModal.tsx uses a
            # present `stage` key to drive its 1-5 stage tracker.
            emit_progress(job_id, EVENT_STAGE, {"label": "Processing started"})
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

        # A job already claimed JOB_MAX_ATTEMPTS times is failed, not requeued
        # (ADR-0097 item 20).  Quarantine runs first: a row it fails has left
        # `processing`, so the requeue below cannot take it back.  Each UPDATE
        # is one statement, so the rows returned are exactly the rows it changed
        # (a SELECT before it could list a row another loop had just taken over).
        # Each changed row gets its own emit_progress below -- every other
        # status transition in this module pairs a DB write with one.
        quarantined = conn.execute(
            f"UPDATE jobs SET status='failed', worker_id=NULL, heartbeat_at=NULL, updated_at=? "
            f"WHERE {where} AND attempts >= ? RETURNING id, attempts",
            (now, *params, JOB_MAX_ATTEMPTS),
        ).fetchall()
        for row in quarantined:
            jid, attempts = row[0], row[1]
            message = f"quarantined after {attempts} attempts (JOB_MAX_ATTEMPTS)"
            logger.warning(f"Job {jid} {message}")
            emit_progress(jid, EVENT_DONE, {"status": "failed", "error": message})

        cur = conn.execute(
            f"UPDATE jobs SET status='queued', worker_id=NULL, heartbeat_at=NULL, updated_at=? "
            f"WHERE {where} AND attempts < ? RETURNING id",
            (now, *params, JOB_MAX_ATTEMPTS),
        )
        ids = [r[0] for r in cur.fetchall()]
        count = len(ids)
        if count > 0:
            logger.info(
                f"Requeued {count} orphaned job(s) "
                f"({'unconditional' if unconditional else 'lease expired'})"
            )
            for jid in ids:
                emit_progress(jid, EVENT_STAGE, {"label": "Requeued after a restart"})
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


def stamp_worker(worker_id: str, *, role: str, max_concurrent: int, started_at: str) -> bool:
    """Write this loop's row in worker_heartbeats, then delete the rows silent
    for WORKER_ROW_RETENTION_S.  Never raises: a failure is logged and returns
    False; the loop goes on claiming and running jobs, but stops touching its
    liveness file until a stamp succeeds again (WorkerLoop.run_once)."""
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO worker_heartbeats (worker_id, role, max_concurrent, app_version, started_at, heartbeat_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT (worker_id) DO UPDATE SET heartbeat_at = excluded.heartbeat_at",
            (worker_id, role, max_concurrent, __version__, started_at, now_iso()),
        )
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=WORKER_ROW_RETENTION_S)).isoformat()
        conn.execute("DELETE FROM worker_heartbeats WHERE heartbeat_at < ?", (cutoff,))
        return True
    except Exception as exc:
        logger.error(f"Exception in stamp_worker: {exc}")
        return False


def forget_worker(worker_id: str) -> None:
    """Delete a loop's worker_heartbeats row when it stops cleanly; never raises."""
    try:
        get_conn().execute("DELETE FROM worker_heartbeats WHERE worker_id=?", (worker_id,))
    except Exception as exc:
        logger.error(f"Exception in forget_worker: {exc}")


def _default_spawn(job_id: str, file_path: str, original_filename: str, on_exit: Callable[[str], None]) -> Any:
    """Start the pipeline subprocess (api.worker._spawn_job); resolved late so tests can replace it."""
    from api.worker import _spawn_job

    return _spawn_job(job_id, file_path, original_filename, on_exit)


def touch_alive(path: Path | None = None) -> None:
    """Refresh the liveness file the container healthcheck watches; never raises.

    Opened with O_NOFOLLOW: on a host install /tmp is shared, and another user's
    symlink at that name must not make the worker create or touch its target.
    """
    target = path or ALIVE_FILE
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.utime(fd if os.utime in os.supports_fd else target)
        finally:
            os.close(fd)
    except OSError:
        pass


class WorkerLoop:
    """Claims, spawns, heartbeats; keeps its worker_heartbeats row, busy or idle.

    Thread-safe: kick() is called from the request thread (role all), the poll
    thread and the watcher threads, and is serialised so a free slot is
    taken once.
    """

    def __init__(
        self,
        *,
        max_concurrent: int,
        worker_id: str = WORKER_ID,
        role: str = "worker",
        poll_s: float = POLL_S,
        heartbeat_s: float = HEARTBEAT_S,
        spawn: Callable[..., Any] | None = None,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.worker_id = worker_id
        self.role = role                    # `worker`, or `all` for the API's own loop
        self.started_at = now_iso()
        self.poll_s = poll_s
        self.heartbeat_s = heartbeat_s
        self._handles: dict[str, Any] = {}
        self._lock = threading.Lock()
        # Serialises kick(): the poll thread, a request thread (role all) and
        # the watcher threads all call it, and has_slot()+claim must be one step.
        self._kick_lock = threading.Lock()
        self._stop = threading.Event()
        # -inf, not 0.0: time.monotonic() counts from the boot, and a loop started
        # less than heartbeat_s after it must still stamp on its first pass.
        self._last_heartbeat = float("-inf")
        self._stamp_ok = True               # did the last stamp reach the database? (run_once)
        self._last_sweep = 0.0
        self._spawn = spawn

    @property
    def running_ids(self) -> list[str]:
        """The ids of the jobs that this loop runs now."""
        with self._lock:
            return list(self._handles.keys())

    @property
    def running_count(self) -> int:
        """The number of jobs that this loop runs now."""
        with self._lock:
            return len(self._handles)

    def has_slot(self) -> bool:
        """True when the loop may start another job: there is no limit, or fewer jobs run than max_concurrent."""
        return self.max_concurrent <= 0 or self.running_count < self.max_concurrent

    def kick(self) -> int:
        """Start queued jobs while slots are free, one at a time, and return how many were started."""
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
            token = claimed_by.set(self.worker_id)
            try:
                handle = (self._spawn or _default_spawn)(job_id, file_path, original_filename, self._on_exit)
                with self._lock:
                    # Absent means the watcher already reported the exit (a
                    # subprocess can die before start() returns): keep it gone.
                    if job_id in self._handles:
                        self._handles[job_id] = handle
                started += 1
                logger.info(f"Started job {job_id}")
            except ClaimLost as exc:
                # Another loop holds the job now: its status is theirs to write, not this launch's to fail.
                with self._lock:
                    self._handles.pop(job_id, None)
                logger.warning(f"Launch abandoned for job {job_id}: {exc}")
                continue
            except Exception as exc:
                with self._lock:
                    self._handles.pop(job_id, None)
                set_job_status(job_id, "failed")
                emit_progress(job_id, EVENT_DONE, {
                    "status": "failed", "error": f"could not start the pipeline process: {exc}",
                })
                logger.error(f"Failed to start job {job_id}: {exc}")
                continue
            finally:
                claimed_by.reset(token)
        return started

    def _on_exit(self, job_id: str) -> None:
        with self._lock:
            self._handles.pop(job_id, None)
        if not self._stop.is_set():
            try:
                self.kick()
            except Exception as exc:
                logger.error(f"Exception in _on_exit kick: {exc}")

    def stamp(self) -> bool:
        """Write this loop's worker_heartbeats row (stamp_worker)."""
        return stamp_worker(self.worker_id, role=self.role, max_concurrent=self.max_concurrent,
                            started_at=self.started_at)

    def forget(self) -> None:
        """Delete this loop's worker_heartbeats row: it stopped cleanly."""
        forget_worker(self.worker_id)

    def heartbeat_if_due(self, now: float | None = None) -> bool:
        """Send the heartbeat for the jobs this loop runs when its period has passed or the last stamp failed. Return
        True when it sent one."""
        now = now or time.monotonic()
        # Retry on the next tick while the last stamp failed: a transient DB
        # error must not silence the liveness refresh for a whole period.
        if not self._stamp_ok or now - self._last_heartbeat >= self.heartbeat_s:
            heartbeat(self.running_ids, self.worker_id)
            # A loop asked to stop writes no row: forget() may already have
            # deleted it (stop_embedded waits 5 s for the thread, then forgets).
            if not self._stop.is_set():
                self._stamp_ok = self.stamp()
            if self._stamp_ok or self._stop.is_set():
                self._last_heartbeat = now
            return True
        return False

    def sweep_if_due(self, now: float | None = None) -> int:
        """Run the job-retention sweep at most once per RETENTION_SWEEP_S.

        A no-op call when JOB_RETENTION_DAYS=0 (the default) still costs the
        monotonic-clock check but nothing else -- sweep_expired_jobs() returns
        immediately without touching the DB.
        """
        now = now or time.monotonic()
        if now - self._last_sweep < RETENTION_SWEEP_S:
            return 0
        self._last_sweep = now
        from api.routes.jobs import sweep_expired_jobs

        return sweep_expired_jobs()

    def run_once(self) -> int:
        # touch_alive() below is what the worker container's HEALTHCHECK
        # watches (a stale file after WORKER_POLL_S x ~60 means "wedged"). It
        # must not fire while the job store does not answer -- a bad
        # DATABASE_URL, a firewalled Postgres, a schema that was never
        # created -- or the container reports healthy forever while it can
        # never claim or process a job.  The calls below log their own
        # database errors and return (requeue_orphans, claim_next_queued,
        # heartbeat, stamp_worker), so the signal is the last stamp: while it
        # failed, no touch.  A stamp runs every heartbeat_s, so an outage turns
        # the container unhealthy a few minutes later, and the first good
        # stamp after it makes the touches resume.  An exception that reaches
        # this method skips the touch too.
        """One pass of the loop: requeue the orphaned jobs, start queued jobs while slots are free, and heartbeat. The
        alive file is touched only while the database answers. Return the number of jobs started."""
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
        if not self._stamp_ok:
            db_ok = False
        # Housekeeping, not liveness: a sweep failure is logged (inside
        # sweep_expired_jobs/sweep_if_due) but must not mark the worker
        # unhealthy or skip touch_alive the way a claim/heartbeat failure does.
        try:
            self.sweep_if_due()
        except Exception as exc:
            logger.error(f"Exception in run_once sweep_if_due: {exc}")
        if not db_ok:
            logger.warning("run_once: not touching the alive file -- a DB call failed (this pass, or the last stamp)")
            return n
        try:
            touch_alive()
        except Exception as exc:
            logger.error(f"Exception in run_once touch_alive: {exc}")
        return n

    def run_forever(self) -> None:
        """Run run_once every poll_s seconds until stop() is called."""
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.poll_s)

    def stop(self) -> None:
        """Ask run_forever to return after its current pass."""
        self._stop.set()

    def drain(self, timeout_s: float) -> list[str]:
        """Wait up to timeout_s seconds for the running jobs to finish, and return the ids that are still running."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._lock:
                if not self._handles:
                    return []
            time.sleep(0.5)
        with self._lock:
            return list(self._handles.keys())

    def terminate_and_requeue(self, job_ids: Iterable[str]) -> int:
        """Requeue the given jobs of this loop without counting the attempt, then terminate their processes. Return the
        number of jobs requeued."""
        count = 0
        for job_id in job_ids:
            with self._lock:
                handle = self._handles.pop(job_id, None)
            # Requeue FIRST, conditioned on the current lease owner.  Clearing
            # worker_id before the SIGTERM neutralizes the subprocess watcher's
            # _finalize_job(jid, "failed", owner_worker_id), which would
            # otherwise freeze the job as failed the instant the signal lands.
            # A job already taken over by another worker (worker_id no longer
            # ours) is left untouched.
            try:
                conn = get_conn()
                cur = conn.execute(
                    # A clean stop is not a failure of the job: the attempt its claim counted is given back
                    # (ADR-0097 item 20). Only a lost lease (requeue_orphans) keeps the attempt.
                    "UPDATE jobs SET status='queued', worker_id=NULL, heartbeat_at=NULL, updated_at=?, "
                    "attempts = GREATEST(attempts - 1, 0) WHERE id=? AND status='processing' AND worker_id=?",
                    (now_iso(), job_id, self.worker_id),
                )
                if cur.rowcount > 0:
                    count += 1
            except Exception as exc:
                logger.error(f"Failed to requeue {job_id}: {exc}")
            if handle is not None:
                try:
                    handle.terminate()
                    handle.join(timeout=5)
                except Exception as exc:
                    logger.error(f"Failed to terminate handle for {job_id}: {exc}")
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
        _embedded = WorkerLoop(max_concurrent=max_concurrent, role="all")
        _embedded_thread = threading.Thread(target=_embedded.run_forever, name="queue-loop", daemon=True)
        _embedded_thread.start()
        return _embedded


def embedded() -> WorkerLoop | None:
    """The loop that start_embedded started in this process, or None when none was started."""
    return _embedded


def stop_embedded(timeout_s: float = 5.0) -> None:
    """Stop the in-process loop, delete its worker_heartbeats row and forget it
    (a no-op when none was started)."""
    global _embedded, _embedded_thread
    with _embedded_lock:
        if _embedded is not None:
            _embedded.stop()
        if _embedded_thread is not None:
            _embedded_thread.join(timeout=timeout_s)
        if _embedded is not None:
            _embedded.forget()
        _embedded = None
        _embedded_thread = None


def main(argv: list[str] | None = None) -> int:
    """Entry point of a worker process (`python -m api.queue_loop`).

    Runs the loop until SIGTERM/SIGINT, then gives running reports
    WORKER_DRAIN_S to finish, requeues the rest and deletes its
    worker_heartbeats row.  `--once` runs a single pass and exits, for
    diagnostics and tests; it deletes its row too.
    """
    setup_logging()
    # A bad STIX_TLP stops the worker here, not at its first bundle (ADR-0073).
    from pipeline.stage4_stix_mapping import tlp_default
    logger.info("[queue] default TLP: %s", tlp_default())
    # Likewise a bad ATTACK_RELEASE (ADR-0087), which this call fixes for the process.
    from pipeline import attack_data
    logger.info("[queue] ATT&CK release: %s", attack_data.current().version)
    parser = argparse.ArgumentParser(description="Job-queue supervisor (role worker)")
    from api.worker import _MAX_CONCURRENT_JOBS

    parser.add_argument("--max-concurrent", type=int, default=_MAX_CONCURRENT_JOBS)
    parser.add_argument("--once", action="store_true", help="Run a single pass and exit")
    args = parser.parse_args(argv)

    # Bring the schema to this code's version before taking any job (ADR-0077).
    # Under the migration lock: whichever of the API and the workers starts
    # first migrates, the others wait and find nothing left to do.
    from api.db import init_db
    init_db()
    # The files of deleted jobs that a previous run could not remove (#724).
    from api.routes.jobs import retry_pending_cleanups
    retry_pending_cleanups()

    logger.info(
        f"[queue] worker {WORKER_ID} starting: max_concurrent={args.max_concurrent}, "
        f"poll={POLL_S}s, heartbeat={HEARTBEAT_S}s, lease={LEASE_TIMEOUT_S}s"
    )

    loop = WorkerLoop(max_concurrent=args.max_concurrent)

    if args.once:
        loop.run_once()
        loop.forget()
        return 0

    def _signal_handler(signum: int, frame: Any) -> None:
        logger.info("[queue] stop requested")
        loop.stop()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    try:
        loop.run_forever()

        still = loop.drain(DRAIN_S)
        if still:
            loop.terminate_and_requeue(still)
            logger.warning(f"Drain timeout: {len(still)} job(s) still running, requeued")
    finally:
        loop.forget()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
