"""
Background worker — runs a job through pipeline/orchestrator.py (ADR-0059) in
its own subprocess, with the hooks that tie it to the job store: progress
events, the lease, persistence and Stage 3 crash-resume.
"""
import json
import multiprocessing as mp
import os
import re
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from uuid import uuid4

# Ensure project root is on sys.path so pipeline imports work
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Initialize logging
from api.logging_config import get_logger

logger = get_logger(__name__)

from api.db import _lock, backup_db, emit_progress, get_conn, now_iso, set_job_status
from api.paths import output_dir, uploads_dir
from pipeline.env_flags import env_int
from pipeline.orchestrator import (
    Document,
    FileCheckpoint,
    Hooks,
    RunAborted,
    RunOptions,
    build_bundle,
    load_file_bytes,
    lookup_cves,
    run_document,
)

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Worker concurrency and timeout limits
# ---------------------------------------------------------------------------
# Maximum execution time per job in seconds (0 = unlimited)
_MAX_JOB_TIMEOUT = env_int("WORKER_JOB_TIMEOUT", default=1800)  # 30 minutes
# Maximum concurrent jobs (each runs in its own subprocess)
_MAX_CONCURRENT_JOBS = env_int("WORKER_MAX_CONCURRENT", default=10)
# Maximum number of jobs allowed to sit in the queue (0 = unbounded).  Beyond
# this the upload is refused with an explicit error instead of accepting work
# the server has no intention of doing.
_QUEUE_MAX_DEPTH = env_int("API_QUEUE_MAX_DEPTH", default=50)

# Note: WORKER_MAX_MEMORY_MB is no longer used.  RLIMIT_AS is not set because
# it limits virtual address space (not physical RAM), which breaks dlopen() for
# ML libraries that memory-map large .so files.  Physical memory protection is
# provided by subprocess isolation + the OS OOM killer instead.

# The concurrency cap (_MAX_CONCURRENT_JOBS) is enforced by the queue loop in
# api/queue_loop.py, which counts the subprocesses it started (ADR-0046).


def _current_owner(job_id: str) -> str | None:
    """The `worker_id` this job's row carries right now, or None.

    Read once at the start of `_run_pipeline` so the terminal write can later
    confirm nothing reclaimed the job in between (see `_finalize_job`)."""
    with get_conn() as conn:
        row = conn.execute("SELECT worker_id FROM jobs WHERE id=?", (job_id,)).fetchone()
    return row["worker_id"] if row else None


def _finalize_job(
    job_id: str, status: str, owner_worker_id: str | None, *, bundle_json: str | None = None,
    ledger_json: str | None = None,
) -> bool:
    """Set a job's terminal status, but only if `owner_worker_id` still owns it.

    A job's lease can be reclaimed by another worker (api/queue_loop.py's
    lease-based requeue_orphans) while this subprocess is still running --
    CPU starvation on a loaded host can delay the parent's heartbeat past
    WORKER_LEASE_TIMEOUT_S even though this subprocess is alive and about to
    finish. Without this check, a stale subprocess's result could silently
    overwrite whatever the worker that now owns the job writes. Returns False
    (and leaves the row untouched) when the row's worker_id no longer matches
    -- the caller should treat its own result as discarded, not applied.

    `owner_worker_id=None` means no lease was recorded when this run started
    (e.g. a job run outside the queue loop, as most tests do) -- the update
    always applies in that case, matching the historical unconditional write.

    `ledger_json` is written with the bundle it describes (ADR-0061), never
    on its own: a ledger left over from an earlier build would misreport this one.
    """
    with _lock:
        with get_conn() as conn:
            if owner_worker_id is None:
                if bundle_json is not None:
                    conn.execute(
                        "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, status=?, "
                        "updated_at=? WHERE id=?",
                        (bundle_json, ledger_json, status, now_iso(), job_id),
                    )
                else:
                    conn.execute(
                        "UPDATE jobs SET status=?, updated_at=? WHERE id=?",
                        (status, now_iso(), job_id),
                    )
                conn.commit()
                return True
            if bundle_json is not None:
                cur = conn.execute(
                    "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, status=?, updated_at=? "
                    "WHERE id=? AND worker_id=?",
                    (bundle_json, ledger_json, status, now_iso(), job_id, owner_worker_id),
                )
            else:
                cur = conn.execute(
                    "UPDATE jobs SET status=?, updated_at=? WHERE id=? AND worker_id=?",
                    (status, now_iso(), job_id, owner_worker_id),
                )
            conn.commit()
            updated = (cur.rowcount or 0) > 0
    if not updated:
        logger.warning(
            f"[Worker] job {job_id} was reclaimed by another worker before this "
            f"subprocess (worker_id={owner_worker_id}) could finalize "
            f"status={status!r} - discarding this result"
        )
    return updated


def bundle_output_path(job_id: str, report_name: str) -> Path:
    """Per-job path for the exported STIX bundle file.

    The job_id is part of the filename so two uploads that share the same source
    filename (e.g. two different "report.pdf" submissions) don't overwrite each
    other's exported bundle — and deleting one job doesn't clobber the other's
    file on disk.  The DB-stored bundle_json was always per-job; only the
    on-disk export collided.
    """
    return output_dir() / f"{report_name}_{job_id}_bundle.json"


def _ttp_ids_covered(llm_result) -> tuple[set[str], set[str]]:
    """Return (ids, parents) already covered by the normalized LLM TTP set.

    ``llm_result.ttps`` is Stage 3c's output: semantic findings are *already*
    merged into it and parent techniques already subsumed.  Re-persisting the
    raw Stage 2c entities on top therefore double-counts every technique both
    stages found — which is why the review UI showed 65 TTPs for a report whose
    bundle contained 51.

    ids     — canonical ATT&CK ids present (upper-case)
    parents — parents of any sub-technique present (T1027.004 → T1027), so the
              less-precise parent is not reintroduced alongside its child.
    """
    ids = {
        t.mitre_id.upper()
        for t in getattr(llm_result, "ttps", []) or []
        if getattr(t, "mitre_id", None)
    }
    parents = {i.split(".")[0] for i in ids if "." in i}
    return ids, parents


def _save_entities(job_id: str, raw_entities, llm_result, report_text: str = "") -> None:
    """Persist Stage 2 IoCs, Stage 2b gazetteer, and Stage 3 LLM entities to the DB.

    TTPs additionally carry the verbatim quote the extractor was asked for
    (ADR-0028) and its resolved offset into `report_text`.  An unlocatable quote
    stores a NULL offset and demotes the grade — it never drops the technique:
    99.4% of unlocatable evidence was measured to be paraphrase of real report
    content rather than invention.
    """
    _covered_ids, _covered_parents = _ttp_ids_covered(llm_result)

    rows_ioc = []
    for e in raw_entities:
        # Use the source field from RawEntity (ioc | gazetteer) so provenance is tracked
        source = getattr(e, "source", "ioc")

        # Skip a raw TTP the normalized LLM set already covers (same id, or the
        # parent of a sub-technique it contains) so the review UI matches the
        # bundle instead of listing the same technique once per source.
        if e.entity_type.value == "ttp" and getattr(e, "mitre_id", None):
            _mid = e.mitre_id.upper()
            if _mid in _covered_ids or _mid in _covered_parents:
                continue

        rows_ioc.append((
            str(uuid4()), job_id,
            e.value, e.entity_type.value,
            e.context, e.confidence,
            e.mitre_id, None, source,
        ))

    # Deliberately heterogeneous: ordinary rows carry 9 fields, TTP rows 13,
    # and they are padded to a common width just before the insert below.
    # The NER stages drop denied names at their own output (ADR-0052); the
    # LLM's name lists are the one source that reaches the store without
    # passing through a stage, so they are filtered here.
    from pipeline.overrides import is_denied

    rows_llm: list[tuple] = []
    for name in llm_result.malware_families:
        if not is_denied(name, "malware"):
            rows_llm.append((str(uuid4()), job_id, name, "malware", "", 0.9, None, None, "llm"))
    for name in llm_result.threat_actors:
        if not is_denied(name, "threat_actor"):
            rows_llm.append((str(uuid4()), job_id, name, "threat_actor", "", 0.9, None, None, "llm"))
    for name in llm_result.tools:
        if not is_denied(name, "tool"):
            rows_llm.append((str(uuid4()), job_id, name, "tool", "", 0.9, None, None, "llm"))
    if llm_result.campaign_name and not is_denied(llm_result.campaign_name, "campaign"):
        rows_llm.append((str(uuid4()), job_id, llm_result.campaign_name, "campaign", "", 0.9, None, None, "llm"))
    # ADR-0028 — resolve each TTP quote to an offset in the report.
    from pipeline.evidence_span import locate

    _ttp_evidence: dict[int, tuple[str | None, str | None, int | None, int | None]] = {}
    for _i, ttp in enumerate(llm_result.ttps):
        _quote = (getattr(ttp, "evidence_text", None) or "").strip()
        _label = getattr(ttp, "evidence_label", None)
        _label = getattr(_label, "value", _label) or "reported"
        _start = None
        _end = None
        if _quote and report_text:
            try:
                _span = locate(_quote, report_text)
            except Exception:   # locating must never fail a job
                _span = None
            if _span is not None:
                # BOTH ends. `evidence_text` is the model's wording and
                # `_normalise` folds curly quotes and whitespace runs, so
                # `start + len(evidence_text)` does not delimit the quote —
                # measured wrong for 68 of 313 stored TTPs. The span does.
                _start = _span.start
                _end = _span.end
            else:
                # The quote is not in the document. Demote one grade rather than
                # drop the technique — see the docstring.
                _label = "inferred" if _label in ("observed", "reported") else _label
        _ttp_evidence[_i] = (_quote or None, _label, _start, _end)

    for _i, ttp in enumerate(llm_result.ttps):
        _ev_text, _ev_label, _ev_start, _ev_end = _ttp_evidence[_i]
        rows_llm.append((
            str(uuid4()), job_id, ttp.technique_name, "ttp",
            ttp.description, 0.9, ttp.mitre_id, None, "llm",
            _ev_text, _ev_label, _ev_start, _ev_end,
        ))

    rows_rel = []
    for rel in llm_result.relationships:
        # evidence_label is an EvidenceLabel enum on the model — store its value
        _label = (
            getattr(rel.evidence_label, "value", rel.evidence_label)
            if getattr(rel, "evidence_label", None) else "reported"
        )
        # Dates as the source states them (ADR-0063); start_time/stop_time
        # stay NULL — the export decides the native bounds at build time.
        from pipeline.temporal import times_to_json
        # Stored accepted, as they always were — but as the pipeline's
        # default, not anyone's decision (ADR-0058).
        rows_rel.append((
            str(uuid4()), job_id,
            rel.source_value, rel.relationship_type, rel.target_value,
            rel.confidence, 1, rel.evidence_text, _label,
            times_to_json(list(getattr(rel, "times", None) or [])),
            "default",
        ))

    with _lock:
        with get_conn() as conn:
            # Only TTP rows carry evidence (ADR-0028); every other row is padded
            # here rather than at each of the six places they are built.
            _entity_rows = [
                r if len(r) == 13 else (*r, None, None, None, None)
                for r in rows_ioc + rows_llm
            ]
            # ON CONFLICT DO NOTHING is the portable spelling of INSERT OR IGNORE
            # (SQLite 3.24+ and PostgreSQL, ADR-0045).
            conn.executemany(
                "INSERT INTO entities "
                "(id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source,"
                "evidence_text,evidence_label,evidence_start,evidence_end) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT (id) DO NOTHING",
                _entity_rows,
            )
            conn.executemany(
                "INSERT INTO relationships "
                "(id,job_id,source_value,relationship_type,target_value,"
                "confidence,accepted,evidence_text,evidence_label,times_json,"
                "decision_origin) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT (id) DO NOTHING",
                rows_rel,
            )
            conn.commit()


def _apply_auto_accept(job_id: str) -> None:
    """Accept the job's high-confidence entities server-side (ADR-0058).

    This used to happen in the browser, the first time anyone opened the
    review page, through the same PATCH an analyst's click used — so the
    store could not tell the two apart.  A failure here leaves the rows
    pending, which is safe: it must never fail the job.
    """
    from pipeline.decisions import apply_auto_accept

    try:
        with _lock:
            with get_conn() as conn:
                counts = apply_auto_accept(conn, job_id, now_iso())
        logger.info(
            f"[Worker] auto-accept: {counts['accepted']} entities accepted, "
            f"{counts['control_sample']} left pending as control sample"
        )
    except Exception as exc:
        logger.warning(f"[Worker] auto-accept skipped: {exc}")


def _load_policy() -> dict | None:
    """The saved relationship policy, or None when none has been saved (or the
    row cannot be read — a job never fails over its policy)."""
    from api.db import load_relationship_policy
    try:
        return load_relationship_policy()
    except Exception as exc:
        logger.warning(f"[Worker] relationship policy not read, building without one: {exc}")
        return None


class _WorkerHooks(Hooks):
    """The worker's side of a run (pipeline/orchestrator.py): the job row in
    PostgreSQL, progress events, the lease, the timeout, Stage 3 crash-resume."""

    def __init__(self, job_id: str, owner_worker_id: str | None, started: float):
        self.job_id = job_id
        self.owner = owner_worker_id
        self.started = started
        # output/{job_id}_stage3.ckpt.json — a lingering file always means the
        # previous run crashed mid-Stage 3.
        self.checkpoint = FileCheckpoint(output_dir() / f"{job_id}_stage3.ckpt.json", job_id)

    def progress(self, event: str, data: dict) -> None:
        emit_progress(self.job_id, event, data)

    def check_timeout(self) -> None:
        elapsed = time.monotonic() - self.started
        if _MAX_JOB_TIMEOUT > 0 and elapsed > _MAX_JOB_TIMEOUT:
            raise TimeoutError(f"Job timeout exceeded: {elapsed:.0f}s > {_MAX_JOB_TIMEOUT}s")

    def text_ready(self, text: str, figure_spans: list, figure_provider: str) -> None:
        with _lock:
            with get_conn() as conn:
                conn.execute("UPDATE jobs SET report_text=?, updated_at=? WHERE id=?",
                             (text, now_iso(), self.job_id))
                conn.commit()
        # Figure provenance is written only after report_text is stored: the
        # spans index into it, and a row pointing at text that was never saved
        # is worse than no row.
        if figure_spans:
            from pipeline.figure_store import save_spans
            n = save_spans(self.job_id, figure_spans, figure_provider)
            logger.info(f"[Stage 1f] {n} figure spans recorded")

    def extraction_ready(self, entities, llm_result, text: str) -> None:
        # _finalize_job's ownership check only guards the terminal write.
        # Saving entities and the LLM result are the first hard-to-undo writes
        # of the run -- and Stage 3's LLM calls are the largest window for a
        # lease to expire and be reclaimed -- so re-check ownership here and
        # abandon the run rather than land a duplicate set of entities under a
        # job another worker now owns.
        if self.owner is not None and _current_owner(self.job_id) != self.owner:
            logger.warning(
                f"[Worker] job {self.job_id} was reclaimed by another worker before "
                f"Stage 3 results could be saved (worker_id={self.owner}) - discarding this run"
            )
            raise RunAborted
        _save_entities(self.job_id, entities, llm_result, report_text=text)
        _apply_auto_accept(self.job_id)
        # Persist the LLM result for finalize.
        with _lock:
            with get_conn() as conn:
                conn.execute("UPDATE jobs SET llm_result_json=?, updated_at=? WHERE id=?",
                             (llm_result.model_dump_json(), now_iso(), self.job_id))
                conn.commit()

    def policy(self) -> dict | None:
        return _load_policy()

    def policy_used(self, policy: dict | None) -> None:
        # Record the configuration this bundle was built under (ADR-0024),
        # stamped right after the policy is read, so the snapshot is the policy
        # actually applied rather than whatever the row holds when someone asks.
        try:
            from api.run_config import build_run_config
            rc = json.dumps(build_run_config(policy))
            with _lock:
                with get_conn() as conn:
                    conn.execute("UPDATE jobs SET run_config_json=?, updated_at=? WHERE id=?",
                                 (rc, now_iso(), self.job_id))
                    conn.commit()
        except Exception as exc:
            logger.warning(f"[run-config] not recorded for job {self.job_id}: {exc}")


def _record_stage_report(job_id: str, stages: list[dict]) -> None:
    """Add which stages ran, were skipped or failed to the job's run config
    (ADR-0059), so a bundle says what produced it."""
    try:
        with _lock:
            with get_conn() as conn:
                row = conn.execute("SELECT run_config_json FROM jobs WHERE id=?", (job_id,)).fetchone()
                rc = json.loads(row["run_config_json"]) if row and row["run_config_json"] else {}
                # "stages" is already taken: the models each stage could load.
                rc["stage_report"] = stages
                conn.execute("UPDATE jobs SET run_config_json=? WHERE id=?", (json.dumps(rc), job_id))
                conn.commit()
    except Exception as exc:
        logger.warning(f"[run-config] stage report not recorded for job {job_id}: {exc}")


def _run_pipeline(job_id: str, file_path: str, original_filename: str) -> None:
    """
    Run the full pipeline for a job (pipeline/orchestrator.py, ADR-0059) with
    the worker's hooks: timeout, lease, persistence, progress, crash-resume.
    """
    # Slot acquisition belongs to the parent process (run_pipeline_async); this
    # subprocess holds its own fresh copy of the counter, so checking here would
    # always pass and the check that used to live here was dead code.
    start_time = time.monotonic()
    _owner_worker_id: str | None = None

    try:
        # RLIMIT_AS (virtual address space) is intentionally NOT set here.
        #
        # A modern Python ML process maps 8–20 GB of virtual address space through
        # dlopen() / mmap() for shared libraries (scipy, torch, transformers .so
        # files), numpy arrays, and HuggingFace memory-mapped model weights — even
        # when physical RAM usage is only 2–4 GB.  Setting RLIMIT_AS too low causes
        # dlopen() to fail with ENOMEM ("failed to map segment from shared object"),
        # which is a hard import error that silently breaks entire pipeline stages.
        #
        # Physical-memory protection is provided by two other mechanisms:
        #   1. Subprocess isolation — a crash (std::bad_alloc → SIGABRT, or the OS
        #      OOM killer → SIGKILL) only terminates the worker subprocess.  The
        #      parent's watcher thread detects exit code ≠ 0 and writes
        #      status=failed so the frontend updates immediately.
        #   2. WORKER_JOB_TIMEOUT — jobs that run too long are cancelled via
        #      _WorkerHooks.check_timeout.
        #
        # If you still need a hard memory cap (e.g. on a shared server), use
        # systemd's MemoryMax= or Docker's --memory flag at the container level
        # rather than RLIMIT_AS inside Python.

        set_job_status(job_id, "processing")
        _owner_worker_id = _current_owner(job_id)

        # TLP / PAP markings selected at upload time.
        with get_conn() as conn:
            row = conn.execute("SELECT tlp_level, pap_level FROM jobs WHERE id=?", (job_id,)).fetchone()
        document = Document(
            file_path=file_path,
            original_filename=original_filename,
            tlp_level=row["tlp_level"] if row else None,
            pap_level=row["pap_level"] if row else None,
        )
        document.output_path = str(bundle_output_path(job_id, document.report_name))

        result = run_document(document, RunOptions.from_env(),
                              _WorkerHooks(job_id, _owner_worker_id, start_time))
        _record_stage_report(job_id, result.stage_report())
        if result.bundle is None:
            raise RuntimeError("the run produced no bundle (Stage 4 did not run)")

        bundle_json = result.bundle.serialize(pretty=True)
        ledger_json = json.dumps(result.ledger) if result.ledger is not None else None
        if not _finalize_job(job_id, "for_review", _owner_worker_id,
                             bundle_json=bundle_json, ledger_json=ledger_json):
            return

        emit_progress(job_id, "done", {"status": "for_review"})

        # Backup database after successful processing
        try:
            backup_db()
            logger.info(f"[Worker] Database backup completed for job {job_id}")
        except Exception as e:
            logger.error(f"[Worker] Database backup failed: {e}")

    except RunAborted:
        return
    except TimeoutError as exc:
        error_msg = str(exc)
        if _finalize_job(job_id, "failed", _owner_worker_id):
            emit_progress(job_id, "done", {"status": "failed", "error": error_msg})
        logger.error(f"[Worker TIMEOUT] job {job_id}: {error_msg}")
    except Exception as exc:
        import traceback
        error_msg = traceback.format_exc()
        if _finalize_job(job_id, "failed", _owner_worker_id):
            emit_progress(job_id, "done", {"status": "failed", "error": str(exc)})
        logger.error(f"[Worker ERROR] job {job_id}: {error_msg}")
    finally:
        # No need to reset RLIMIT_AS — this subprocess is about to exit.  The
        # parent's watcher thread reports the exit to the queue loop.
        logger.info(f"[Worker] Subprocess finished for job {job_id}")


def _subprocess_entry(job_id: str, file_path: str, original_filename: str) -> None:
    """
    Entry point for the isolated worker subprocess.

    This function runs inside a fresh Python interpreter (mp.get_context("spawn")).
    Setting thread-count env vars here — before any ML library import — limits the
    number of OpenMP/MKL worker threads each model spawns, which is the primary
    lever for reducing peak resident memory on CPU-only inference.

    RLIMIT_AS is applied inside _run_pipeline; it now correctly limits only this
    subprocess, not the uvicorn process.
    """
    # ── Thread-count caps ────────────────────────────────────────────────────
    # Each OpenMP worker allocates its own BLAS workspace.  2 threads is a
    # reasonable default for WSL/single-socket CPU inference.  Users who have
    # more RAM can raise this via env vars before starting the server.
    os.environ.setdefault("OMP_NUM_THREADS", "2")
    os.environ.setdefault("MKL_NUM_THREADS", "2")
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "2")
    # HuggingFace fast tokenizers spawn a Rust thread pool; disable parallelism
    # for batches of 1 (standard pipeline use case) to save ~200-400 MB.
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

    _run_pipeline(job_id, file_path, original_filename)


def _upload_path_for(job_id: str) -> str | None:
    """The uploaded file for a job: uploads/<job_id>.<ext>, or None if it is gone.

    Looked up by id rather than passed around, so a worker container that only
    shares the uploads volume with the API can find it (ADR-0046).
    """
    try:
        matches = sorted(uploads_dir().glob(f"{job_id}.*"))
        if matches:
            return str(matches[0])
    except Exception as exc:
        logger.warning(f"Failed to resolve upload path for {job_id}: {exc}")
    return None


def _spawn_job(job_id: str, file_path: str, original_filename: str,
               on_exit: Callable[[str], None]) -> mp.process.BaseProcess:
    """Start the isolated pipeline subprocess for one job and watch it.

    The queue loop (api/queue_loop.py, ADR-0046) decides WHEN a job runs and
    how many run at once; this function only knows HOW: a `spawn`-context
    process — the memory and crash boundary of ADR-0002 — plus a watcher thread
    that turns a crash into a `failed` status and, in every case, calls
    `on_exit(job_id)` so the loop frees the slot and claims the next job.
    """
    logger.info(f"[Worker] Spawning isolated subprocess for job {job_id}")

    # Captured now, right after the queue loop's claim (api/queue_loop.py's
    # claim_next_queued already set worker_id on this row before calling us),
    # so the crash-path finalization below can use the same ownership check
    # _run_pipeline uses -- without this, a crash-triggered write is the most
    # realistic way to hit the exact race that check exists to close: a lease
    # can expire and be reclaimed by another worker while THIS subprocess is
    # still alive and CPU/memory-starved, then get OOM-killed.
    owner_worker_id = _current_owner(job_id)

    ctx = mp.get_context("spawn")
    proc = ctx.Process(
        target=_subprocess_entry,
        args=(job_id, file_path, original_filename),
        daemon=True,
        name=f"pipeline-{job_id}",
    )
    proc.start()
    logger.debug(f"[Worker] Subprocess pid={proc.pid} started for job {job_id}")

    _SIGNAL_NAMES: dict[int, str] = {
        -6:  "SIGABRT (std::bad_alloc or abort() in a native library)",
        -9:  "SIGKILL (OS out-of-memory killer)",
        -11: "SIGSEGV (segmentation fault in native code)",
    }

    def _watch(p: mp.Process, jid: str) -> None:
        p.join()
        code = p.exitcode
        if code == 0:
            logger.info(f"[Worker] Subprocess for job {jid} exited cleanly")
        else:
            reason = (
                _SIGNAL_NAMES.get(code, f"exit code {code}")
                if code is not None
                else "unknown (process has no exit code)"
            )
            logger.error(f"[Worker] Subprocess for job {jid} crashed: {reason}")
            try:
                if _finalize_job(jid, "failed", owner_worker_id):
                    emit_progress(jid, "done", {
                        "status": "failed",
                        "error": (
                            f"Pipeline worker process terminated unexpectedly ({reason}). "
                            "The document may require more memory than is available. "
                            "Try a smaller file, reduce WORKER_MAX_MEMORY_MB, or set "
                            "SKIP_HEAVY_MODELS=1 to disable ML models and use regex-only extraction."
                        ),
                    })
            except Exception as exc:
                logger.error(
                    f"[Worker] Could not update job {jid} status after subprocess crash: {exc}"
                )
        try:
            on_exit(jid)
        except Exception as exc:
            logger.error(f"[Worker] on_exit hook failed for job {jid}: {exc}")

    watcher = threading.Thread(
        target=_watch,
        args=(proc, job_id),
        daemon=True,
        name=f"watcher-{job_id}",
    )
    watcher.start()
    return proc


def run_pipeline_async(job_id: str, file_path: str, original_filename: str) -> str:
    """Queue a job, and start it right away when this process runs the pipeline.

    Returns:
        "started"  — role `all` and a slot was free: the subprocess is running
        "queued"   — the job waits in the `jobs` table, for a worker process
                     (role `api`) or for a free slot (role `all`)
        "rejected" — the queue is deeper than API_QUEUE_MAX_DEPTH; the job is
                     marked failed and the caller answers 503

    `file_path` is kept for the callers' sake: the worker locates the upload
    by job id under uploads/, which is the directory a worker container shares
    with the API (ADR-0046).
    """
    from api import queue_loop

    if _QUEUE_MAX_DEPTH > 0 and queue_loop.count_queued() >= _QUEUE_MAX_DEPTH:
        set_job_status(job_id, "failed")
        emit_progress(job_id, "done", {
            "status": "failed",
            "error": f"Queue is full ({_QUEUE_MAX_DEPTH} jobs waiting) — try again later"
        })
        logger.warning(f"[Worker] Job {job_id} rejected — queue full")
        return "rejected"

    set_job_status(job_id, "queued")
    emit_progress(job_id, "queued", {
        "status": "queued",
        "position": queue_loop.count_queued()
    })

    if queue_loop.role() != "all":
        logger.info(f"[Worker] Job {job_id} queued for a worker process")
        return "queued"

    # This process runs the pipeline: kick the loop so that a free slot starts
    # the job before the response is written — the "processing" answer the UI
    # already knows — instead of on the next poll.
    try:
        queue_loop.start_embedded().kick()
    except Exception as exc:
        logger.error(f"[Worker] Could not kick the queue loop: {exc}")
    row = get_conn().execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
    return "started" if row and row["status"] == "processing" else "queued"

def _lexicon_rescan(job_id: str, report_text: str) -> int:
    """
    Report Lexicon Re-scan — per-report few-shot adaptation (Approach 1).

    After the reviewer accepts entities in the UI, those accepted values form a
    domain-specific lexicon for this document.  This function scans the full
    report text for every occurrence of each accepted entity value that the
    initial pipeline passes (regex, NER, LLM) may have missed.

    Why this matters:
      The LLM might extract "GREYVIBE" once from the executive summary, but the
      same name appears 12 more times in the body.  Stage 2 regex won't catch
      named malware families; Stage 2e (GLiNER) may miss low-confidence spans.
      The reviewer's accept decision is the highest-quality signal available —
      propagating it back over the full text closes the coverage gap at zero
      ML cost (pure string matching, O(text × entities)).

    Returns the number of new entity rows inserted.
    """
    from uuid import uuid4

    if not report_text:
        return 0

    text_lower = report_text.lower()

    with _lock:
        with get_conn() as conn:
            # Load accepted entities that are suitable for text-span matching.
            # Exclude generic SCO types (IPs, hashes) whose value is already
            # found exactly by regex — focus on named SDO entities.
            _SDO_TYPES = {
                "malware", "threat_actor", "intrusion_set", "tool",
                "campaign", "identity", "location", "infrastructure",
                "technique", "tactic", "procedure", "ttp",
                "vulnerability", "cve", "indicator", "incident",
            }
            rows = conn.execute(
                "SELECT id, value, entity_type, confidence, mitre_id, source "
                "FROM entities WHERE job_id=? AND accepted=1",
                (job_id,),
            ).fetchall()

            # Build a deduplicated lookup of existing (value_lower, entity_type) pairs
            existing_keys: set[tuple[str, str]] = {
                (r["value"].lower(), r["entity_type"]) for r in rows
            }

            to_insert: list[tuple] = []
            seen_new: set[tuple[str, str]] = set()

            for row in rows:
                etype = row["entity_type"]
                if etype not in _SDO_TYPES:
                    continue   # skip regex-handled SCOs
                value = row["value"].strip()
                if len(value) < 4:
                    continue   # too short — too many false positives
                value_lower = value.lower()

                # Scan the full text for ALL occurrences of this value
                pos = 0
                found_new = False
                while True:
                    idx = text_lower.find(value_lower, pos)
                    if idx == -1:
                        break
                    # Word-boundary check — don't match mid-word
                    before_ok = (idx == 0 or not text_lower[idx - 1].isalnum())
                    after_ok  = (
                        idx + len(value_lower) >= len(text_lower)
                        or not text_lower[idx + len(value_lower)].isalnum()
                    )
                    if before_ok and after_ok:
                        found_new = True   # at least one span found (even if original)
                    pos = idx + 1

                if not found_new:
                    continue

                # The entity appears in the text.  Insert a "report_lexicon" copy
                # only if not already present as a different source.
                new_key = (value_lower, etype)
                if new_key in existing_keys or new_key in seen_new:
                    continue
                seen_new.add(new_key)

                # Context: first 200 chars around first occurrence
                first_idx = text_lower.find(value_lower)
                ctx_start = max(0, first_idx - 60)
                ctx_end   = min(len(report_text), first_idx + len(value) + 60)
                context   = report_text[ctx_start:ctx_end].strip()

                to_insert.append((
                    str(uuid4()), job_id, value, etype,
                    context, row["confidence"], row["mitre_id"],
                    1,                  # accepted=True (reviewer already validated the label)
                    "report_lexicon",   # source tag — distinguishable from pipeline sources
                    "propagated",       # ADR-0058: a copy of that decision, not a new one
                ))

            if to_insert:
                conn.executemany(
                    "INSERT INTO entities "
                    "(id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source,"
                    "decision_origin) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT (id) DO NOTHING",
                    to_insert,
                )
                conn.commit()
                logger.info(
                    f"[lexicon_rescan] +{len(to_insert)} entity rows "
                    f"(source=report_lexicon, from {len(rows)} accepted SDO entities)"
                )

    return len(to_insert)


def re_run_final_stages(job_id: str, skip_rescan: bool = False) -> str | None:
    """
    Re-runs Stage 4+5 using the accepted entities currently in the DB.
    Returns the new bundle JSON, or None on failure.

    skip_rescan=True  — used by the auto-finalize (background debounce) to
                        skip the lexicon re-scan for speed.  The manual Finalize
                        button always passes skip_rescan=False (full re-scan).
                        It also leaves the job's status alone: the
                        auto-finalize runs 4 s after every review edit, and it
                        used to mark the report completed, so a report left
                        "Reviewing" after its analyst's first click.

    Entity sources stored during the pipeline:
      ioc       – regex-extracted IoC (Stage 2)
      gazetteer – MITRE name dictionary (Stage 2b)
      semantic  – embedding TTP match (Stage 2c)
      cyner     – CyNER cybersecurity NER (Stage 2d)
      gliner    – GLiNER zero-shot NER (Stage 2e)
      llm       – LLM extraction (Stage 3)
      manual    – reviewer-added via "Add as entity"

    Previously only source='ioc' and source='llm' were read, so accepted
    entities from all other sources — including every manually added entity —
    were silently dropped from the final bundle.  The fix reads all sources
    and routes each entity by its entity_type to the correct STIX path.
    """
    import sys
    from pathlib import Path
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))

    from models.schemas import EntityType, RawEntity
    from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
    from pipeline.stage5_validation import validate_and_export

    with _lock:
        with get_conn() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                return None

    # ── Report lexicon re-scan — runs BEFORE rebuilding the bundle ────────────
    # Uses the reviewer's accepted entities as a per-report domain lexicon and
    # scans the full text for additional occurrences of known named entities
    # that the initial NER/LLM passes may have missed.
    # Skipped when skip_rescan=True (auto-finalize path) to keep latency low.
    report_text = job["report_text"] or ""
    if not skip_rescan:
        new_count = _lexicon_rescan(job_id, report_text)
        if new_count:
            logger.info(f"[finalize] Lexicon re-scan added {new_count} new entity rows")

    with _lock:
        with get_conn() as conn:
            job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not job:
                return None

            # ALL accepted/unreviewed entities regardless of source
            all_entity_rows = conn.execute(
                "SELECT * FROM entities WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
                (job_id,),
            ).fetchall()

            # ALL accepted/unreviewed relationships (DB is authoritative —
            # includes every manual addition, edit, or deletion from the UI)
            rel_rows = conn.execute(
                "SELECT * FROM relationships WHERE job_id=? AND (accepted IS NULL OR accepted=1)",
                (job_id,),
            ).fetchall()

    # ── Route entities to the correct STIX path ───────────────────────────────
    #
    # build_stix_bundle accepts two inputs:
    #   raw_entities  — RawEntity objects that map to SCOs (network IoCs, hashes)
    #                   or to SDOs handled via _entity_to_sdo / explicit loops
    #                   (CVE, technique, tactic, procedure, infrastructure, …)
    #   llm_result    — named lists for malware/threat-actor/tool SDOs
    #
    # Entity types that build_stix_bundle handles via raw_entities:
    _RAW_ENTITY_TYPES: frozenset[str] = frozenset({
        # SCOs
        EntityType.IPV4.value, EntityType.IPV6.value, EntityType.DOMAIN.value,
        EntityType.URL.value, EntityType.EMAIL.value, EntityType.MD5.value,
        EntityType.SHA1.value, EntityType.SHA256.value, EntityType.MAC_ADDR.value,
        EntityType.ASN.value, EntityType.FILE.value, EntityType.REGISTRY_KEY.value,
        EntityType.MUTEX.value, EntityType.NETWORK_TRAFFIC.value,
        EntityType.USER_ACCOUNT.value,
        # SDOs — stage4 handles these via _entity_to_sdo or explicit loops
        EntityType.CVE.value,
        EntityType.TECHNIQUE.value, EntityType.TACTIC.value,
        EntityType.PROCEDURE.value, EntityType.TTP.value,
        EntityType.INFRASTRUCTURE.value, EntityType.INTRUSION_SET.value,
        EntityType.LOCATION.value, EntityType.IDENTITY.value,
        EntityType.CAMPAIGN.value, EntityType.INCIDENT.value,
    })

    raw_entities: list[RawEntity] = []

    for row in all_entity_rows:
        etype_str = row["entity_type"]
        value     = row["value"]

        if etype_str in _RAW_ENTITY_TYPES:
            try:
                raw_entities.append(RawEntity(
                    value=value,
                    entity_type=EntityType(etype_str),
                    context=row["context"] or "",
                    confidence=row["confidence"],
                    mitre_id=row["mitre_id"],
                    source=row["source"],
                ))
            except Exception:
                pass  # defensive — skip any unknown enum value

        # EntityType.INTRUSION_SET is already in _RAW_ENTITY_TYPES and handled
        # by _entity_to_sdo.  Any unrecognised type strings are silently skipped.

    # Malware, threat-actor and tool names: the stored rows, every source
    # (gazetteer, NER, LLM, analyst) minus the rejected ones — through the same
    # helper a pipeline run uses before Stage 4 (pipeline/named_entities.py).
    from pipeline.named_entities import with_named_entities
    _named = with_named_entities(LLMEnrichmentResult(),
                                 ((row["entity_type"], row["value"]) for row in all_entity_rows))
    malware_names      = _named.malware_families
    threat_actor_names = _named.threat_actors
    tool_names         = _named.tools

    # ── Load original LLM JSON for fields that have no individual entity rows ───
    # (TTPs, ioc_associations, campaign_name, targeted_sectors/countries,
    #  course_of_action are stored only as aggregate JSON, not as individual rows)
    llm_result = LLMEnrichmentResult()
    if job["llm_result_json"]:
        try:
            llm_result = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])
        except Exception:
            pass

    # ── Build rejection filter sets from the DB ────────────────────────────────
    # Bug fix: the JSON blob bypasses accept/reject decisions made in the UI.
    # Fetch rejected entity rows and use them to filter the JSON-blob fields
    # (ttps, campaign_name, targeted_countries, targeted_sectors) so that
    # objects the reviewer explicitly rejected don't sneak back into the bundle.
    with _lock:
        with get_conn() as conn:
            rejected_rows = conn.execute(
                "SELECT value, entity_type, mitre_id FROM entities "
                "WHERE job_id=? AND accepted=0",
                (job_id,),
            ).fetchall()

    rejected_ttp_names:    set[str] = set()
    rejected_ttp_mitre:    set[str] = set()
    rejected_locations:    set[str] = set()
    rejected_identities:   set[str] = set()
    rejected_campaigns:    set[str] = set()

    for r in rejected_rows:
        et  = r["entity_type"]
        val = r["value"].lower().strip()
        mid = (r["mitre_id"] or "").lower().strip()

        if et in ("technique", "tactic", "procedure", "ttp"):
            rejected_ttp_names.add(val)
            if mid:
                rejected_ttp_mitre.add(mid)
        elif et == "location":
            rejected_locations.add(val)
        elif et == "identity":
            rejected_identities.add(val)
        elif et == "campaign":
            rejected_campaigns.add(val)

    # Filter TTPs — a TTP is excluded if its name OR MITRE ID was explicitly rejected
    filtered_ttps = [
        t for t in llm_result.ttps
        if t.technique_name.lower() not in rejected_ttp_names
        and (not t.mitre_id or t.mitre_id.lower() not in rejected_ttp_mitre)
    ]

    # Filter campaign_name — excluded if the user rejected the campaign entity
    campaign_name = llm_result.campaign_name
    if campaign_name and campaign_name.lower().strip() in rejected_campaigns:
        campaign_name = None

    # Filter targeted countries and sectors — excluded if entity was rejected
    filtered_countries = [
        c for c in llm_result.targeted_countries
        if c.lower().strip() not in rejected_locations
    ]
    filtered_sectors = [
        s for s in llm_result.targeted_sectors
        if s.lower().strip() not in rejected_identities
    ]

    def _row_times(row):
        # ADR-0063 — the dates as stored.  A row written before it has only
        # start_time/stop_time: legacy dates of unknown precision, kept and
        # never re-interpreted (a stored 1 January may be a year).
        from pipeline.temporal import legacy_assertions, times_from_json
        keys = row.keys()
        times = times_from_json(row["times_json"] if "times_json" in keys else None)
        if times:
            return times
        return legacy_assertions(
            row["start_time"] if "start_time" in keys else None,
            row["stop_time"] if "stop_time" in keys else None,
        )

    db_relationships = [
        RelationshipExtracted(
            source_value=row["source_value"],
            relationship_type=row["relationship_type"],
            target_value=row["target_value"],
            confidence=row["confidence"],
            evidence_text=row["evidence_text"] if "evidence_text" in row.keys() else None,
            evidence_label=(
                row["evidence_label"]
                if "evidence_label" in row.keys() and row["evidence_label"]
                else "reported"
            ),
            times=_row_times(row),
        )
        for row in rel_rows
    ]

    llm_result = LLMEnrichmentResult(
        # DB is the authoritative source for named SDOs — includes gazetteer,
        # CyNER, GLiNER, manual additions, and reviewer edits on top of LLM output.
        malware_families=malware_names,
        threat_actors=threat_actor_names,
        tools=tool_names,
        # JSON-blob fields, now filtered through the reviewer's decisions:
        ttps=filtered_ttps,
        ioc_associations=llm_result.ioc_associations,
        campaign_name=campaign_name,
        targeted_sectors=filtered_sectors,
        targeted_countries=filtered_countries,
        course_of_action=llm_result.course_of_action,
        # DB relationships override everything (manual adds/edits/deletions):
        relationships=db_relationships,
    )

    original_filename = job["original_filename"]
    report_name       = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)

    # Locate the uploaded file to recompute its hash (stable — file never changes)
    upload_matches = list(uploads_dir().glob(f"{job_id}.*"))
    source_hash, source_bytes = load_file_bytes(upload_matches[0] if upload_matches else None)

    # The report's publication date, recomputed from the stored source and
    # text exactly as the run computed it (ADR-0063 §4) — deterministic, so
    # nothing extra is stored.
    try:
        from pipeline.stage1_ingestion import extract_anchor
        _source = next((p for p in upload_matches if p.suffix.lower() in (".txt", ".html", ".htm")),
                       upload_matches[0] if upload_matches else None)
        document_anchor = extract_anchor(str(_source) if _source else None, report_text)
    except Exception as exc:
        logger.debug(f"[finalize] document anchor unavailable: {exc}")
        document_anchor = None

    # Stage 4 through the same function a pipeline run uses (ADR-0059).
    from pipeline.bundle_ledger import MappingLedger
    ledger = MappingLedger()
    bundle = build_bundle(
        raw_entities, llm_result,
        report_name=report_name,
        report_text=report_text,
        original_filename=original_filename,
        source_hash=source_hash,
        source_bytes=source_bytes,
        policy=_load_policy(),
        tlp_level=job["tlp_level"],
        pap_level=job["pap_level"],
        cve_metadata=lookup_cves(raw_entities),
        ledger=ledger,
        document_anchor=document_anchor,
    )
    bundle_json = bundle.serialize(pretty=True)
    ledger_json = json.dumps(ledger.to_dict())

    out_path = str(bundle_output_path(job_id, report_name))
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    validate_and_export(bundle, out_path)

    with _lock:
        with get_conn() as conn:
            if skip_rescan:
                conn.execute(
                    "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, updated_at=? WHERE id=?",
                    (bundle_json, ledger_json, now_iso(), job_id),
                )
            else:
                conn.execute(
                    "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, status='completed', "
                    "updated_at=? WHERE id=?",
                    (bundle_json, ledger_json, now_iso(), job_id),
                )
            conn.commit()

    return bundle_json
