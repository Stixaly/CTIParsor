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

from api.baseline_store import baseline_sha256, load_baseline, objects_by_id, validate_in_worker
from api.db import _lock, backup_db, emit_progress, get_conn, now_iso, set_job_status, transaction
from api.paths import output_dir, uploads_dir
from api.run_config import BuildKind, build_record, run_build_record, utc_stamp
from pipeline import baseline_stix
from pipeline.baseline_stix import BaselineBuild, BaselineError, BaselineIndex, Reconciliation
from pipeline.decisions import BASELINE_STIX
from pipeline.decisions import SHIPS as _SHIPS
from pipeline.decisions import WITHHELD as _WITHHELD
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


# What is stored of Stage 5's errors: a bundle with thousands of objects can
# fail on thousands of them, and the first few tell the analyst what is wrong.
_MAX_VALIDATION_ERRORS = 20
_MAX_VALIDATION_ERROR_CHARS = 500


def _stored_validation_errors(errors: list[str] | None) -> list[str]:
    """The errors as the job store keeps and the API returns them: the first
    few, each cut short."""
    return [e[:_MAX_VALIDATION_ERROR_CHARS] for e in (errors or [])[:_MAX_VALIDATION_ERRORS]]


def _validation_errors_json(errors: list[str] | None) -> str | None:
    """`jobs.bundle_validation_errors`: the stored errors as a JSON list; NULL
    when there are none."""
    return json.dumps(_stored_validation_errors(errors)) if errors else None


class BundleInvalidError(RuntimeError):
    """Stage 5's JSON schemas refused the bundle `re_run_final_stages` just built.

    The bundle is stored with its verdict, but the job is not completed and the
    API does not serve the bundle (409 on GET /bundle).  `errors` are the
    validator's messages as stored: 20 at most, 500 characters each."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = _stored_validation_errors(errors)
        super().__init__("the rebuilt bundle failed STIX schema validation"
                         + (f": {self.errors[0]}" if self.errors else ""))


def _finalize_job(
    job_id: str, status: str, owner_worker_id: str | None, *, bundle_json: str | None = None,
    ledger_json: str | None = None, validation: str | None = None,
    validation_errors: list[str] | None = None, build_json: str | None = None,
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
    So are `validation` (Stage 5's status) and `validation_errors`: a verdict left
    over from an earlier build would clear or condemn this one.  So is
    `build_json`, what built the bundle (ADR-0086), and the job's current
    `review_revision` as the revision it was built from: a finalize that read
    the rows before this write is then refused.
    """
    errors_json = _validation_errors_json(validation_errors)
    with _lock:
        with get_conn() as conn:
            if owner_worker_id is None:
                if bundle_json is not None:
                    conn.execute(
                        "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, bundle_validation=?, "
                        "bundle_validation_errors=?, bundle_build_json=?, bundle_review_revision=review_revision, "
                        "status=?, updated_at=? WHERE id=?",
                        (bundle_json, ledger_json, validation, errors_json, build_json, status, now_iso(),
                         job_id),
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
                    "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, bundle_validation=?, "
                    "bundle_validation_errors=?, bundle_build_json=?, bundle_review_revision=review_revision, "
                    "status=?, updated_at=? WHERE id=? AND worker_id=?",
                    (bundle_json, ledger_json, validation, errors_json, build_json, status, now_iso(), job_id,
                     owner_worker_id),
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


# The LLM's malware, actor, tool and campaign names carry no measured
# confidence.  They were stored at 0.9, at AUTO_ACCEPT_LEVEL, so every one was
# accepted automatically and the review page marked it "auto" as if 90 % sure
# (audit B 8.3.6).  Below the level, they wait for an analyst.  What ships does
# not change: a pending row ships (decisions.SHIPS); a rejected one does not.
# A detector's names keep their own confidences, and calibration (ADR-0051)
# can raise a source past the level once auto_accept_audit has measured it.
LLM_NAME_CONFIDENCE = 0.5


def _stage3r_entity(row: tuple, reconciliation: Reconciliation | None, now: str) -> tuple:
    """An entities row (14 fields) with the four Stage 3r columns appended:
    enrichment_status, baseline_stix_id, decision_origin, decided_at (ADR-0090).
    A row the baseline already holds (MATCHED) is accepted with origin
    `baseline_stix`; its held_reason, if any, stays.  Without a reconciliation
    the four columns are NULL, as they were before."""
    if reconciliation is None:
        return (*row, None, None, None, None)
    status, bid = reconciliation.entity(row[3], row[2])
    if status != baseline_stix.MATCHED:
        return (*row, status, bid, None, None)
    # accepted is field 7; the rest of the row is unchanged.
    return (*row[:7], 1, *row[8:], status, bid, BASELINE_STIX, now)


def _stage3r_relation(row: tuple, reconciliation: Reconciliation | None, now: str) -> tuple:
    """A relationships row (12 fields) with enrichment_status, baseline_stix_id and
    decided_at appended.  A MATCHED one is accepted with origin `baseline_stix`,
    decided now, as an entity is; its held_reason, if any, stays.  Without a
    reconciliation the three are NULL, as they were before."""
    if reconciliation is None:
        return (*row, None, None, None)
    status, bid = reconciliation.relation(row[2], row[3], row[4])
    if status != baseline_stix.MATCHED:
        return (*row, status, bid, None)
    # accepted is field 6 and decision_origin field 10.
    return (*row[:6], 1, *row[7:10], BASELINE_STIX, row[11], status, bid, now)


def _save_entities(job_id: str, raw_entities, llm_result, report_text: str = "",
                   reconciliation: Reconciliation | None = None) -> None:
    """Persist Stage 2 IoCs, Stage 2b gazetteer, and Stage 3 LLM entities to the DB.

    TTPs additionally carry the verbatim quote the extractor was asked for
    (ADR-0028) and its resolved offset into `report_text`.  An unlocatable quote
    stores a NULL offset and demotes the grade — it never drops the technique:
    99.4% of unlocatable evidence was measured to be paraphrase of real report
    content rather than invention.

    With a `reconciliation` (Stage 3r, enrich mode) every row carries its status
    against the analyst's baseline, and the baseline's own entities and
    relationships are stored too, pre-accepted (ADR-0090).

    The job's rows are replaced, not added to: a job requeued after Stage 3
    (lease expired, worker drained) runs again from Stage 1 and saves again.
    Only a `processing` job reaches this, so no analyst decision is lost.
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
            rows_llm.append((str(uuid4()), job_id, name, "malware", "", LLM_NAME_CONFIDENCE, None, None, "llm"))
    for name in llm_result.threat_actors:
        if not is_denied(name, "threat_actor"):
            rows_llm.append((str(uuid4()), job_id, name, "threat_actor", "", LLM_NAME_CONFIDENCE,
                             None, None, "llm"))
    for name in llm_result.tools:
        if not is_denied(name, "tool"):
            rows_llm.append((str(uuid4()), job_id, name, "tool", "", LLM_NAME_CONFIDENCE, None, None, "llm"))
    if llm_result.campaign_name and not is_denied(llm_result.campaign_name, "campaign"):
        rows_llm.append((str(uuid4()), job_id, llm_result.campaign_name, "campaign", "",
                         LLM_NAME_CONFIDENCE, None, None, "llm"))
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
            except Exception as exc:   # locating must never fail a job
                # ... but it demotes the technique below as if the quote were
                # not in the text: say it was the locator.
                logger.warning(f"[Worker] job {job_id}: quote of {ttp.mitre_id or ttp.technique_name} not located "
                               f"(locator error, graded as not found): {type(exc).__name__}: {exc}")
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

    # ADR-0082 — techniques Stage 3f's selection could not decide, stored
    # pending with the reason: finalize leaves them out until an analyst
    # accepts one.  Graded `gap`: nothing established them.  A technique
    # already stored from another source is not listed twice.
    rows_held: list[tuple] = []
    _stored_ids = {
        (r[6] or "").upper() for r in rows_ioc + rows_llm if r[3] == "ttp"
    }
    for held_ttp in getattr(llm_result, "ttp_review", None) or []:
        _mid = held_ttp.attack_id.upper()
        if _mid in _stored_ids:
            continue
        _stored_ids.add(_mid)
        _quote = (held_ttp.evidence_quote or "").strip() or None
        _start = _end = None
        if _quote and report_text:
            try:
                _span = locate(_quote, report_text)
            except Exception as exc:   # locating must never fail a job
                logger.warning(f"[Worker] job {job_id}: quote of held {held_ttp.attack_id} not located "
                               f"(locator error): {type(exc).__name__}: {exc}")
                _span = None
            if _span is not None:
                _start, _end = _span.start, _span.end
        rows_held.append((
            str(uuid4()), job_id, held_ttp.name or held_ttp.attack_id, "ttp",
            "", 0.9, held_ttp.attack_id, None, "llm",
            _quote, "gap", _start, _end, held_ttp.reason,
        ))

    rows_rel: list[tuple] = []
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
            "default", None,
        ))
    # ADR-0082 — claims Stage 3d could not decide: pending, nobody's decision
    # yet, with the reason; finalize leaves them out until an analyst accepts.
    for held_rel in getattr(llm_result, "rel_review", None) or []:
        _label = getattr(held_rel.evidence_label, "value", held_rel.evidence_label) or "reported"
        rows_rel.append((
            str(uuid4()), job_id,
            held_rel.source_value, held_rel.relationship_type, held_rel.target_value,
            held_rel.confidence, None, held_rel.evidence_text, _label,
            times_to_json(list(held_rel.times or [])),
            None, held_rel.reason,
        ))

    with _lock:
        with get_conn() as conn:
            # Only TTP rows carry evidence (ADR-0028) and only held rows a
            # reason (ADR-0082); every other row is padded here rather than at
            # each of the places they are built.
            _entity_rows = [
                (*r, None) if len(r) == 13 else (*r, None, None, None, None, None)
                for r in rows_ioc + rows_llm
            ] + rows_held
            # Stage 3r (ADR-0090): each row's status against the baseline, then the
            # rows the baseline adds, pre-accepted with origin baseline_stix.
            _now = now_iso()
            _entity_rows = [_stage3r_entity(r, reconciliation, _now) for r in _entity_rows]
            _rel_rows = [_stage3r_relation(r, reconciliation, _now) for r in rows_rel]
            if reconciliation is not None:
                _entity_rows += [
                    (str(uuid4()), job_id, item.value, item.entity_type, "", 1.0,
                     item.mitre_id, 1, baseline_stix.SOURCE, item.evidence_text, None,
                     item.evidence_start, item.evidence_end, None,
                     item.status, item.baseline_stix_id, BASELINE_STIX, _now)
                    for item in reconciliation.imported_entities
                ]
                _rel_rows += [
                    (str(uuid4()), job_id, item.source_value, item.relationship_type, item.target_value,
                     1.0, 1, None, None, None, BASELINE_STIX, None, item.status, item.baseline_stix_id, _now)
                    for item in reconciliation.imported_relations
                ]
            with transaction(conn):
                # A job run again after Stage 3 rewrites its rows instead of doubling them.
                conn.execute("DELETE FROM entities WHERE job_id=?", (job_id,))
                conn.execute("DELETE FROM relationships WHERE job_id=?", (job_id,))
                # ON CONFLICT DO NOTHING is the portable spelling of INSERT OR IGNORE
                # (SQLite 3.24+ and PostgreSQL, ADR-0045).
                conn.executemany(
                    "INSERT INTO entities "
                    "(id,job_id,value,entity_type,context,confidence,mitre_id,accepted,source,"
                    "evidence_text,evidence_label,evidence_start,evidence_end,held_reason,"
                    "enrichment_status,baseline_stix_id,decision_origin,decided_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT (id) DO NOTHING",
                    _entity_rows,
                )
                conn.executemany(
                    "INSERT INTO relationships "
                    "(id,job_id,source_value,relationship_type,target_value,"
                    "confidence,accepted,evidence_text,evidence_label,times_json,"
                    "decision_origin,held_reason,enrichment_status,baseline_stix_id,decided_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT (id) DO NOTHING",
                    _rel_rows,
                )


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
        # The run config `policy_used` built; None until then, or when it raised.
        self.run_config: dict | None = None
        # Stage 3r's reconciliation; None in full mode.
        self.reconciliation: Reconciliation | None = None

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
        _save_entities(self.job_id, entities, llm_result, report_text=text, reconciliation=self.reconciliation)
        _apply_auto_accept(self.job_id)
        # Persist the LLM result for finalize.
        with _lock:
            with get_conn() as conn:
                conn.execute("UPDATE jobs SET llm_result_json=?, updated_at=? WHERE id=?",
                             (llm_result.model_dump_json(), now_iso(), self.job_id))
                conn.commit()

    def baseline_reconciled(self, reconciliation: Reconciliation) -> None:
        self.reconciliation = reconciliation

    def policy(self) -> dict | None:
        return _load_policy()

    def policy_used(self, policy: dict | None) -> None:
        # Record the configuration this bundle was built under (ADR-0024),
        # stamped right after the policy is read, so the snapshot is the policy
        # actually applied rather than whatever the row holds when someone asks.
        try:
            from api.run_config import build_run_config
            self.run_config = build_run_config(policy)
            rc = json.dumps(self.run_config)
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


def _run_pipeline(job_id: str, file_path: str, original_filename: str,
                  owner_worker_id: str | None = None) -> None:
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
        _owner_worker_id = owner_worker_id if owner_worker_id is not None else _current_owner(job_id)

        # A baseline (ADR-0090) was read without the JSON schemas, which take
        # seconds per thousand objects; they run here, once.  A bundle that
        # fails now (the chosen Report itself) fails the job: no silent fallback
        # to the full mode.
        validate_in_worker(job_id)

        # TLP / PAP markings selected at upload time.
        with get_conn() as conn:
            row = conn.execute("SELECT tlp_level, pap_level FROM jobs WHERE id=?", (job_id,)).fetchone()
        loaded = load_baseline(job_id)
        document = Document(
            file_path=file_path,
            original_filename=original_filename,
            tlp_level=row["tlp_level"] if row else None,
            pap_level=row["pap_level"] if row else None,
            baseline=loaded[0] if loaded is not None else None,
            baseline_objects=loaded[1] if loaded is not None else None,
        )
        document.output_path = str(bundle_output_path(job_id, document.report_name))

        hooks = _WorkerHooks(job_id, _owner_worker_id, start_time)
        result = run_document(document, RunOptions.from_env(), hooks)
        _record_stage_report(job_id, result.stage_report())
        if result.bundle is None:
            raise RuntimeError("the run produced no bundle (Stage 4 did not run)")

        baseline_build = result.baseline_build
        bundle_json = baseline_stix.serialize_bundle(
            result.bundle, baseline_build.verbatim if baseline_build is not None else None)
        ledger_json = json.dumps(result.ledger) if result.ledger is not None else None
        if result.validation == "invalid":
            # Nothing is published at this stage: the job waits for review either
            # way, and the API refuses to serve this bundle until a rebuild is valid.
            logger.warning(f"[Worker] job {job_id}: the bundle failed STIX schema validation "
                           f"({len(result.validation_errors)} error(s)); it is not served until "
                           "a rebuild passes")
        if not _finalize_job(job_id, "for_review", _owner_worker_id,
                             bundle_json=bundle_json, ledger_json=ledger_json,
                             validation=result.validation, validation_errors=result.validation_errors,
                             build_json=json.dumps(run_build_record(
                                 hooks.run_config,
                                 baseline_sha256=baseline_sha256(job_id) if loaded is not None else None))):
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
    except BaselineError as exc:
        # The baseline cannot be used (ADR-0090): the analyst's bundle is at fault, not the
        # code, so the reason is the message and there is no traceback to read.
        if _finalize_job(job_id, "failed", _owner_worker_id):
            emit_progress(job_id, "done", {"status": "failed", "error": str(exc)})
        logger.warning(f"[Worker] job {job_id}: the baseline cannot be used: {exc}")
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


def _subprocess_entry(job_id: str, file_path: str, original_filename: str,
                      owner_worker_id: str | None = None) -> None:
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

    _run_pipeline(job_id, file_path, original_filename, owner_worker_id)


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
        args=(job_id, file_path, original_filename, owner_worker_id),
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
                            "Try a smaller file, lower WORKER_MAX_CONCURRENT or raise the container's "
                            "memory limit, or set "
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
        # A job that never runs keeps no baseline (up to 20 MB) in the store.
        with _lock:
            with get_conn() as conn:
                conn.execute("DELETE FROM job_baselines WHERE job_id=?", (job_id,))
                conn.commit()
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


def _stored_newer_build(job_id: str, revision: int, *, complete: bool) -> str | None:
    """The bundle that stands when `re_run_final_stages` read the rows at
    `revision` and a build from a newer revision is stored (ADR-0086).

    `complete`: the analyst's Finalize, which completes the job with that
    bundle unless its verdict is invalid.  Raises `BundleInvalidError` with the
    STORED errors when the stored verdict is invalid.  None when the job no
    longer exists."""
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                if complete:
                    conn.execute(
                        "UPDATE jobs SET status='completed', updated_at=? "
                        "WHERE id=? AND bundle_review_revision > ? AND bundle_validation IS DISTINCT FROM 'invalid'",
                        (now_iso(), job_id, revision))
                stored = conn.execute(
                    "SELECT bundle_json, bundle_validation, bundle_validation_errors FROM jobs WHERE id=?",
                    (job_id,)).fetchone()
    if stored is None:
        return None
    logger.info(f"[finalize] job {job_id}: rows read at revision {revision}, but a build from a newer "
                "revision is stored; nothing published")
    if stored["bundle_validation"] == "invalid":
        try:
            errors = json.loads(stored["bundle_validation_errors"] or "[]")
        except ValueError:
            errors = []         # a damaged column must not turn a refused build into a 500
        raise BundleInvalidError([e for e in errors if isinstance(e, str)] if isinstance(errors, list) else [])
    return stored["bundle_json"]


def re_run_final_stages(job_id: str, quick: bool = False) -> str | None:
    """
    Re-runs Stage 4+5 using the accepted entities currently in the DB.
    Returns the new bundle JSON, or None on failure.

    quick=True  — used by the auto-finalize (background debounce): it leaves the
                  job's status alone.  The auto-finalize runs 4 s after every
                  review edit, and it used to mark the report completed, so a
                  report left "Reviewing" after its analyst's first click.
                  The manual Finalize button passes quick=False: the rebuild
                  also completes the job.

    The bundle is stored with Stage 5's verdict (`bundle_validation`).  One the
    schemas refuse ("invalid") never completes a job, whatever `quick` says: a
    `completed` job goes back to `for_review`, and `BundleInvalidError` is
    raised.  "unverified" (schemas missing) completes as before.

    The rows are read in one snapshot, with the job's `review_revision`; the
    bundle, ledger, verdict, build record (`bundle_build_json`) and that
    revision are published by one conditional UPDATE (ADR-0086).  A build from
    an older revision than the stored bundle's is refused, so a slow finalize
    never overwrites a newer one.  The refused build returns the stored bundle
    instead: the full finalize completes the job with it, and a stored invalid
    verdict raises `BundleInvalidError` with the stored errors; the refused
    build's own verdict is not acted on.  Only a build that publishes writes
    the export file in output/ (never served: the job store is authoritative).

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
    from pipeline.stage4b_graph_completion import HELD_FOR_REVIEW, REJECTED_BY_ANALYST, RefusedRelationship
    from pipeline.stage5_validation import INVALID, export_bundle, validate_bundle

    with _lock:
        with get_conn() as conn:
            # One snapshot, so the rows agree with the revision read with them
            # whatever the analyst decides while the bundle is being built.
            with transaction(conn, snapshot=True):
                job = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
                if not job:
                    return None
                # The id the database holds (a uuid the server generated), not the
                # request's string: it names the bundle file and goes into the log.
                job_id = job["id"]
                report_text = job["report_text"] or ""
                revision = job["review_revision"]

                # ALL accepted/unreviewed entities regardless of source
                all_entity_rows = conn.execute(
                    "SELECT * FROM entities WHERE job_id=? AND " + _SHIPS,
                    (job_id,),
                ).fetchall()

                # ALL accepted/unreviewed relationships (DB is authoritative —
                # includes every manual addition, edit, or deletion from the UI)
                rel_rows = conn.execute(
                    "SELECT * FROM relationships WHERE job_id=? AND " + _SHIPS,
                    (job_id,),
                ).fetchall()

                # The relationships that do not ship, rejected or held: graph
                # completion may not add them back (ADR-0013, amendment
                # 2026-10-26).  Every row, a baseline import's too: whoever
                # stated it, the analyst ruled it out.
                withheld_rel_rows = conn.execute(
                    "SELECT source_value, relationship_type, target_value, accepted "
                    "FROM relationships WHERE job_id=? AND " + _WITHHELD,
                    (job_id,),
                ).fetchall()

                # The rejected entity rows, for the JSON-blob fields below.
                rejected_rows = conn.execute(
                    "SELECT value, entity_type, mitre_id FROM entities "
                    "WHERE job_id=? AND accepted=0",
                    (job_id,),
                ).fetchall()

                # The analyst's baseline (ADR-0090), for an enrich job: its row, and the
                # baseline objects the analyst rejected.  An object leaves only when all
                # its rows are rejected: a pending row keeps it.
                baseline_row = None
                baseline_rejected: list = []
                if job["pipeline_mode"] == "enrich":
                    baseline_row = conn.execute(
                        "SELECT sha256, index_json, bundle_json FROM job_baselines WHERE job_id=?",
                        (job_id,),
                    ).fetchone()
                    if baseline_row is None:
                        # A job the full queue refused keeps no baseline (lot 2): its
                        # bundle is built without one, and its imported rows still
                        # stay out (below), so nothing is invented from them.
                        logger.warning("[finalize] job %s is in enrich mode but holds no baseline: "
                                       "the bundle is built without it", job_id)
                    baseline_rejected = conn.execute(
                        "SELECT baseline_stix_id FROM entities WHERE job_id=? AND baseline_stix_id IS NOT NULL "
                        "GROUP BY baseline_stix_id HAVING COUNT(*) = SUM(CASE WHEN accepted = 0 THEN 1 ELSE 0 END) "
                        "UNION "
                        "SELECT baseline_stix_id FROM relationships WHERE job_id=? AND baseline_stix_id IS NOT NULL "
                        "GROUP BY baseline_stix_id HAVING COUNT(*) = SUM(CASE WHEN accepted = 0 THEN 1 ELSE 0 END)",
                        (job_id, job_id),
                    ).fetchall()

    # ── The baseline's share (ADR-0090, Stage 4 merge) ────────────────────────
    #
    # The baseline's imported rows are not written again from the rows: Stage 4
    # writes the baseline's objects as received.  They are dropped before anything
    # below reads the rows (raw_entities, the named lists, the relationships).
    baseline_build: BaselineBuild | None = None
    if job["pipeline_mode"] == "enrich":
        all_entity_rows = [row for row in all_entity_rows if row["enrichment_status"] != baseline_stix.BASELINE_ONLY]
        rel_rows = [row for row in rel_rows if row["enrichment_status"] not in baseline_stix.IMPORTED]
    if baseline_row is not None:
        baseline_build = BaselineBuild(
            index=BaselineIndex.from_json(baseline_row["index_json"]),
            objects=objects_by_id(baseline_row["bundle_json"]),
            excluded=frozenset(row["baseline_stix_id"] for row in baseline_rejected),
        )

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
    unreadable: list[str] = []

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
            except ValueError as exc:     # a stored row the model no longer accepts
                unreadable.append(f"{etype_str} {value!r}: {exc}".splitlines()[0])

        # EntityType.INTRUSION_SET is already in _RAW_ENTITY_TYPES and handled
        # by _entity_to_sdo.  Type strings outside that set are not bundle objects.
    if unreadable:
        logger.warning("[finalize] job %s: %d stored entity row(s) could not be read and are "
                       "left out of the bundle, e.g. %s", job_id, len(unreadable), unreadable[0])

    # ── Load original LLM JSON for fields that have no individual entity rows ───
    # (TTPs, ioc_associations, campaign_name, targeted_sectors/countries,
    #  course_of_action are stored only as aggregate JSON, not as individual rows)
    llm_result = LLMEnrichmentResult()
    if job["llm_result_json"]:
        try:
            llm_result = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])
        except ValueError as exc:
            # Techniques, IoC associations, campaign, sectors, countries and
            # remediations live only in this JSON: the bundle goes without them.
            logger.error("[finalize] job %s: the stored LLM result cannot be read (%s); "
                         "the bundle has no techniques, campaign or targets from it",
                         job_id, str(exc).splitlines()[0])

    # ── Build rejection filter sets from the DB ────────────────────────────────
    # Bug fix: the JSON blob bypasses accept/reject decisions made in the UI.
    # Use the rejected entity rows to filter the JSON-blob fields
    # (ttps, campaign_name, targeted_countries, targeted_sectors) so that
    # objects the reviewer explicitly rejected don't sneak back into the bundle.
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

    # Malware, threat-actor and tool names: the stored rows, every source
    # (gazetteer, NER, LLM, analyst) minus the rejected ones — through the same
    # helper a pipeline run uses before Stage 4 (pipeline/named_entities.py).
    # It runs once campaign_name is read: a name typed several ways keeps its
    # best-ranked source's type, the analyst's accept counting as the analyst's
    # (ADR-0092).  A campaign it outranks leaves campaign_name and the raw
    # entities (the stored campaign row); the ledger records it.
    from pipeline.named_entities import stored_row_source, with_named_entities
    named = with_named_entities(
        LLMEnrichmentResult(campaign_name=campaign_name),
        ((row["entity_type"], row["value"],
          stored_row_source(row["source"], row["accepted"], row["decision_origin"]))
         for row in all_entity_rows),
    )
    raw_entities = [e for e in raw_entities if named.keeps(e)]
    campaign_name = named.llm_result.campaign_name

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
    refused_relationships = [
        RefusedRelationship(row["source_value"], row["relationship_type"], row["target_value"],
                            REJECTED_BY_ANALYST if row["accepted"] == 0 else HELD_FOR_REVIEW)
        for row in withheld_rel_rows
    ]

    llm_result = LLMEnrichmentResult(
        # DB is the authoritative source for named SDOs — includes gazetteer,
        # CyNER, GLiNER, manual additions, and reviewer edits on top of LLM output.
        malware_families=named.llm_result.malware_families,
        threat_actors=named.llm_result.threat_actors,
        tools=named.llm_result.tools,
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
    named.record(ledger)
    policy = _load_policy()
    bundle = build_bundle(
        raw_entities, llm_result,
        report_name=report_name,
        report_text=report_text,
        original_filename=original_filename,
        source_hash=source_hash,
        source_bytes=source_bytes,
        policy=policy,
        tlp_level=job["tlp_level"],
        pap_level=job["pap_level"],
        cve_metadata=lookup_cves(raw_entities),
        ledger=ledger,
        document_anchor=document_anchor,
        baseline=baseline_build,
        refused_relationships=refused_relationships,
    )
    bundle_json = baseline_stix.serialize_bundle(
        bundle, baseline_build.verbatim if baseline_build is not None else None)
    ledger_json = json.dumps(ledger.to_dict())

    out_path = str(bundle_output_path(job_id, report_name))
    # The baseline's trusted objects were validated at intake: Stage 5 does not check them again.
    validation = validate_bundle(baseline_stix.validation_json(
        bundle_json, baseline_build.trusted if baseline_build is not None else frozenset()))
    invalid = validation.status == INVALID
    verdict = (validation.status, _validation_errors_json(validation.errors))

    # One statement publishes the bundle with everything that describes it, and
    # refuses it when the stored bundle was built from newer rows (equal
    # revisions: same rows, the last writer wins).  The verdict is stored with
    # the bundle it judged (like the ledger).  An invalid one never completes
    # the job, and a job that was completed no longer is: its bundle is no
    # longer served.
    kind: BuildKind = "quick" if quick else "finalize"
    try:
        record = build_record(policy, kind=kind,
                              baseline_sha256=baseline_row["sha256"] if baseline_row is not None else None)
    except Exception as exc:
        # Metadata never fails a finalize (the run does the same with its run
        # config).  No git_rev: freshness falls back to the run's revision, as
        # for a row built before this record existed.
        logger.warning(f"[finalize] job {job_id}: build record not built: {type(exc).__name__}: {exc}")
        record = {"kind": kind, "built_at": utc_stamp(), "error": f"{type(exc).__name__}: {exc}"}
    build = json.dumps(record)
    # The export file is written only by a build that publishes, while its UPDATE
    # holds the job's row: concurrent publications write it in the order they
    # publish, a refused build or a job deleted meanwhile writes none, and a
    # write that fails rolls the publication back (as before, when a failed
    # export failed the finalize ahead of any write to the database).
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                published = conn.execute(
                    "UPDATE jobs SET bundle_json=?, bundle_ledger_json=?, bundle_validation=?, "
                    "bundle_validation_errors=?, bundle_build_json=?, bundle_review_revision=?, "
                    "status = CASE WHEN ? THEN 'completed' WHEN ? AND status = 'completed' THEN 'for_review' "
                    "ELSE status END, updated_at=? "
                    "WHERE id=? AND (bundle_review_revision IS NULL OR bundle_review_revision <= ?)",
                    (bundle_json, ledger_json, *verdict, build, revision, not quick and not invalid, invalid,
                     now_iso(), job_id, revision),
                ).rowcount == 1
                if published:
                    export_bundle(bundle_json, out_path, validation)

    if not published:
        stored = _stored_newer_build(job_id, revision, complete=not quick)
        if stored is not None:
            return stored
        # The job was deleted meanwhile: nothing is stored, as before.

    if invalid:
        logger.error(f"[finalize] job {job_id}: the rebuilt bundle failed STIX schema validation "
                     f"({len(validation.errors)} error(s)); the job is not completed and the bundle "
                     "is not served")
        raise BundleInvalidError(validation.errors)

    return bundle_json
