"""Guards and small workflows shared by the job-scoped route modules."""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import HTTPException

from api.baseline_store import intake_json, log_exclusions, scrubbed
from api.db import _lock, get_conn, now_iso, transaction
from api.db_backend import DBConnection
from pipeline import baseline_stix
from pipeline.baseline_stix import MAX_BASELINE_BYTES, BaselineError, BaselineIndex, Intake
from pipeline.env_flags import env_bool
from pipeline.stage4_stix_mapping import TLP_LEVELS, tlp_default


def require_job(conn: DBConnection, job_id: str) -> None:
    """Raise 404 unless *job_id* names an existing job.

    Ten handlers across four route modules repeated this guard verbatim.  It
    takes the caller's already-open connection rather than opening its own — as
    a FastAPI dependency it would have added a second connection per request,
    which is exactly the kind of extra SQLite traffic this codebase has had to
    hunt down before.
    """
    if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
        raise HTTPException(404, "Job not found")


# ── A baseline STIX bundle (ADR-0090) ───────────────────────────────────────

# What a route that reads a baseline can answer besides its own codes.
BASELINE_REFUSED: dict[int | str, dict[str, Any]] = {
    400: {"description": "STIX enrichment is off, or the baseline cannot be used (not UTF-8, not JSON, not a STIX "
                         "2.1 bundle, several reports and no `baseline_report_id`, a report it does not hold), or "
                         "the job's TLP or PAP is lower than the baseline's; `detail` says why."},
    413: {"description": "The baseline is larger than `max_bytes` (GET /api/baselines/status)."},
    503: {"description": "Busy reading other STIX bundles (retry), or the processing queue is full."},
}

# At most this many baselines are read at once in this process, whichever route
# they come by: a read is CPU and memory (a 20 MB bundle parses to hundreds of
# MB), and the four rate limits that guard these routes are independent.
_INTAKE_SLOTS = threading.BoundedSemaphore(2)
_INTAKE_WAIT_S = 30.0


# Read at each request, not at import: a test (or an operator, after a restart)
# turns the mode on without reloading the module.
def enrichment_enabled() -> bool:
    return env_bool("STIX_ENRICHMENT_ENABLED", default=False)


def require_enrichment() -> None:
    if not enrichment_enabled():
        raise HTTPException(400, "STIX enrichment is not enabled on this server")


def check_baseline_request(present: bool, report_id: str | None) -> None:
    """The cheap refusals, before a byte of the baseline is read: the mode is off,
    or a `baseline_report_id` comes with no baseline."""
    if present:
        require_enrichment()
    elif report_id and report_id.strip():
        raise HTTPException(400, "baseline_report_id needs a baseline")


@contextmanager
def intake_slot() -> Iterator[None]:
    """Hold one of the process's reading slots; 503 after `_INTAKE_WAIT_S` without one."""
    if not _INTAKE_SLOTS.acquire(timeout=_INTAKE_WAIT_S):
        raise HTTPException(503, "Busy reading another STIX bundle, retry in a moment.")
    try:
        yield
    finally:
        _INTAKE_SLOTS.release()


def part_has_content(file: BinaryIO) -> bool:
    """Does an uploaded part start with something other than whitespace?  Looks at its
    first bytes only and puts the file back: it serves the refusals that must not read
    the whole baseline."""
    head = file.read(4096)
    file.seek(0)
    return bool(head.strip())


def read_baseline_file(file: BinaryIO) -> bytes:
    """The bytes of an uploaded baseline; one byte past the limit is enough to refuse."""
    return file.read(MAX_BASELINE_BYTES + 1)


def baseline_text_bytes(text: str) -> bytes:
    """The bytes of a baseline sent as text (`baseline_bundle`)."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:         # a lone surrogate: the text is no file's content
        raise HTTPException(400, "The baseline is not valid UTF-8.") from exc


def check_baseline_bytes(raw: bytes) -> None:
    """413 past the size limit, 400 unless UTF-8 (json.loads would also read UTF-16
    and UTF-32; the table holds UTF-8)."""
    if len(raw) > MAX_BASELINE_BYTES:
        raise HTTPException(
            413, f"Baseline too large. Maximum allowed size is {MAX_BASELINE_BYTES // (1024 * 1024)} MB.")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "The baseline is not valid UTF-8.") from exc


@dataclass(frozen=True)
class StoredBaseline:
    raw: bytes
    index: BaselineIndex
    intake: Intake


def read_baseline(raw: bytes | None, report_id: str | None) -> StoredBaseline | None:
    """The baseline of an ingestion request, or None when it carries none (nothing
    sent, or only whitespace).

    HTTPException 400 when the feature is off, when the bytes cannot be used
    (not UTF-8, not a STIX 2.1 bundle, several reports and no `report_id`, a
    `report_id` the bundle does not hold, a `report_id` with no bundle), 413
    when they are too large and 503 when other reads hold every slot.  Reads the
    stix2 parse only: the JSON schemas run in the worker, so a request does not
    wait seconds for them.
    """
    if raw is not None and len(raw) <= MAX_BASELINE_BYTES and not raw.strip():
        raw = None
    report_id = (report_id or "").strip() or None
    check_baseline_request(raw is not None, report_id)
    if raw is None:
        return None
    check_baseline_bytes(raw)
    try:
        with intake_slot():
            index, intake, _ = baseline_stix.intake(raw, report_id=report_id, preview=False, validate=False)
    except BaselineError as exc:
        raise HTTPException(400, str(exc)) from exc
    if index is None:              # only a preview returns no index
        raise HTTPException(400, "The baseline needs a report to be chosen.")
    return StoredBaseline(raw, index, scrubbed(intake))


def tlp_at_least(level: str, minimum: str) -> bool:
    """Is TLP `level` as restrictive as `minimum`?  Both in `normalise_tlp`'s vocabulary."""
    return TLP_LEVELS.index(level) >= TLP_LEVELS.index(minimum)


def pap_at_least(level: str, minimum: str) -> bool:
    """Is PAP `level` as restrictive as `minimum`?  Both in `_pap_marking`'s vocabulary
    (WHITE, GREEN, AMBER, RED); the order is the baseline module's, which has no public name for it."""
    return baseline_stix._PAP_ORDER.index(level) >= baseline_stix._PAP_ORDER.index(minimum)


def baseline_markings(baseline: StoredBaseline | None, tlp: str | None,
                      pap: str | None) -> tuple[str | None, str | None]:
    """The job's TLP and PAP once the baseline's minimum is applied (D2): a lower
    level is refused with 400.  With no TLP the job gets the more restrictive of the
    minimum and the server's default (STIX_TLP), so a baseline never makes a job less
    restricted than the full mode would; PAP has no default, so it takes the minimum.
    The routes call it before they store or capture anything; `start_job` calls it
    again."""
    if baseline is None:
        return tlp, pap
    intake = baseline.intake
    if intake.min_tlp is not None:
        if tlp is None:
            default = tlp_default()
            tlp = default if tlp_at_least(default, intake.min_tlp) else intake.min_tlp
        elif not tlp_at_least(tlp, intake.min_tlp):
            raise HTTPException(400, f"tlp_level {tlp} is lower than the TLP:{intake.min_tlp} the baseline carries.")
    if intake.min_pap is not None:
        if pap is None:
            pap = intake.min_pap
        elif not pap_at_least(pap, intake.min_pap):
            raise HTTPException(400, f"pap_level {pap} is lower than the PAP:{intake.min_pap} the baseline carries.")
    return tlp, pap


def start_job(
    job_id: str, dest: Path, filename: str, tlp: str | None, pap: str | None,
    *, baseline: StoredBaseline | None = None,
) -> dict[str, object]:
    """Insert the `jobs` row and hand the file to the pipeline.

    Shared by every ingestion entry point (file upload, pasted text, a
    captured URL — api/routes/upload.py and api/routes/ingest.py) so the
    queue-outcome contract lives in one place instead of three copies that
    have to be kept in sync by hand.

    With a `baseline` the job is in `enrich` mode: its row and the baseline's
    are written in one transaction, before the worker can start.
    """
    from api.worker import run_pipeline_async

    tlp, pap = baseline_markings(baseline, tlp, pap)

    ts = now_iso()
    with _lock:
        with get_conn() as conn:
            with transaction(conn):
                conn.execute(
                    "INSERT INTO jobs (id, original_filename, status, tlp_level, pap_level, pipeline_mode, "
                    "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (job_id, filename, "uploaded", tlp, pap, "enrich" if baseline else "full", ts, ts),
                )
                if baseline is not None:
                    # ASCII JSON: a NUL or a lone surrogate in a string is an escape, which PostgreSQL accepts.
                    conn.execute(
                        "INSERT INTO job_baselines (job_id, sha256, size_bytes, report_id, bundle_json, index_json, "
                        "intake_json, validated, created_at, updated_at) VALUES (?,?,?,?,?,?,?,0,?,?)",
                        (job_id, baseline.intake.sha256, len(baseline.raw), baseline.intake.scope_report_id,
                         baseline.raw.decode("utf-8"), baseline.index.to_json(), intake_json(baseline.intake),
                         ts, ts),
                    )
    if baseline is not None:
        log_exclusions(job_id, baseline.intake.excluded)

    outcome = run_pipeline_async(job_id, str(dest), filename)
    if outcome == "rejected":
        raise HTTPException(503, "The processing queue is full — try again in a few minutes.")

    # "started" keeps reporting "processing" — the value these endpoints have
    # always returned and the frontend switches on. "queued" is reported as
    # itself: answering "processing" for work that has not started is the lie
    # this contract exists to remove.
    status = "queued" if outcome == "queued" else "processing"
    return {"job_id": job_id, "filename": filename, "status": status}
