import base64
import json
import mimetypes
import re
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from api.auth.deps import current_user
from api.auth.store import User
from api.baseline_store import EXCLUDED_LISTED
from api.db import _lock, get_conn, now_iso, transaction
from api.logging_config import get_logger
from api.paths import output_dir, uploads_dir
from api.response_models.jobs import (
    BundleLedger,
    DeleteResult,
    FinalizeResult,
    JobDetail,
    JobSummary,
    StatusResult,
)
from api.routes._common import require_job
from api.worker import BundleInvalidError, FinalizeOvertaken, re_run_final_stages
from pipeline.env_flags import env_int

logger = get_logger(__name__)

# Age (in days) past which a job's DB row and files are swept automatically.
# 0 (default) disables the sweep entirely -- the previous behaviour, where only
# an explicit DELETE removes a job. Uploaded reports and STIX bundles otherwise
# accumulate on disk forever: nothing before this purged them, so an analyst
# who never clicks delete slowly fills the disk.
JOB_RETENTION_DAYS = env_int("JOB_RETENTION_DAYS", default=0)

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def _delete_job_files(job_id: str, original_filename: str) -> None:
    """
    Remove all files that were produced for this job:
      • uploads/{job_id}.*                              — original uploaded document
      • output/{report_name}_{job_id}_bundle.json         — valid STIX bundle
      • output/{report_name}_{job_id}_bundle_invalid.json — bundle written when validation fails
      • output/{job_id}_stage3.ckpt.json                  — LLM checkpoint (deleted on clean finish,
                                                            kept on crash — clean it up now)
      • output/{job_id}_stage3.ckpt.tmp                   — atomic-rename temp file if crash mid-save

    All unlinks use missing_ok=True so a partially-created job (e.g. pipeline
    crashed before writing the bundle) doesn't raise.
    """
    from api.worker import bundle_output_path

    # 1 — Original uploaded file (glob so we don't need to know the extension)
    uploads, output = uploads_dir(), output_dir()
    for f in uploads.glob(f"{job_id}.*"):
        f.unlink(missing_ok=True)
    # …and a URL capture's publication metadata (ADR-0063), kept in a
    # subdirectory so the glob above never mistakes it for the source.
    (uploads / "meta" / f"{job_id}.json").unlink(missing_ok=True)

    # 2 — STIX bundle(s) — reconstruct report_name the same way the worker does
    report_name = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)
    out_path = bundle_output_path(job_id, report_name)
    out_path.unlink(missing_ok=True)
    out_path.with_stem(out_path.stem + "_invalid").unlink(missing_ok=True)
    # Best-effort cleanup of the legacy non-job-scoped names written by older
    # builds (these collided across same-filename jobs — see bundle_output_path).
    (output / f"{report_name}_bundle.json").unlink(missing_ok=True)
    (output / f"{report_name}_bundle_invalid.json").unlink(missing_ok=True)

    # 3 — Stage 3 LLM checkpoint (and its .tmp rename-in-progress counterpart)
    (output / f"{job_id}_stage3.ckpt.json").unlink(missing_ok=True)
    (output / f"{job_id}_stage3.ckpt.tmp").unlink(missing_ok=True)


class StatusPatch(BaseModel):
    status: str


# One code for "Stage 5's schemas refused this bundle", on every route that
# serves or completes it.  Not 422: FastAPI declares that one with a list
# `detail` (HTTPValidationError), and ours is an object.
_BUNDLE_REFUSED: dict[int | str, dict[str, Any]] = {409: {
    "description": "Stage 5's STIX 2.1 schemas refused the bundle; "
                   "`detail` is {\"validation\": \"invalid\", \"errors\": [...]}.",
}}


def _bundle_refused(errors: list[str]) -> HTTPException:
    return HTTPException(409, detail={"validation": "invalid", "errors": errors})


# DELETE and PATCH refuse a job a worker is running, whatever its lease (#385): a
# status change would take the job out of the heartbeat's reach.
_PROCESSING_DETAIL = "job is currently processing — stop it or wait for it to finish"


def _stored_errors(raw: str | None) -> list[str]:
    """`jobs.bundle_validation_errors` (a JSON list, already cut short by the worker)."""
    try:
        return json.loads(raw or "[]")
    except ValueError:
        return []


_JOB_SUMMARY_COLUMNS = ("SELECT id, original_filename, status, tlp_level, pap_level, pipeline_mode, created_at, "
                        "updated_at FROM jobs")
_CURSOR_MALFORMED = "malformed cursor"


def _summary(row) -> dict:
    return {
        "id": row["id"],
        "original_filename": row["original_filename"],
        "status": row["status"],
        "tlp_level": row["tlp_level"],
        "pap_level": row["pap_level"],
        "pipeline_mode": row["pipeline_mode"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _encode_cursor(created_at: str, job_id: str) -> str:
    """The opaque `cursor` of a page: the (created_at, id) of its last job, base64url of JSON."""
    raw = json.dumps([created_at, job_id], separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    """(created_at, id) of a `cursor`; 400 when it is not one this endpoint wrote."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True))
    except (ValueError, TypeError):
        raise HTTPException(400, _CURSOR_MALFORMED) from None
    if not (isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) for v in value)):
        raise HTTPException(400, _CURSOR_MALFORMED)
    return value[0], value[1]


@router.get("", response_model=list[JobSummary], response_model_exclude_unset=True)
def list_jobs(
    response: Response,
    limit: int | None = Query(None, ge=1, le=500, description="Most jobs in this page (1-500)."),
    cursor: str | None = Query(None, description="The X-Next-Cursor of the previous page."),
):
    """Every job, newest first.  Without `limit` the whole list, as before.  With `limit`, one page of at
    most `limit` jobs, ordered by created_at DESC then id DESC; when more jobs follow, the response
    header X-Next-Cursor holds the cursor of the next page (keyset pagination, no OFFSET)."""
    if limit is None:
        if cursor is not None:
            raise HTTPException(400, "cursor needs limit")
        with get_conn() as conn:
            rows = conn.execute(_JOB_SUMMARY_COLUMNS + " ORDER BY created_at DESC").fetchall()
        return [_summary(row) for row in rows]

    sql = _JOB_SUMMARY_COLUMNS
    params: list[Any] = []
    if cursor is not None:
        created_at, last_id = _decode_cursor(cursor)
        sql += " WHERE (created_at < ? OR (created_at = ? AND id < ?))"
        params += [created_at, created_at, last_id]
    # One row more than the page: its presence says whether another page follows.
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit + 1)
    with get_conn() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
    page = rows[:limit]
    if len(rows) > limit:
        last = page[-1]
        response.headers["X-Next-Cursor"] = _encode_cursor(last["created_at"], last["id"])
    return [_summary(row) for row in page]


def _enrichment(conn, job_id: str) -> dict:
    """A job in `enrich` mode (ADR-0090): what the intake made of the baseline, whether the
    worker has validated it against the JSON schemas, and how many rows have each
    `enrichment_status` (none until Stage 3r writes them).  Never the bundle itself, and
    the objects left out are the first EXCLUDED_LISTED with their total: the whole list
    is GET /api/jobs/{id}/baseline/intake."""
    base = conn.execute(
        "SELECT intake_json, validated FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()
    counts: dict[str, dict[str, int]] = {}
    for table in ("entities", "relationships"):
        rows = conn.execute(
            f"SELECT enrichment_status, COUNT(*) AS n FROM {table} "
            "WHERE job_id=? AND enrichment_status IS NOT NULL GROUP BY enrichment_status", (job_id,)).fetchall()
        counts[table] = {r["enrichment_status"]: r["n"] for r in rows}
    intake = json.loads(base["intake_json"]) if base else None
    if intake is not None:
        intake["excluded_total"] = len(intake["excluded"])
        intake["excluded"] = intake["excluded"][:EXCLUDED_LISTED]
    return {"intake": intake, "validated": bool(base and base["validated"]), "counts": counts}


@router.get("/{job_id}", response_model=JobDetail, response_model_exclude_unset=True)
def get_job(job_id: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        entity_count = conn.execute(
            "SELECT COUNT(*) FROM entities WHERE job_id=?", (job_id,)
        ).fetchone()[0]
        rel_count = conn.execute(
            "SELECT COUNT(*) FROM relationships WHERE job_id=?", (job_id,)
        ).fetchone()[0]
        enrichment = _enrichment(conn, job_id) if row["pipeline_mode"] == "enrich" else None

    job = {
        "id": row["id"],
        "original_filename": row["original_filename"],
        "status": row["status"],
        "report_text": row["report_text"],
        "tlp_level": row["tlp_level"],
        "pap_level": row["pap_level"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "pipeline_mode": row["pipeline_mode"],
        "entity_count": entity_count,
        "relationship_count": rel_count,
    }
    if enrichment is not None:
        job["enrichment"] = enrichment
    return job


_NO_BASELINE: dict[int | str, dict[str, Any]] = {404: {"description": "No such job, or a job with no baseline."}}
# The two baseline routes answer the stored text as JSON: the bundle, or the intake (BaselineIntake).
_BASELINE_JSON: dict[int | str, dict[str, Any]] = {200: {
    "description": "The JSON text stored for the job (bytes as received, or the intake).",
    "content": {"application/json": {}},
}}


@router.get("/{job_id}/baseline", responses={**_NO_BASELINE, **_BASELINE_JSON})
def get_baseline(job_id: str):
    """The STIX bundle the job was created from (ADR-0090), byte for byte, as a download."""
    with get_conn() as conn:
        row = conn.execute("SELECT bundle_json FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "No baseline for this job")
    return Response(row["bundle_json"], media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=\"{job_id}_baseline.json\""})


@router.get("/{job_id}/baseline/intake", responses={**_NO_BASELINE, **_BASELINE_JSON})
def get_baseline_intake(job_id: str):
    """What the intake made of the job's baseline, whole: the counts, every object left out and
    why, the reports, the markings.  `GET /api/jobs/{id}` carries the first of the exclusions."""
    with get_conn() as conn:
        row = conn.execute("SELECT intake_json FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "No baseline for this job")
    return Response(row["intake_json"], media_type="application/json")


@router.patch("/{job_id}", response_model=StatusResult, response_model_exclude_unset=True,
               responses=_BUNDLE_REFUSED)
def update_job_status(job_id: str, patch: StatusPatch):
    """Set a job's status.  409 while a worker runs the job (#385, as DELETE does), and
    409 for `completed` while the stored bundle is one the STIX schemas refused (see finalize)."""
    valid = {"for_review", "reviewing", "completed", "failed"}
    if patch.status not in valid:
        raise HTTPException(400, f"Invalid status. Valid: {valid}")
    running = False
    refused: list[str] | None = None
    conflict: str | None = None
    rowcount = 0
    with _lock:
        with get_conn() as conn:
            # Read and write under the same lock and connection: a rebuild
            # cannot slip its verdict in between.
            row = conn.execute(
                "SELECT status, bundle_json, bundle_validation, bundle_validation_errors "
                "FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if row and row["status"] == "processing":
                # The heartbeat stamps only `processing` rows: a status set here
                # would leave the job unleased, and requeue_orphans would never
                # take it back.
                running = True
            elif patch.status == "completed":
                if row and row["bundle_validation"] == "invalid":
                    refused = _stored_errors(row["bundle_validation_errors"])
                elif row and (row["bundle_json"] is None
                              or row["status"] in ("uploaded", "queued")):
                    # A job still in a worker-execution state, or without a
                    # built bundle, must not be marked completed.
                    conflict = (f"job is {row['status']!r} with no STIX bundle yet")
            if not running and refused is None and conflict is None:
                if patch.status == "completed":
                    # The guard is repeated in the UPDATE's WHERE so a worker
                    # writing concurrently cannot slip between the SELECT and
                    # the UPDATE.
                    result = conn.execute(
                        "UPDATE jobs SET status=?, updated_at=? WHERE id=? "
                        "AND bundle_json IS NOT NULL "
                        "AND bundle_validation IS DISTINCT FROM 'invalid' "
                        "AND status NOT IN ('uploaded','queued','processing')",
                        (patch.status, now_iso(), job_id),
                    )
                else:
                    # Same guard as DELETE's: a worker may claim the job after the SELECT.
                    result = conn.execute(
                        "UPDATE jobs SET status=?, updated_at=? WHERE id=? AND status <> 'processing'",
                        (patch.status, now_iso(), job_id),
                    )
                conn.commit()
                rowcount = result.rowcount
                if rowcount == 0 and row is not None:
                    again = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                    running = again is not None and again["status"] == "processing"
    # Raise outside the lock so the lock is always released cleanly
    if running:
        raise HTTPException(409, _PROCESSING_DETAIL)
    if refused is not None:
        raise _bundle_refused(refused)
    if conflict is not None:
        raise HTTPException(409, f"Cannot mark job completed: {conflict}")
    if rowcount == 0:
        if row is not None and patch.status == "completed":
            raise HTTPException(409, "Cannot mark job completed: no STIX bundle or still running")
        raise HTTPException(404, "Job not found")
    return {"status": patch.status}


@router.post("/{job_id}/finalize", response_model=FinalizeResult, response_model_exclude_unset=True,
             responses=_BUNDLE_REFUSED)
def finalize_job(job_id: str, quick: bool = False):
    """
    Re-run Stages 4+5 and regenerate the STIX bundle.

    quick=false (default) — full finalize: the rebuild also completes the job.
        Used when the reviewer clicks the Finalize button.

    quick=true — fast finalize: used by the debounced auto-finalize triggered
        after every entity/relationship change so the bundle stays current
        without user action.  It rebuilds the bundle only: the report keeps its
        status (completing it is the reviewer's click).
        Call via POST /api/jobs/{id}/finalize?quick=true

    Either way, 409 when Stage 5's JSON schemas refuse the rebuilt bundle: the
    job is not completed (one that was goes back to for_review) and the
    response lists the first errors.  The response of a success carries the
    bundle's `validation`: validated, unverified (schemas missing) or unknown.
    """
    with get_conn() as conn:
        require_job(conn, job_id)

    try:
        bundle_json = re_run_final_stages(job_id, quick=quick)
    except BundleInvalidError as exc:
        raise _bundle_refused(exc.errors) from exc
    except FinalizeOvertaken as exc:
        raise HTTPException(409, "Review decisions changed during every rebuild; finalize again "
                                 "once the review settles") from exc
    if bundle_json is None:
        raise HTTPException(500, "Finalize failed — check server logs")

    with get_conn() as conn:
        row = conn.execute("SELECT status, bundle_validation FROM jobs WHERE id=?", (job_id,)).fetchone()
    return {"status": row["status"] if row else "completed", "bundle_size": len(bundle_json),
            "validation": (row["bundle_validation"] if row else None) or "unknown"}


class _NotDeleted(Exception):
    """The guarded DELETE of the jobs row matched nothing: roll the transaction back."""


# The cutoff of the retention sweep in progress (sweep_expired_jobs), or None.  While it is set,
# _delete_job deletes a job only if it is still expired, and its DELETE repeats that test (#488).
_sweep_cutoff: ContextVar[str | None] = ContextVar("sweep_cutoff", default=None)


def _delete_job(job_id: str) -> bool:
    """Delete one job's DB rows and files. Returns False if it did not exist.

    Shared by the DELETE route and the retention sweep so both apply the exact
    same cleanup — a second copy of this would drift the moment one of them
    gained a new output file type.

    Under the sweep (`_sweep_cutoff` set) a job that is queued, processing or
    was updated after the cutoff is kept, and so is one that changes between
    the read below and the DELETE: the sweep's list is only a choice of
    candidates, the DELETE decides.  Returns False then, not 409.
    """
    cutoff = _sweep_cutoff.get()
    with _lock:
        with get_conn() as conn:
            # Fetch original_filename BEFORE deleting — needed to locate output files
            row = conn.execute(
                "SELECT id, original_filename, status, updated_at FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not row:
                return False
            if cutoff is not None and (row["status"] in ("queued", "processing") or row["updated_at"] >= cutoff):
                return False
            if row["status"] == "processing":
                # Deleting a running job would orphan the worker's writes
                # (progress_events rows, output/ files) mid-pipeline.
                raise HTTPException(409, _PROCESSING_DETAIL)
            # From here on the id is the one the database holds (a uuid the
            # server generated), never the request's string: it names files.
            job_id, original_filename = row["id"], row["original_filename"]

            # One transaction: the connection is autocommit, so without this
            # each DELETE would commit separately and a crash mid-delete would
            # leave orphaned rows.
            try:
                with transaction(conn):
                    # Delete children first so a crash mid-delete doesn't leave orphaned rows
                    # (the FK CASCADE would do this automatically when foreign_keys=ON, but
                    # deleting explicitly makes the order safe regardless of PRAGMA state)
                    conn.execute("DELETE FROM entities WHERE job_id=?", (job_id,))
                    conn.execute("DELETE FROM relationships WHERE job_id=?", (job_id,))
                    conn.execute("DELETE FROM progress_events WHERE job_id=?", (job_id,))
                    # The foreign key would do it; deleting explicitly keeps the order safe, as for the rows above.
                    conn.execute("DELETE FROM job_baselines WHERE job_id=?", (job_id,))
                    # The status test is part of the DELETE: a worker may claim
                    # the job between the SELECT above and here.  Under the sweep
                    # the expiry is tested here too, for the same reason (#488).
                    # 0 rows rolls the children back with it.
                    if cutoff is None:
                        cur = conn.execute(
                            "DELETE FROM jobs WHERE id=? AND status <> 'processing'", (job_id,)
                        )
                    else:
                        cur = conn.execute(
                            "DELETE FROM jobs WHERE id=? AND status NOT IN ('queued','processing') "
                            "AND updated_at < ?", (job_id, cutoff),
                        )
                    if cur.rowcount == 0:
                        raise _NotDeleted
            except _NotDeleted:
                again = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
                if not again or cutoff is not None:
                    return False
                raise HTTPException(409, _PROCESSING_DETAIL) from None

    # Delete associated files AFTER the DB transaction commits successfully.
    # If file deletion partially fails the DB is already clean — no orphaned rows.
    _delete_job_files(job_id, original_filename)
    return True


def may_delete(user: User, imported_by: str | None) -> bool:
    """An admin deletes any report; an analyst only one they imported.  A report with
    no owner (stored before migration 18) is an admin's to delete."""
    return user.role == "admin" or (imported_by is not None and imported_by == user.id)


@router.delete("/{job_id}", response_model=DeleteResult, response_model_exclude_unset=True,
               responses={403: {"description": "An analyst deletes only the reports they imported."}})
def delete_job(job_id: str, user: User | None = Depends(current_user)):
    if user is not None and user.role != "admin":
        row = get_conn().execute("SELECT imported_by FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is not None and not may_delete(user, row["imported_by"]):
            raise HTTPException(403, "Only an admin, or the analyst who imported this report, may delete it")
    if not _delete_job(job_id):
        raise HTTPException(404, "Job not found")
    return {"deleted": job_id}


def sweep_expired_jobs(retention_days: int | None = None) -> int:
    """Delete every job whose last update is older than the retention window.

    Called periodically by the queue loop (api/queue_loop.py), never by a
    request handler. `queued`/`processing` jobs are excluded regardless of
    age — they are active work, not abandoned output — everything else
    (`uploaded`, `for_review`, `completed`, `failed`) is eligible once stale,
    since a row stuck at `uploaded` past the window is itself an anomaly worth
    clearing rather than a job to protect.

    Returns the number of jobs deleted. A no-op when retention is disabled
    (the default: JOB_RETENTION_DAYS=0).
    """
    days = JOB_RETENTION_DAYS if retention_days is None else retention_days
    if days <= 0:
        return 0

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    try:
        with get_conn() as conn:
            ids = [
                r[0] for r in conn.execute(
                    "SELECT id FROM jobs WHERE status NOT IN ('queued','processing') "
                    "AND updated_at < ?",
                    (cutoff,),
                ).fetchall()
            ]
    except Exception as exc:
        logger.error(f"[retention] failed to list expired jobs: {exc}")
        return 0

    deleted = 0
    token = _sweep_cutoff.set(cutoff)
    try:
        for job_id in ids:
            try:
                if _delete_job(job_id):
                    deleted += 1
            except Exception as exc:
                logger.error(f"[retention] failed to delete job {job_id}: {exc}")
    finally:
        _sweep_cutoff.reset(token)

    if deleted:
        logger.info(f"[retention] swept {deleted} job(s) older than {days}d")
    return deleted


# What an imported report may load: its own data: URIs and nothing else.  The viewer's
# sandbox stops scripts but not image or style requests, so a tracking pixel would
# otherwise report the analyst's address to its author (and hang on an air-gapped host).
_SOURCE_CSP = ("default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; "
               "base-uri 'none'; form-action 'none'")
# Types the browser renders as a page (XML through <?xml-stylesheet?>): the policy goes
# on these, not on a PDF, whose viewer it can break.
_PAGE_MIMES = {"text/html", "application/xhtml+xml", "image/svg+xml", "application/xml", "text/xml"}


@router.get("/{job_id}/source", responses={200: {
    "description": "The uploaded report: a PDF inline, or the type its suffix names (DOCX, HTML, text, "
                   "Markdown); application/octet-stream for another suffix.",
    "content": {"*/*": {}},
}})
def get_source_file(job_id: str):
    """
    Stream the original uploaded file back to the browser.

    The file is stored as  uploads/{job_id}{original_suffix}  (e.g. .pdf, .docx).
    We glob for it so the caller never needs to know the extension.
    The Content-Type header is set from the file suffix so browsers can render
    PDFs inline and download other formats correctly.
    """
    with get_conn() as conn:
        require_job(conn, job_id)

    matches = list(uploads_dir().glob(f"{job_id}.*"))
    if not matches:
        raise HTTPException(404, "Source file not found — it may have been removed")

    # A URL capture writes two files under this job id: the .pdf the analyst
    # should look at, and the .txt the pipeline actually ingested (ADR-0029).
    # Glob order is arbitrary, so pick the one meant for the viewer rather than
    # whichever the filesystem listed first; `.pdf.part` is a capture that timed
    # out mid-render and must never be served.
    matches = [m for m in matches if m.suffix.lower() != ".part"]
    if not matches:
        raise HTTPException(404, "Source file not found — it may have been removed")
    matches.sort(key=lambda m: (m.suffix.lower() != ".pdf", m.name))

    fpath     = matches[0]
    mime, _   = mimetypes.guess_type(str(fpath))
    mime      = mime or "application/octet-stream"

    headers = {"Content-Disposition": f"inline; filename=\"{fpath.name}\""}
    if mime in _PAGE_MIMES:
        headers["Content-Security-Policy"] = _SOURCE_CSP

    return FileResponse(
        path=str(fpath),
        media_type=mime,
        # inline disposition so PDFs open in the browser instead of downloading
        headers=headers,
    )


@router.get("/{job_id}/bundle", responses={**_BUNDLE_REFUSED, 200: {
    "description": "The stored STIX 2.1 bundle, as JSON.",
    "content": {"application/json": {}},
    "headers": {"X-Bundle-Validation": {
        "description": "validated, unverified (JSON schemas missing) or unknown (built before the verdict was stored).",
        "schema": {"type": "string"},
    }},
}})
def get_bundle(job_id: str):
    """The stored bundle, with Stage 5's verdict in the `X-Bundle-Validation`
    header: validated, unverified (JSON schemas missing) or unknown (built
    before the verdict was stored).  409 when the schemas refused it: the graph
    view and the download both read this route, and an invalid bundle is not
    served by either; a rebuild (POST /finalize) that passes replaces it."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT bundle_json, bundle_validation, bundle_validation_errors FROM jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        if not row["bundle_json"]:
            raise HTTPException(404, "Bundle not yet available")

    validation = row["bundle_validation"]
    if validation == "invalid":
        raise _bundle_refused(_stored_errors(row["bundle_validation_errors"]))

    try:
        bundle = json.loads(row["bundle_json"])
    except Exception as exc:
        raise HTTPException(500, "Bundle JSON is corrupted") from exc
    return JSONResponse(bundle, headers={"X-Bundle-Validation": validation or "unknown"})


@router.get("/{job_id}/bundle/ledger", response_model=BundleLedger, response_model_exclude_unset=True)
def get_bundle_ledger(job_id: str):
    """What Stage 4 did with each entity and relationship row when it built the
    stored bundle (ADR-0061): what each became, what was rewritten, what was
    dropped and why, and why each generated object and edge exists.

    404 when the bundle predates the ledger (or was written without one); a
    rebuild (POST /finalize?quick=true) produces it.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT bundle_json, bundle_ledger_json FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        if not row["bundle_json"]:
            raise HTTPException(404, "Bundle not yet available")
        if not row["bundle_ledger_json"]:
            raise HTTPException(404, "No ledger for this bundle — rebuild it to get one")

    try:
        return json.loads(row["bundle_ledger_json"])
    except Exception as exc:
        raise HTTPException(500, "Bundle ledger JSON is corrupted") from exc
