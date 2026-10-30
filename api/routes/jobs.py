import json
import mimetypes
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from api.baseline_store import EXCLUDED_LISTED
from api.db import _lock, get_conn, now_iso
from api.logging_config import get_logger
from api.paths import output_dir, uploads_dir
from api.routes._common import require_job
from api.worker import BundleInvalidError, re_run_final_stages
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


def _stored_errors(raw: str | None) -> list[str]:
    """`jobs.bundle_validation_errors` (a JSON list, already cut short by the worker)."""
    try:
        return json.loads(raw or "[]")
    except ValueError:
        return []


@router.get("")
def list_jobs():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, original_filename, status, tlp_level, pap_level, pipeline_mode, created_at, updated_at "
            "FROM jobs ORDER BY created_at DESC"
        ).fetchall()
    jobs = []
    for row in rows:
        jobs.append({
            "id": row["id"],
            "original_filename": row["original_filename"],
            "status": row["status"],
            "tlp_level": row["tlp_level"],
            "pap_level": row["pap_level"],
            "pipeline_mode": row["pipeline_mode"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return jobs


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


@router.get("/{job_id}")
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


@router.get("/{job_id}/baseline", responses=_NO_BASELINE)
def get_baseline(job_id: str):
    """The STIX bundle the job was created from (ADR-0090), byte for byte, as a download."""
    with get_conn() as conn:
        row = conn.execute("SELECT bundle_json FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "No baseline for this job")
    return Response(row["bundle_json"], media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=\"{job_id}_baseline.json\""})


@router.get("/{job_id}/baseline/intake", responses=_NO_BASELINE)
def get_baseline_intake(job_id: str):
    """What the intake made of the job's baseline, whole: the counts, every object left out and
    why, the reports, the markings.  `GET /api/jobs/{id}` carries the first of the exclusions."""
    with get_conn() as conn:
        row = conn.execute("SELECT intake_json FROM job_baselines WHERE job_id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "No baseline for this job")
    return Response(row["intake_json"], media_type="application/json")


@router.patch("/{job_id}", responses=_BUNDLE_REFUSED)
def update_job_status(job_id: str, patch: StatusPatch):
    """Set a job's status.  409 for `completed` while the stored bundle is one
    the STIX schemas refused (see finalize)."""
    valid = {"for_review", "reviewing", "completed", "failed"}
    if patch.status not in valid:
        raise HTTPException(400, f"Invalid status. Valid: {valid}")
    refused: list[str] | None = None
    rowcount = 0
    with _lock:
        with get_conn() as conn:
            # Read and write under the same lock and connection: a rebuild
            # cannot slip its verdict in between.
            if patch.status == "completed":
                row = conn.execute(
                    "SELECT bundle_validation, bundle_validation_errors FROM jobs WHERE id=?", (job_id,)
                ).fetchone()
                if row and row["bundle_validation"] == "invalid":
                    refused = _stored_errors(row["bundle_validation_errors"])
            if refused is None:
                result = conn.execute(
                    "UPDATE jobs SET status=?, updated_at=? WHERE id=?",
                    (patch.status, now_iso(), job_id),
                )
                conn.commit()
                rowcount = result.rowcount
    # Raise outside the lock so the lock is always released cleanly
    if refused is not None:
        raise _bundle_refused(refused)
    if rowcount == 0:
        raise HTTPException(404, "Job not found")
    return {"status": patch.status}


@router.post("/{job_id}/finalize", responses=_BUNDLE_REFUSED)
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
    if bundle_json is None:
        raise HTTPException(500, "Finalize failed — check server logs")

    with get_conn() as conn:
        row = conn.execute("SELECT status, bundle_validation FROM jobs WHERE id=?", (job_id,)).fetchone()
    return {"status": row["status"] if row else "completed", "bundle_size": len(bundle_json),
            "validation": (row["bundle_validation"] if row else None) or "unknown"}


def _delete_job(job_id: str) -> bool:
    """Delete one job's DB rows and files. Returns False if it did not exist.

    Shared by the DELETE route and the retention sweep so both apply the exact
    same cleanup — a second copy of this would drift the moment one of them
    gained a new output file type.
    """
    with _lock:
        with get_conn() as conn:
            # Fetch original_filename BEFORE deleting — needed to locate output files
            row = conn.execute(
                "SELECT id, original_filename FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not row:
                return False
            # From here on the id is the one the database holds (a uuid the
            # server generated), never the request's string: it names files.
            job_id, original_filename = row["id"], row["original_filename"]

            # Delete children first so a crash mid-delete doesn't leave orphaned rows
            # (the FK CASCADE would do this automatically when foreign_keys=ON, but
            # deleting explicitly makes the order safe regardless of PRAGMA state)
            conn.execute("DELETE FROM entities WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM relationships WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM progress_events WHERE job_id=?", (job_id,))
            # The foreign key would do it; deleting explicitly keeps the order safe, as for the rows above.
            conn.execute("DELETE FROM job_baselines WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
            conn.commit()

    # Delete associated files AFTER the DB transaction commits successfully.
    # If file deletion partially fails the DB is already clean — no orphaned rows.
    _delete_job_files(job_id, original_filename)
    return True


@router.delete("/{job_id}")
def delete_job(job_id: str):
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
    for job_id in ids:
        try:
            if _delete_job(job_id):
                deleted += 1
        except Exception as exc:
            logger.error(f"[retention] failed to delete job {job_id}: {exc}")

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


@router.get("/{job_id}/source")
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


@router.get("/{job_id}/bundle", responses=_BUNDLE_REFUSED)
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


@router.get("/{job_id}/bundle/ledger")
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
