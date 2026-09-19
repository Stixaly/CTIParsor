import json
import mimetypes
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.db import _lock, get_conn, now_iso
from api.logging_config import get_logger
from api.routes._common import require_job
from api.worker import re_run_final_stages

logger = get_logger(__name__)

_ROOT        = Path(__file__).parent.parent.parent
# Folder where uploaded files are kept (mirrors upload.py UPLOADS_DIR)
_UPLOADS_DIR = _ROOT / "uploads"
_OUTPUT_DIR  = _ROOT / "output"

# Age (in days) past which a job's DB row and files are swept automatically.
# 0 (default) disables the sweep entirely -- the previous behaviour, where only
# an explicit DELETE removes a job. Uploaded reports and STIX bundles otherwise
# accumulate on disk forever: nothing before this purged them, so an analyst
# who never clicks delete slowly fills the disk.
JOB_RETENTION_DAYS = int(os.getenv("JOB_RETENTION_DAYS", "0"))

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
    for f in _UPLOADS_DIR.glob(f"{job_id}.*"):
        f.unlink(missing_ok=True)

    # 2 — STIX bundle(s) — reconstruct report_name the same way the worker does
    report_name = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)
    out_path = bundle_output_path(job_id, report_name)
    out_path.unlink(missing_ok=True)
    out_path.with_stem(out_path.stem + "_invalid").unlink(missing_ok=True)
    # Best-effort cleanup of the legacy non-job-scoped names written by older
    # builds (these collided across same-filename jobs — see bundle_output_path).
    (_OUTPUT_DIR / f"{report_name}_bundle.json").unlink(missing_ok=True)
    (_OUTPUT_DIR / f"{report_name}_bundle_invalid.json").unlink(missing_ok=True)

    # 3 — Stage 3 LLM checkpoint (and its .tmp rename-in-progress counterpart)
    (_OUTPUT_DIR / f"{job_id}_stage3.ckpt.json").unlink(missing_ok=True)
    (_OUTPUT_DIR / f"{job_id}_stage3.ckpt.tmp").unlink(missing_ok=True)


class StatusPatch(BaseModel):
    status: str


@router.get("")
def list_jobs():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, original_filename, status, tlp_level, pap_level, created_at, updated_at "
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
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return jobs


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

    return {
        "id": row["id"],
        "original_filename": row["original_filename"],
        "status": row["status"],
        "report_text": row["report_text"],
        "tlp_level": row["tlp_level"],
        "pap_level": row["pap_level"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "entity_count": entity_count,
        "relationship_count": rel_count,
    }


@router.patch("/{job_id}")
def update_job_status(job_id: str, patch: StatusPatch):
    valid = {"uploaded", "processing", "for_review", "reviewing", "completed", "failed"}
    if patch.status not in valid:
        raise HTTPException(400, f"Invalid status. Valid: {valid}")
    with _lock:
        with get_conn() as conn:
            result = conn.execute(
                "UPDATE jobs SET status=?, updated_at=? WHERE id=?",
                (patch.status, now_iso(), job_id),
            )
            conn.commit()
            rowcount = result.rowcount
    # Raise outside the lock so the lock is always released cleanly
    if rowcount == 0:
        raise HTTPException(404, "Job not found")
    return {"status": patch.status}


@router.post("/{job_id}/finalize")
def finalize_job(job_id: str, quick: bool = False):
    """
    Re-run Stages 4+5 and regenerate the STIX bundle.

    quick=false (default) — full finalize: runs the lexicon re-scan before
        building the bundle.  Used when the reviewer clicks the Finalize button.

    quick=true — fast finalize: skips the lexicon re-scan.  Used by the
        debounced auto-finalize triggered after every entity/relationship change
        so the bundle stays current without user action.
        Call via POST /api/jobs/{id}/finalize?quick=true
    """
    with get_conn() as conn:
        require_job(conn, job_id)

    bundle_json = re_run_final_stages(job_id, skip_rescan=quick)
    if bundle_json is None:
        raise HTTPException(500, "Finalize failed — check server logs")

    return {"status": "completed", "bundle_size": len(bundle_json)}


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
                "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not row:
                return False
            original_filename = row["original_filename"]

            # Delete children first so a crash mid-delete doesn't leave orphaned rows
            # (the FK CASCADE would do this automatically when foreign_keys=ON, but
            # deleting explicitly makes the order safe regardless of PRAGMA state)
            conn.execute("DELETE FROM entities WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM relationships WHERE job_id=?", (job_id,))
            conn.execute("DELETE FROM progress_events WHERE job_id=?", (job_id,))
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

    matches = list(_UPLOADS_DIR.glob(f"{job_id}.*"))
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

    return FileResponse(
        path=str(fpath),
        media_type=mime,
        # inline disposition so PDFs open in the browser instead of downloading
        headers={"Content-Disposition": f"inline; filename=\"{fpath.name}\""},
    )


@router.get("/{job_id}/bundle")
def get_bundle(job_id: str):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT bundle_json, original_filename FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        if not row["bundle_json"]:
            raise HTTPException(404, "Bundle not yet available")

    try:
        return json.loads(row["bundle_json"])
    except Exception:
        raise HTTPException(500, "Bundle JSON is corrupted")
