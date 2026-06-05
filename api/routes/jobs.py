import json
import re
import mimetypes
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from api.db import get_conn, now_iso, _lock
from api.worker import re_run_final_stages

_ROOT        = Path(__file__).parent.parent.parent
# Folder where uploaded files are kept (mirrors upload.py UPLOADS_DIR)
_UPLOADS_DIR = _ROOT / "uploads"
_OUTPUT_DIR  = _ROOT / "output"

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


def _delete_job_files(job_id: str, original_filename: str) -> None:
    """
    Remove all files that were produced for this job:
      • uploads/{job_id}.*              — original uploaded document
      • output/{report_name}_bundle.json         — valid STIX bundle
      • output/{report_name}_bundle_invalid.json — bundle written when validation fails
      • output/{job_id}_stage3.ckpt.json         — LLM checkpoint (deleted on clean finish,
                                                    kept on crash — clean it up now)
      • output/{job_id}_stage3.ckpt.tmp          — atomic-rename temp file if crash mid-save

    All unlinks use missing_ok=True so a partially-created job (e.g. pipeline
    crashed before writing the bundle) doesn't raise.
    """
    # 1 — Original uploaded file (glob so we don't need to know the extension)
    for f in _UPLOADS_DIR.glob(f"{job_id}.*"):
        f.unlink(missing_ok=True)

    # 2 — STIX bundle(s) — reconstruct report_name the same way the worker does
    report_name = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)
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
            "SELECT id, original_filename, status, created_at, updated_at FROM jobs ORDER BY created_at DESC"
        ).fetchall()
    jobs = []
    for row in rows:
        jobs.append({
            "id": row["id"],
            "original_filename": row["original_filename"],
            "status": row["status"],
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
        row = conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")

    bundle_json = re_run_final_stages(job_id, skip_rescan=quick)
    if bundle_json is None:
        raise HTTPException(500, "Finalize failed — check server logs")

    return {"status": "completed", "bundle_size": len(bundle_json)}


@router.delete("/{job_id}")
def delete_job(job_id: str):
    with _lock:
        with get_conn() as conn:
            # Fetch original_filename BEFORE deleting — needed to locate output files
            row = conn.execute(
                "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
            ).fetchone()
            if not row:
                raise HTTPException(404, "Job not found")
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

    return {"deleted": job_id}


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
        row = conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Job not found")

    matches = list(_UPLOADS_DIR.glob(f"{job_id}.*"))
    if not matches:
        raise HTTPException(404, "Source file not found — it may have been removed")

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
