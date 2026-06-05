from pathlib import Path
from uuid import uuid4
from fastapi import APIRouter, UploadFile, File, HTTPException
from api.db import get_conn, now_iso, _lock
from api.worker import run_pipeline_async

router = APIRouter(prefix="/api", tags=["upload"])

UPLOADS_DIR = Path(__file__).parent.parent.parent / "uploads"
SUPPORTED = {".pdf", ".docx", ".html", ".htm", ".txt", ".md"}

# 50 MB upload limit
_MAX_BYTES = 50 * 1024 * 1024


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    suffix = Path(file.filename or "file").suffix.lower()
    if suffix not in SUPPORTED:
        raise HTTPException(400, f"Unsupported format '{suffix}'. Accepted: {', '.join(SUPPORTED)}")

    job_id = str(uuid4())
    dest = UPLOADS_DIR / f"{job_id}{suffix}"
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Stream to disk while enforcing the size limit
    written = 0
    try:
        with dest.open("wb") as f:
            while chunk := await file.read(1024 * 64):  # 64 KB chunks
                written += len(chunk)
                if written > _MAX_BYTES:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(413, "File too large. Maximum allowed size is 50 MB.")
                f.write(chunk)
    except HTTPException:
        raise  # re-raise 413 as-is
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, "File upload failed — disk write error") from exc

    ts = now_iso()
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
                (job_id, file.filename, "uploaded", ts, ts),
            )
            conn.commit()

    run_pipeline_async(job_id, str(dest), file.filename or "unknown")

    return {"job_id": job_id, "filename": file.filename, "status": "processing"}
