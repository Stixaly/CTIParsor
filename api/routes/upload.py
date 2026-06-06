from pathlib import Path
from uuid import uuid4
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
import magic
import filetype
from api.db import get_conn, now_iso, _lock
from api.worker import run_pipeline_async
from api.main import limiter

router = APIRouter(prefix="/api", tags=["upload"])

UPLOADS_DIR = Path(__file__).parent.parent.parent / "uploads"
SUPPORTED = {".pdf", ".docx", ".html", ".htm", ".txt", ".md"}
SUPPORTED_MIME = {
    ".pdf": ["application/pdf"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".html": ["text/html"],
    ".htm": ["text/html"],
    ".txt": ["text/plain"],
    ".md": ["text/markdown", "text/plain"],
}

# 50 MB upload limit
_MAX_BYTES = 50 * 1024 * 1024
# Maximum file size to check in memory for MIME validation (10 MB)
_MAX_MIME_CHECK = 10 * 1024 * 1024


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...)
):
    """
    Upload a CTI report file for processing.
    
    Rate limited to 10 uploads per minute per IP address.
    """
    # Check file extension
    suffix = Path(file.filename or "file").suffix.lower()
    if suffix not in SUPPORTED:
        raise HTTPException(
            400, 
            f"Unsupported format '{suffix}'. Accepted: {', '.join(SUPPORTED)}"
        )

    # Check file size BEFORE reading content
    # For File objects, we need to read the content to get the size
    # But we can check Content-Length header first if available
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BYTES:
        raise HTTPException(
            413, 
            f"File too large. Maximum allowed size is {_MAX_BYTES // (1024*1024)} MB."
        )

    # Read first chunk to validate MIME type
    first_chunk = await file.read(1024 * 1024)  # Read 1MB for MIME check
    
    # Validate MIME type using python-magic
    try:
        mime_type = magic.from_buffer(first_chunk, mime=True)
        allowed_mimes = SUPPORTED_MIME.get(suffix, [])
        if allowed_mimes and mime_type not in allowed_mimes:
            raise HTTPException(
                400,
                f"MIME type '{mime_type}' does not match expected type for '{suffix}'. "
                f"Expected: {', '.join(allowed_mimes)}"
            )
    except Exception as e:
        # Fallback to filetype library
        try:
            kind = filetype.guess(first_chunk)
            if kind is None:
                raise HTTPException(
                    400,
                    f"Could not determine file type. Please ensure the file is valid."
                )
            if suffix == ".pdf" and kind.mime != "application/pdf":
                raise HTTPException(
                    400,
                    f"File appears to be '{kind.mime}' but extension is '.pdf'"
                )
        except Exception:
            raise HTTPException(
                400,
                f"File type validation failed: {str(e)}"
            )

    # Check total size after reading first chunk
    if len(first_chunk) > _MAX_BYTES:
        raise HTTPException(
            413,
            f"File too large. Maximum allowed size is {_MAX_BYTES // (1024*1024)} MB."
        )

    job_id = str(uuid4())
    dest = UPLOADS_DIR / f"{job_id}{suffix}"
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Stream remaining content to disk
    written = len(first_chunk)
    try:
        with dest.open("wb") as f:
            f.write(first_chunk)
            while chunk := await file.read(1024 * 64):  # 64 KB chunks
                written += len(chunk)
                if written > _MAX_BYTES:
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        413,
                        f"File too large. Maximum allowed size is {_MAX_BYTES // (1024*1024)} MB."
                    )
                f.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise  # re-raise 413 as-is
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(
            500,
            "File upload failed — disk write error"
        ) from exc

    # Verify file was written correctly
    if not dest.exists() or dest.stat().st_size == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, "File upload failed — empty file")

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
