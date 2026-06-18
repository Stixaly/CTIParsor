from pathlib import Path
from uuid import uuid4

import filetype
import magic
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from api.db import _lock, get_conn, now_iso
from api.main import limiter
from api.worker import run_pipeline_async

# Explicit annotation needed: this module is part of an import cycle
# (api.main -> api.routes.upload -> api.main, for the `limiter` import),
# so mypy can't always infer `router`'s type from the call expression alone —
# it then reports "Cannot determine type of 'router'" at the `include_router`
# call site in api/main.py.
router: APIRouter = APIRouter(prefix="/api", tags=["upload"])

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

# Allowed TLP / PAP marking levels (object_marking_refs applied to every
# object in the generated STIX bundle — see stage4_stix_mapping.py)
_MARKING_LEVELS = {"RED", "AMBER", "GREEN", "WHITE"}


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    tlp_level: str | None = Form(None),
    pap_level: str | None = Form(None),
):
    """
    Upload a CTI report file for processing.

    Rate limited to 10 uploads per minute per IP address.

    tlp_level / pap_level — optional TLP/PAP markings ("RED"|"AMBER"|"GREEN"|"WHITE")
    applied to every object in the generated STIX bundle.
    """
    if tlp_level is not None:
        tlp_level = tlp_level.strip().upper() or None
        if tlp_level and tlp_level not in _MARKING_LEVELS:
            raise HTTPException(400, f"Invalid tlp_level. Valid: {', '.join(sorted(_MARKING_LEVELS))}")
    if pap_level is not None:
        pap_level = pap_level.strip().upper() or None
        if pap_level and pap_level not in _MARKING_LEVELS:
            raise HTTPException(400, f"Invalid pap_level. Valid: {', '.join(sorted(_MARKING_LEVELS))}")
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

    # Validate MIME type using python-magic with filetype as fallback.
    # HTTPException is re-raised immediately so validation rejections always
    # surface correctly.  Only actual library errors fall through to the fallback.
    try:
        mime_type = magic.from_buffer(first_chunk, mime=True)
        allowed_mimes = SUPPORTED_MIME.get(suffix, [])
        if allowed_mimes and mime_type not in allowed_mimes:
            raise HTTPException(
                415,
                f"MIME type '{mime_type}' does not match expected type for '{suffix}'. "
                f"Expected: {', '.join(allowed_mimes)}"
            )
    except HTTPException:
        raise  # validation rejection — propagate as-is
    except Exception:
        # python-magic unavailable or raised an internal error — fall back to filetype.
        kind = filetype.guess(first_chunk)
        if kind is None:
            raise HTTPException(400, "Could not determine file type. Please ensure the file is valid.")
        allowed_mimes = SUPPORTED_MIME.get(suffix, [])
        if allowed_mimes and kind.mime not in allowed_mimes:
            raise HTTPException(
                415,
                f"File content appears to be '{kind.mime}' but extension is '{suffix}'. "
                f"Expected: {', '.join(allowed_mimes)}"
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
                "INSERT INTO jobs (id, original_filename, status, tlp_level, pap_level, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (job_id, file.filename, "uploaded", tlp_level, pap_level, ts, ts),
            )
            conn.commit()

    run_pipeline_async(job_id, str(dest), file.filename or "unknown")

    return {"job_id": job_id, "filename": file.filename, "status": "processing"}
