from pathlib import Path
from uuid import uuid4

import filetype
import magic
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from api.body_limit import ENVELOPE_BYTES
from api.main import limiter
from api.paths import uploads_dir
from api.routes._common import (
    BASELINE_REFUSED,
    baseline_markings,
    check_baseline_request,
    enrichment_enabled,
    part_has_content,
    read_baseline,
    read_baseline_file,
    start_job,
)
from pipeline.baseline_stix import MAX_BASELINE_BYTES
from pipeline.stage4_stix_mapping import normalise_tlp

# Explicit annotation needed: this module is part of an import cycle
# (api.main -> api.routes.upload -> api.main, for the `limiter` import),
# so mypy can't always infer `router`'s type from the call expression alone —
# it then reports "Cannot determine type of 'router'" at the `include_router`
# call site in api/main.py.
router: APIRouter = APIRouter(prefix="/api", tags=["upload"])

SUPPORTED = {".pdf", ".docx", ".html", ".htm", ".txt", ".md"}
SUPPORTED_MIME = {
    ".pdf": ["application/pdf"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".html": ["text/html"],
    ".htm": ["text/html"],
    ".txt": ["text/plain"],
    ".md": ["text/markdown", "text/plain"],
}

# 50 MB: a report's own limit, checked as it is copied to uploads/
_MAX_BYTES = 50 * 1024 * 1024
# Maximum file size to check in memory for MIME validation (10 MB)
_MAX_MIME_CHECK = 10 * 1024 * 1024

# PAP marking levels (object_marking_refs applied to every object in the
# generated STIX bundle — see stage4_stix_mapping.py).  TLP levels come from
# the same module, which also owns their spelling (ADR-0073).
_PAP_LEVELS = {"RED", "AMBER", "GREEN", "WHITE"}


def body_budget() -> int:
    """The most a POST /api/upload body may weigh (api/body_limit.py): the report,
    the baseline while the enrichment mode is on, and the form around them."""
    return _MAX_BYTES + (MAX_BASELINE_BYTES if enrichment_enabled() else 0) + ENVELOPE_BYTES


def clean_tlp(value: str | None) -> str | None:
    """A job's TLP as stored: canonical (`TLP:amber+strict` -> `AMBER+STRICT`,
    `white` -> `CLEAR`), None when blank, 400 when unknown — never silently
    another level."""
    if value is None or not value.strip():
        return None
    try:
        return normalise_tlp(value)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid tlp_level: {exc}") from exc


def clean_pap(value: str | None) -> str | None:
    """A job's PAP as stored: upper-cased, None when blank, 400 when unknown."""
    if value is None or not value.strip():
        return None
    v = value.strip().upper()
    if v not in _PAP_LEVELS:
        raise HTTPException(400, f"Invalid pap_level. Valid: {', '.join(sorted(_PAP_LEVELS))}")
    return v


@router.post("/upload", responses=BASELINE_REFUSED)
@limiter.limit("10/minute")
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    tlp_level: str | None = Form(None),
    pap_level: str | None = Form(None),
    baseline_stix: UploadFile | None = File(None),
    baseline_report_id: str | None = Form(None),
):
    """
    Upload a CTI report file for processing.

    Rate limited to 10 uploads per minute per IP address.

    tlp_level — optional TLP marking (CLEAR | GREEN | AMBER | AMBER+STRICT | RED,
    a `TLP:` prefix and WHITE accepted); pap_level — optional PAP marking
    (RED | AMBER | GREEN | WHITE).  Applied to every object in the generated
    STIX bundle; without a TLP the report gets the STIX_TLP default.

    baseline_stix — optional STIX 2.1 bundle the analyst already holds, to
    enrich instead of starting from scratch (ADR-0090; 400 when
    STIX_ENRICHMENT_ENABLED=false); baseline_report_id — which of its Reports to
    enrich, required when it holds several.  The job's TLP and PAP may not be
    lower than the bundle's.

    Declared as a plain `def`, not `async def`: the body does blocking disk I/O
    (`dest.open("wb")`, `f.write`) and a synchronous SQLite insert (`start_job`).
    FastAPI runs a sync path operation in a worker thread automatically, so
    those calls never block the event loop the way they would inside an
    `async def` that never awaits them.
    """
    tlp_level = clean_tlp(tlp_level)
    pap_level = clean_pap(pap_level)
    # Refused before a byte of either file is read: the mode is off, or a
    # baseline_report_id comes without a baseline (an empty part is none).
    check_baseline_request(baseline_stix is not None and part_has_content(baseline_stix.file), baseline_report_id)
    # Check file extension
    suffix = Path(file.filename or "file").suffix.lower()
    if suffix not in SUPPORTED:
        raise HTTPException(
            400,
            f"Unsupported format '{suffix}'. Accepted: {', '.join(SUPPORTED)}"
        )

    # The request as a whole was held to `body_budget()` while it arrived
    # (api/body_limit.py): FastAPI has the form, both files spooled, before this
    # runs.  What is left to check is the report's own limit, as it is copied below.

    # Read first chunk to validate MIME type.  `file.file` is the underlying
    # SpooledTemporaryFile — read synchronously since this route now runs in
    # FastAPI's threadpool rather than on the event loop.
    first_chunk = file.file.read(1024 * 1024)  # Read 1MB for MIME check

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
        if suffix in {".txt", ".md"}:
            try:
                first_chunk.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HTTPException(400, "Text file is not valid UTF-8.") from exc
        else:
            # The rejections below are filetype's verdict, not python-magic's
            # failure: `from None` keeps that failure out of their traceback.
            kind = filetype.guess(first_chunk)
            if kind is None:
                raise HTTPException(400, "Could not determine file type. Please ensure the file is valid.") from None
            allowed_mimes = SUPPORTED_MIME.get(suffix, [])
            if allowed_mimes and kind.mime not in allowed_mimes:
                raise HTTPException(
                    415,
                    f"File content appears to be '{kind.mime}' but extension is '{suffix}'. "
                    f"Expected: {', '.join(allowed_mimes)}"
                ) from None

    # Check total size after reading first chunk
    if len(first_chunk) > _MAX_BYTES:
        raise HTTPException(
            413,
            f"File too large. Maximum allowed size is {_MAX_BYTES // (1024*1024)} MB."
        )

    job_id = str(uuid4())
    uploads = uploads_dir()
    dest = uploads / f"{job_id}{suffix}"
    uploads.mkdir(parents=True, exist_ok=True)

    # Stream remaining content to disk
    written = len(first_chunk)
    try:
        with dest.open("wb") as f:
            f.write(first_chunk)
            while chunk := file.file.read(1024 * 64):  # 64 KB chunks
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

    # The baseline is read last, once the cheap checks on the report have passed
    # and it is on disk; whatever stops the request before the job is handed to
    # `start_job` (a refused baseline, a marking that cannot be resolved, a bug)
    # takes the report file with it.
    handed_over = False
    try:
        baseline = read_baseline(
            read_baseline_file(baseline_stix.file) if baseline_stix is not None else None, baseline_report_id)
        tlp_level, pap_level = baseline_markings(baseline, tlp_level, pap_level)
        handed_over = True
    finally:
        if not handed_over:
            dest.unlink(missing_ok=True)

    return start_job(job_id, dest, file.filename or "unknown", tlp_level, pap_level, baseline=baseline)
