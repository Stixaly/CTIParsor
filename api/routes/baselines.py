"""
The STIX bundle an analyst already holds (ADR-0090): what the server accepts
and what it makes of a bundle before a job is created.  The bundle itself
travels with the ingestion routes (api/routes/upload.py, api/routes/ingest.py).
"""
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from api.baseline_store import scrubbed
from api.main import limiter
from api.routes._common import (
    BASELINE_REFUSED,
    check_baseline_bytes,
    enrichment_enabled,
    intake_slot,
    read_baseline_file,
    require_enrichment,
)
from pipeline import baseline_stix
from pipeline.baseline_stix import MAX_BASELINE_BYTES, MAX_BASELINE_OBJECTS, BaselineError, Intake

# Explicit annotation: same import cycle as api/routes/upload.py (`limiter`).
router: APIRouter = APIRouter(prefix="/api/baselines", tags=["baselines"])



@router.get("/status")
def baselines_status():
    """Whether this server enriches a bundle (`STIX_ENRICHMENT_ENABLED`) and the limits it applies."""
    return {"enabled": enrichment_enabled(), "max_bytes": MAX_BASELINE_BYTES, "max_objects": MAX_BASELINE_OBJECTS}


@router.post("/inspect", response_model=Intake, responses=BASELINE_REFUSED)
@limiter.limit("10/minute")
def inspect_baseline(
    request: Request,
    file: UploadFile = File(...),
    report_id: str | None = Form(None),
):
    """
    What a job would make of this bundle: its counts by type, the objects left
    out and why, the reports it holds, the TLP and PAP it carries.

    With several reports and no `report_id`, `needs_report_choice` is true and
    `reports` lists them.  Nothing is stored and nothing is logged; the JSON
    schemas are not run (the job runs them), so an object only they refuse is
    still counted here.
    """
    require_enrichment()
    raw = read_baseline_file(file.file)
    check_baseline_bytes(raw)
    try:
        with intake_slot():
            _, intake, _ = baseline_stix.intake(
                raw, report_id=(report_id or "").strip() or None, preview=True, validate=False)
    except BaselineError as exc:
        raise HTTPException(400, str(exc)) from exc
    return scrubbed(intake)
