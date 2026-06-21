"""Detection-coverage API (ADR-0006).

Coverage is computed live from the job's accepted technique entities joined
against the detection-rule store — so it always reflects current review
decisions and the current rule corpora, with no per-job staleness.
"""
from fastapi import APIRouter, HTTPException

from api.db import get_conn
from pipeline.detection.coverage import compute_for_job, rules_for_job
from pipeline.detection.store import corpus_counts, rules_for_technique

router = APIRouter(prefix="/api", tags=["coverage"])


@router.get("/jobs/{job_id}/coverage")
def get_coverage(job_id: str):
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return compute_for_job(conn, job_id)


@router.get("/jobs/{job_id}/coverage/rules")
def get_coverage_report_rules(job_id: str):
    """All canonical Sigma rules linkable to this report, grouped by technique.

    Backs the Review "Detections" tab. Declared before the `{technique_id}` route
    so the literal `/rules` path wins. Metadata only — no rule bodies.
    """
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return rules_for_job(conn, job_id)


@router.get("/jobs/{job_id}/coverage/{technique_id}/rules")
def get_coverage_rules(job_id: str, technique_id: str):
    """License-aware drill-down: which rules cover this technique. No raw bodies."""
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return {"technique_id": technique_id.upper(), "rules": rules_for_technique(conn, technique_id)}


@router.get("/detection-corpora")
def get_detection_corpora():
    with get_conn() as conn:
        return {"corpora": corpus_counts(conn)}
