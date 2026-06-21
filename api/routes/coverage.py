"""Detection-coverage API (ADR-0006).

Coverage is computed live from the job's accepted technique entities joined
against the detection-rule store — so it always reflects current review
decisions and the current rule corpora, with no per-job staleness.
"""
import io
import json
import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from api.db import get_conn
from pipeline.detection.coverage import compute_for_job, rule_bodies_for_job, rules_for_job
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


def _safe_slug(text: str, fallback: str) -> str:
    """Filesystem-safe slug for a rule filename inside the export ZIP."""
    slug = re.sub(r"[^\w\-]+", "_", (text or "").strip()).strip("_")[:80]
    return slug or fallback


@router.get("/jobs/{job_id}/detections/export")
def export_detections(job_id: str):
    """Download every detected Sigma rule for this report as a ZIP.

    "Detected" = the canonical rules linkable to the report's accepted ATT&CK
    techniques (same set as the Review "Detections" tab). One `.yml` per rule
    plus a MANIFEST.json and README carrying each rule's license and source, so
    provenance/license travels with the export (ADR-0006)."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        rules = rule_bodies_for_job(conn, job_id)

    if not rules:
        raise HTTPException(404, "No detection rules match this report's techniques")

    report_stem = _safe_slug(Path(row["original_filename"]).stem, "report")

    manifest: list[dict] = []
    used_names: set[str] = set()
    licenses: dict[str, set[str]] = {}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in rules:
            base = _safe_slug(r["title"] or r["native_key"] or r["id"], "rule")
            fname = f"{r['corpus']}__{base}.yml"
            n = 2
            while fname in used_names:
                fname = f"{r['corpus']}__{base}_{n}.yml"
                n += 1
            used_names.add(fname)

            zf.writestr(f"rules/{fname}", r["raw"] or "")
            manifest.append({
                "file": f"rules/{fname}",
                "id": r["id"],
                "corpus": r["corpus"],
                "title": r["title"],
                "license": r["license"],
                "source_ref": r["source_ref"],
                "techniques": r["techniques"],
            })
            licenses.setdefault(r["license"] or "unknown", set()).add(r["corpus"])

        zf.writestr("MANIFEST.json", json.dumps({
            "job_id": job_id,
            "report": row["original_filename"],
            "rule_count": len(manifest),
            "rules": manifest,
        }, indent=2))

        license_lines = "\n".join(
            f"  - {lic}: {', '.join(sorted(corpora))}"
            for lic, corpora in sorted(licenses.items())
        )
        zf.writestr("README.txt", (
            "Sigma detection rules for this CTI report\n"
            "=========================================\n\n"
            f"Report : {row['original_filename']}\n"
            f"Rules  : {len(manifest)} canonical rule(s)\n\n"
            "These are the public detection rules whose ATT&CK techniques match\n"
            "the techniques extracted from this report. This reflects detection\n"
            "READINESS — that a rule exists — not that any rule was validated\n"
            "against live telemetry.\n\n"
            "Each rule retains its original license. Respect each license before\n"
            "redistributing. See MANIFEST.json for per-rule license and source.\n\n"
            "Licenses present:\n"
            f"{license_lines}\n"
        ))

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{report_stem}_sigma_rules.zip"'
        },
    )


@router.get("/detection-corpora")
def get_detection_corpora():
    with get_conn() as conn:
        return {"corpora": corpus_counts(conn)}
