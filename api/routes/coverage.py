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

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from api.db import get_conn
from pipeline.detection.coverage import (
    compute_for_job,
    rule_bodies_for_job,
    rule_facets_for_job,
    rules_for_job,
)
from pipeline.detection.relevance import propose_for_job
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


@router.get("/jobs/{job_id}/detections/proposals")
def get_detection_proposals(job_id: str, limit: int = 200):
    """Rules ranked by what the report actually contains (ADR-0014).

    Unlike `/coverage/rules` — which returns every rule sharing an ATT&CK tag —
    this scores each candidate on its overlap with the report's observables
    (hashes, domains, binaries, paths, registry keys, CVEs) and on platform
    compatibility, and returns the evidence behind each rank. Metadata only, no
    rule bodies.
    """
    limit = max(1, min(limit, 1000))
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return propose_for_job(conn, job_id, limit=limit)


@router.get("/jobs/{job_id}/coverage/{technique_id}/rules")
def get_coverage_rules(job_id: str, technique_id: str):
    """License-aware drill-down: which rules cover this technique. No raw bodies."""
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return {"technique_id": technique_id.upper(), "rules": rules_for_technique(conn, technique_id)}


#: File extension per format. A Suricata rule written as `.yml` loads in no tool;
#: measured, 8,380 of 10,372 rules in a real export are Suricata (ADR-0020).
_EXPORT_EXTENSIONS = {
    "sigma": "yml",
    "suricata": "rules",
    "yara": "yar",
}
_DEFAULT_EXTENSION = "txt"

_FILTER_DEFAULTS = {"format": "sigma", "corpus": "unknown",
                    "license": "unknown", "severity": "unknown"}


def _safe_slug(text: str, fallback: str) -> str:
    """Filesystem-safe slug for a rule filename inside the export ZIP."""
    slug = re.sub(r"[^\w\-]+", "_", (text or "").strip()).strip("_")[:80]
    return slug or fallback


def _load_rules(conn, job_id: str) -> list[dict]:
    """Technique-selected rules for a job, enriched with `format` and `severity`.

    `rule_bodies_for_job` predates the multi-format store and returns neither, so
    they are joined on here — in one query for the whole store rather than one per
    rule, which at ~18k selected rules is the difference between a scan and a
    round-trip storm.
    """
    rules = rule_bodies_for_job(conn, job_id)
    if not rules:
        return []
    meta = {
        r[0]: (r[1] or "sigma", r[2] or "unknown")
        for r in conn.execute("SELECT id, format, severity FROM detection_rules")
    }
    for r in rules:
        fmt, sev = meta.get(r["id"], ("sigma", "unknown"))
        r["format"] = fmt
        r["severity"] = sev
    return rules


def _apply_filters(
    rules: list[dict],
    formats: list[str] | None,
    corpora: list[str] | None,
    licenses: list[str] | None,
    severities: list[str] | None,
) -> list[dict]:
    """Keep rules matching every non-empty axis (axes combine with AND).

    An empty or absent axis means "no constraint", so an unfiltered request keeps
    the pre-ADR-0020 behaviour. Comparison is case-folded on both sides.
    """
    # Normalise once, not per rule: at 18k rules x 4 axes the inline form rebuilt
    # 72k sets for nothing.
    wanted = {
        "format": {v.strip().lower() for v in (formats or [])},
        "corpus": {v.strip().lower() for v in (corpora or [])},
        "license": {v.strip().lower() for v in (licenses or [])},
        "severity": {v.strip().lower() for v in (severities or [])},
    }
    active = {k: v for k, v in wanted.items() if v}
    if not active:
        return list(rules)
    out = []
    for r in rules:
        if all(
            (r.get(axis) or _FILTER_DEFAULTS[axis]).strip().lower() in allowed
            for axis, allowed in active.items()
        ):
            out.append(r)
    return out


def _facet(rules: list[dict], key: str) -> list[dict]:
    """Aggregate rules by one axis: value -> rule count and raw byte size."""
    counts: dict[str, dict] = {}
    for r in rules:
        val = (r.get(key) or _FILTER_DEFAULTS.get(key, "unknown")).strip().lower()
        entry = counts.setdefault(val, {"value": val, "rules": 0, "bytes": 0})
        entry["rules"] += 1
        entry["bytes"] += len(r.get("raw") or "")
    return sorted(counts.values(), key=lambda x: (-x["rules"], x["value"]))


@router.get("/jobs/{job_id}/detections/export/facets")
def export_facets(job_id: str):
    """Per-axis rule counts and byte sizes for the export filter UI (ADR-0020).

    Exists so the operator sees the volume and the licence split *before*
    downloading: a real report yields 18,196 rules / 268 MB, of which 1,642 are
    all-rights-reserved. Disclosing the size is why no silent cap is needed.

    A job with no matching rules returns `total: 0`, not 404 — the UI must be able
    to render "nothing to export".
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        return rule_facets_for_job(conn, job_id)


@router.get("/jobs/{job_id}/detections/export")
def export_detections(
    job_id: str,
    format: list[str] | None = Query(None),
    corpus: list[str] | None = Query(None),
    license: list[str] | None = Query(None),
    severity: list[str] | None = Query(None),
):
    """Download the report's detection rules as a ZIP, optionally filtered (ADR-0020).

    "Detected" = the canonical rules linkable to the report's accepted ATT&CK
    techniques (same set as the Review "Detections" tab). One file per rule, named
    with the extension its format requires, plus MANIFEST.json and README carrying
    each rule's licence and source so provenance travels with the export (ADR-0006).
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        all_rules = _load_rules(conn, job_id)

    if not all_rules:
        raise HTTPException(404, "No detection rules match this report's techniques")

    rules = _apply_filters(all_rules, format, corpus, license, severity)
    if not rules:
        raise HTTPException(404, "No rules match the selected filters")

    report_name = row["original_filename"]
    report_stem = _safe_slug(Path(report_name).stem, "report")

    manifest: list[dict] = []
    used_paths: set[str] = set()
    licenses: dict[str, set[str]] = {}
    fmt_counts: dict[str, int] = {}

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in rules:
            fmt = r.get("format") or "sigma"
            ext = _EXPORT_EXTENSIONS.get(fmt, _DEFAULT_EXTENSION)
            base = _safe_slug(r["title"] or r["native_key"] or r["id"], "rule")
            corpus_val = r.get("corpus") or "unknown"

            path_base = f"rules/{fmt}/{corpus_val}__{base}"
            path = f"{path_base}.{ext}"
            n = 2
            while path in used_paths:
                path = f"{path_base}_{n}.{ext}"
                n += 1
            used_paths.add(path)

            zf.writestr(path, r["raw"] or "")
            manifest.append({
                "file": path,
                "id": r["id"],
                "corpus": r["corpus"],
                "format": fmt,
                "severity": r.get("severity") or "unknown",
                "title": r.get("title"),
                "license": r.get("license") or "unknown",
                "source_ref": r.get("source_ref"),
                "techniques": r.get("techniques", []),
            })
            licenses.setdefault(r.get("license") or "unknown", set()).add(r["corpus"])
            fmt_counts[fmt] = fmt_counts.get(fmt, 0) + 1

        # Excluded counts by id, NOT by `r not in rules`: that is a linear scan
        # comparing dicts by value — including multi-kilobyte `raw` — which at
        # 18k x 2.5k rules is ~45M deep comparisons and hangs the request.
        kept_ids = {r["id"] for r in rules}
        excluded = [r for r in all_rules if r["id"] not in kept_ids]

        def _count_excluded(key: str) -> dict[str, int]:
            counts: dict[str, int] = {}
            for r in excluded:
                val = (r.get(key) or _FILTER_DEFAULTS.get(key, "unknown")).strip().lower()
                counts[val] = counts.get(val, 0) + 1
            return counts

        zf.writestr("MANIFEST.json", json.dumps({
            "job_id": job_id,
            "report": report_name,
            "rule_count": len(manifest),
            "filters": {
                "format": format or [], "corpus": corpus or [],
                "license": license or [], "severity": severity or [],
            },
            # Without this, an export that silently omitted 1,642 rules would be
            # indistinguishable from one where they never matched.
            "excluded": {
                "total": len(all_rules) - len(rules),
                "format": _count_excluded("format"),
                "corpus": _count_excluded("corpus"),
                "license": _count_excluded("license"),
                "severity": _count_excluded("severity"),
            },
            "rules": manifest,
        }, indent=2))

        format_lines = "\n".join(
            f"  - {f}: {n}" for f, n in sorted(fmt_counts.items(), key=lambda kv: -kv[1])
        )
        license_lines = "\n".join(
            f"  - {lic}: {', '.join(sorted(corpora_set))}"
            for lic, corpora_set in sorted(licenses.items())
        )
        zf.writestr("README.txt", (
            "Detection rules for this CTI report\n"
            "===================================\n\n"
            f"Report : {report_name}\n"
            f"Rules  : {len(manifest)} canonical rule(s)\n\n"
            "Formats present:\n"
            f"{format_lines}\n\n"
            "These are the public detection rules whose ATT&CK techniques match\n"
            "the techniques extracted from this report. This reflects detection\n"
            "READINESS — that a rule exists — not that any rule was validated\n"
            "against live telemetry.\n\n"
            "Each rule retains its original license. Respect each license before\n"
            "redistributing. A license of 'none' means ALL RIGHTS RESERVED: the\n"
            "upstream repository ships no license file, so those rules may be used\n"
            "for local coverage but NOT redistributed. See MANIFEST.json for\n"
            "per-rule license and source.\n\n"
            "Licenses present:\n"
            f"{license_lines}\n"
        ))

    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{report_stem}_detection_rules.zip"'
        },
    )


@router.get("/detection-corpora")
def get_detection_corpora():
    with get_conn() as conn:
        return {"corpora": corpus_counts(conn)}
