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
from pydantic import BaseModel, Field

from api.db import get_conn
from pipeline.detection.artifacts import coverage_with_phases
from pipeline.detection.coverage import (
    compute_for_job,
    rule_bodies_for_job,
    rule_facets_for_job,
    rules_for_job,
)
from pipeline.detection.relevance import propose_for_job
from pipeline.detection.store import corpus_counts, lookup_rules, rules_for_technique

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


@router.get("/jobs/{job_id}/coverage/artifacts")
def get_artifact_coverage(job_id: str):
    """Evidence-keyed coverage: artifacts score, ATT&CK locates (ADR-0025).

    The unit is the report's own technical content — hashes, addresses, paths,
    tool and malware identities — scored on whether a rule actually holds that
    value, and tiered by Pyramid of Pain. The ATT&CK band rides along unscored,
    to say where in the kill chain the intrusion sits.

    Unlike `/coverage/rules`, this needs no ordering against the
    `{technique_id}` route below: that template carries a trailing `/rules`
    segment, so `/coverage/artifacts` cannot match it either way. Verified by
    moving this route below it — every test still passed.
    """
    with get_conn() as conn:
        if not conn.execute("SELECT id FROM jobs WHERE id=?", (job_id,)).fetchone():
            raise HTTPException(404, "Job not found")
        return coverage_with_phases(conn, job_id)


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


def _load_rules(conn, job_id: str, body_ids: set[str] | None = None) -> list[dict]:
    """Technique-selected rules for a job, enriched with `format` and `severity`.

    `rule_bodies_for_job` predates the multi-format store and returns neither, so
    they are joined on here — in one query for the whole store rather than one per
    rule, which at ~18k selected rules is the difference between a scan and a
    round-trip storm.

    `body_ids` is passed straight through: the rule-id export only needs the
    bodies it actually packages (ADR-0022).
    """
    rules = rule_bodies_for_job(conn, job_id, body_ids=body_ids)
    if not rules:
        return []
    # Batched by the ids we already hold, not a scan of the whole store: the
    # store is 86,180 rows against a report's ~10k, and the full scan measured
    # 4.8s of the export's runtime for rows it then discarded (ADR-0022).
    meta: dict[str, tuple[str, str]] = {}
    ids = sorted(r["id"] for r in rules)
    for i in range(0, len(ids), 400):
        batch = ids[i:i + 400]
        placeholders = ",".join("?" * len(batch))
        for rid, fmt, sev in conn.execute(
            f"SELECT id, format, severity FROM detection_rules "
            f"WHERE id IN ({placeholders})",
            batch,
        ):
            meta[rid] = (fmt or "sigma", sev or "unknown")
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


class ExportSelection(BaseModel):
    """Body of the rule-id export: the exact rules to package (ADR-0022)."""
    rule_ids: list[str] = Field(default_factory=list)


def _zip_export(
    job_id: str,
    report_name: str,
    all_rules: list[dict],
    rules: list[dict],
    filters_meta: dict,
) -> Response:
    """Shared ZIP builder for the axis-filtered GET and the rule-id POST.

    One builder so the two exports can never drift in layout, manifest or
    README.
    """
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
            "filters": filters_meta,
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

    return _zip_export(
        job_id,
        row["original_filename"],
        all_rules,
        rules,
        {
            "format": format or [],
            "corpus": corpus or [],
            "license": license or [],
            "severity": severity or [],
        },
    )


@router.post("/jobs/{job_id}/detections/export")
def export_detections_selection(job_id: str, selection: ExportSelection):
    """Download exactly the requested rules as a ZIP (ADR-0022).

    The axis-filtered GET cannot express an arbitrary rule set; the granular
    coverage UI selects per rule, so it POSTs the ids. Ids are intersected with
    the rules linkable to this report — the export can never reach rules outside
    the report's technique set. Same archive layout, manifest and README as the
    GET.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT original_filename FROM jobs WHERE id=?", (job_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Job not found")
        # Validate before loading: an empty selection must not pay for a scan.
        wanted = {i.strip() for i in selection.rule_ids if i and i.strip()}
        if not wanted:
            raise HTTPException(400, "rule_ids must be a non-empty list")
        all_rules = _load_rules(conn, job_id, body_ids=wanted)

    if not all_rules:
        raise HTTPException(404, "No detection rules match this report's techniques")

    rules = [r for r in all_rules if r["id"] in wanted]
    if not rules:
        raise HTTPException(404, "No requested rule matches this report")

    # The manifest records the COUNT of requested ids, not the list: 10,000 ids
    # copied into the manifest would double its size without audit value.
    filters_meta = {
        "format": [],
        "corpus": [],
        "license": [],
        "severity": [],
        "rule_ids": len(wanted),
    }

    return _zip_export(job_id, row["original_filename"], all_rules, rules, filters_meta)


#: Cap on one lookup. The proposals panel promotes a handful at a time and the
#: coverage page hydrates its promoted set; neither needs more, and an unbounded
#: list would let one request pull every body in the store.
RULE_LOOKUP_MAX = 500


class RuleLookup(BaseModel):
    """Body of the rule lookup: which rules, and whether to include their text."""
    rule_ids: list[str] = Field(default_factory=list)
    include_body: bool = False


@router.post("/rules/lookup")
def post_rule_lookup(lookup: RuleLookup):
    """Metadata for arbitrary canonical rule ids — and their bodies on demand.

    Deliberately NOT scoped to a job. It serves the Proposed-detections panel,
    which shows rules outside the report's ATT&CK tag join by construction —
    measured, 199 of 200 proposals on one real report. The store holds only
    public corpora already cloned locally, so scoping would protect nothing that
    the export does not already hand over.

    `include_body` is opt-in because bodies are large: 219 MB for one real
    report (ADR-0022), against metadata that costs a single indexed read.

    Each rule carries its licence. A licence of `none` means ALL RIGHTS
    RESERVED — usable for local coverage, never redistributable (ADR-0006).
    """
    seen: set[str] = set()
    wanted: list[str] = []
    for raw_id in lookup.rule_ids:
        if not isinstance(raw_id, str):
            continue
        rid = raw_id.strip()
        if rid and rid not in seen:
            seen.add(rid)
            wanted.append(rid)

    if not wanted:
        raise HTTPException(400, "rule_ids must be a non-empty list")
    if len(wanted) > RULE_LOOKUP_MAX:
        raise HTTPException(413, f"at most {RULE_LOOKUP_MAX} rule ids per lookup")

    with get_conn() as conn:
        return {
            "rules": lookup_rules(conn, wanted, include_body=lookup.include_body),
            "requested": len(wanted),
        }


@router.get("/detection-corpora")
def get_detection_corpora():
    with get_conn() as conn:
        return {"corpora": corpus_counts(conn)}
