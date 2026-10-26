"""
The round trip on the real reports, end to end and offline (ADR-0090, lot 7: A2).

    python scripts/baseline_round_trip.py [--db DSN] [--out output/baseline_round_trip.json] [--jobs ID ...]

For each job of the measurement database, the ENRICHED bundle a round trip gives:
the job's stored bundle is the baseline (intake with the JSON schemas, as
`validate_in_worker` runs it), the job's rows are read the way `re_run_final_stages`
reads them, and Stage 4 builds the bundle over that baseline with the pure pieces
the worker calls (`build_bundle`, `BaselineBuild`, `serialize_bundle`,
`validation_json`).  Then Stage 5 gives its verdict, the audit's invariant checks
run on the bundle in memory, and the bundle is compared with the baseline: objects
lost, objects altered, CTIParsor objects added, and the added ones that duplicate a
baseline object by (type, name or value).

Nothing is written: the connections are read-only, `re_run_final_stages` is not
called (it writes the job row, the bundle and the export file), and no LLM is
called (the long-distance inferer stays off: the policy does not enable it).

Two differences from the worker, forced by the measurement database, are reported
in the output and not hidden: its `entities` table has no `held_reason` (a row
ships when `accepted` is 1, or NULL) and no `enrichment_status` (nothing is
`baseline_stix`), and its `jobs` table has no `pipeline_mode` (the job is treated
as the enrich job it simulates).  The CVE metadata is `lookup_cves`' answer, which
is {} when a job has no CVE row; a job with one is skipped, since its metadata
lives in the job store.

Exit 0, or 2 when the data cannot be read.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# The pipeline is imported from the repo root, however the script was invoked.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from api.baseline_store import objects_by_id  # noqa: E402
from api.paths import uploads_dir  # noqa: E402
from models.schemas import EntityType, RawEntity  # noqa: E402
from pipeline import baseline_stix as bs  # noqa: E402
from pipeline.bundle_ledger import MappingLedger  # noqa: E402
from pipeline.named_entities import stored_row_source, with_named_entities  # noqa: E402
from pipeline.orchestrator import build_bundle, load_file_bytes  # noqa: E402
from pipeline.stage1_ingestion import extract_anchor  # noqa: E402
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted  # noqa: E402
from pipeline.stage5_validation import validate_bundle  # noqa: E402
from pipeline.temporal import legacy_assertions  # noqa: E402
from scripts import audit_bundle_invariants as audit  # noqa: E402

DEFAULT_DB = "postgresql://ctiparsor:ctitest@127.0.0.1:5433/ctiparsor_measure"
DEFAULT_OUT = _ROOT / "output" / "baseline_round_trip.json"
# The entity types Stage 4 takes as raw entities: a copy of the list in
# api/worker.py `re_run_final_stages` (a local of that function, not importable).
RAW_ENTITY_TYPES: frozenset[str] = frozenset({
    EntityType.IPV4.value, EntityType.IPV6.value, EntityType.DOMAIN.value,
    EntityType.URL.value, EntityType.EMAIL.value, EntityType.MD5.value,
    EntityType.SHA1.value, EntityType.SHA256.value, EntityType.MAC_ADDR.value,
    EntityType.ASN.value, EntityType.FILE.value, EntityType.REGISTRY_KEY.value,
    EntityType.MUTEX.value, EntityType.NETWORK_TRAFFIC.value,
    EntityType.USER_ACCOUNT.value,
    EntityType.CVE.value,
    EntityType.TECHNIQUE.value, EntityType.TACTIC.value,
    EntityType.PROCEDURE.value, EntityType.TTP.value,
    EntityType.INFRASTRUCTURE.value, EntityType.INTRUSION_SET.value,
    EntityType.LOCATION.value, EntityType.IDENTITY.value,
    EntityType.CAMPAIGN.value, EntityType.INCIDENT.value,
})
# Types without a name or value of their own: not compared by name (a relationship
# has none; a marking-definition is shared by id).
_NOT_NAMED = frozenset({"relationship", "marking-definition"})
_SHOWN = 10                     # examples printed per list, the JSON keeps them all


# ── Inputs: the rows of a job, as the worker reads them ───────────────────────

def ships(row: Mapping[str, Any]) -> bool:
    """`pipeline.decisions.SHIPS` on a row: accepted, or unreviewed and not held.  The
    measurement database has no `held_reason` column: an unreviewed row is not held."""
    return row.get("accepted") == 1 or (row.get("accepted") is None and row.get("held_reason") is None)


def row_times(row: Mapping[str, Any]) -> list:
    """The dates of a relationship row (the worker's `_row_times`): no `times_json`
    column in this database, so the legacy start and stop."""
    return legacy_assertions(row.get("start_time"), row.get("stop_time"))


def job_inputs(job: Mapping[str, Any], entity_rows: Sequence[Mapping[str, Any]],
               relationship_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The Stage 4 inputs of a job, as `re_run_final_stages` builds them from its rows:
    the raw entities, the named lists, the filtered TTPs, countries, sectors and
    campaign, and the relationships, and the `NamedEntities` to record on the ledger.
    Raises ValueError when the stored LLM result cannot be read (the worker goes on
    without it; here that would change the bundle)."""
    rows = [r for r in entity_rows if ships(r)]
    relationships = [r for r in relationship_rows if ships(r)]
    rejected = [r for r in entity_rows if r.get("accepted") == 0]

    raw_entities: list[RawEntity] = []
    unreadable: list[str] = []
    for row in rows:
        if row["entity_type"] in RAW_ENTITY_TYPES:
            try:
                raw_entities.append(RawEntity(value=row["value"], entity_type=EntityType(row["entity_type"]),
                                              context=row.get("context") or "", confidence=row.get("confidence"),
                                              mitre_id=row.get("mitre_id"), source=row["source"]))
            except ValueError as exc:
                unreadable.append(f"{row['entity_type']} {row['value']!r}: {str(exc).splitlines()[0]}")

    llm = LLMEnrichmentResult()
    if job["llm_result_json"]:
        llm = LLMEnrichmentResult.model_validate_json(job["llm_result_json"])

    rej_ttp_names: set[str] = set()
    rej_ttp_mitre: set[str] = set()
    rej_locations: set[str] = set()
    rej_identities: set[str] = set()
    rej_campaigns: set[str] = set()
    for r in rejected:
        et = r["entity_type"]
        val = r["value"].lower().strip()
        mid = (r["mitre_id"] or "").lower().strip()
        if et in ("technique", "tactic", "procedure", "ttp"):
            rej_ttp_names.add(val)
            if mid:
                rej_ttp_mitre.add(mid)
        elif et == "location":
            rej_locations.add(val)
        elif et == "identity":
            rej_identities.add(val)
        elif et == "campaign":
            rej_campaigns.add(val)

    ttps = [t for t in llm.ttps
            if t.technique_name.lower() not in rej_ttp_names
            and (not t.mitre_id or t.mitre_id.lower() not in rej_ttp_mitre)]
    campaign_name = llm.campaign_name
    if campaign_name and campaign_name.lower().strip() in rej_campaigns:
        campaign_name = None
    # Once the campaign is read, as the worker does (ADR-0092): a name typed several
    # ways keeps its best-ranked source's type, and an outranked campaign leaves.
    named = with_named_entities(
        LLMEnrichmentResult(campaign_name=campaign_name),
        ((r["entity_type"], r["value"], stored_row_source(r["source"], r["accepted"], r.get("decision_origin")))
         for r in rows),
    )
    raw_entities = [e for e in raw_entities if named.keeps(e)]
    campaign_name = named.llm_result.campaign_name
    countries = [c for c in llm.targeted_countries if c.lower().strip() not in rej_locations]
    sectors = [s for s in llm.targeted_sectors if s.lower().strip() not in rej_identities]

    llm_result = LLMEnrichmentResult(
        malware_families=named.llm_result.malware_families,
        threat_actors=named.llm_result.threat_actors,
        tools=named.llm_result.tools,
        ttps=ttps,
        ioc_associations=llm.ioc_associations,
        campaign_name=campaign_name,
        targeted_sectors=sectors,
        targeted_countries=countries,
        course_of_action=llm.course_of_action,
        relationships=[
            RelationshipExtracted(source_value=r["source_value"], relationship_type=r["relationship_type"],
                                  target_value=r["target_value"], confidence=r["confidence"],
                                  evidence_text=r.get("evidence_text"),
                                  evidence_label=r.get("evidence_label") or "reported", times=row_times(r))
            for r in relationships
        ],
    )
    return {"raw_entities": raw_entities, "llm_result": llm_result, "named": named, "unreadable": unreadable,
            "entity_rows": len(rows), "relationship_rows": len(relationships)}


# ── The build: the worker's pure pieces, nothing written ──────────────────────

def build_enriched(job: Mapping[str, Any], inputs: Mapping[str, Any], policy: dict | None) -> dict[str, Any]:
    """The enriched bundle of a job over its own stored bundle as the baseline, and
    Stage 5's verdict on it, as `re_run_final_stages` computes them.  Raises
    BaselineError when the stored bundle cannot be used as a baseline."""
    bundle_raw = job["bundle_json"].encode("utf-8")
    index, _intake, _parsed = bs.intake(bundle_raw, validate=True)
    if index is None:
        raise bs.BaselineError("the baseline needs a report to be chosen")
    baseline = bs.BaselineBuild(index=index, objects=objects_by_id(job["bundle_json"]), excluded=frozenset())

    original_filename = job["original_filename"]
    report_name = re.sub(r"[^\w\-]", "_", Path(original_filename).stem)
    if any(e.entity_type == EntityType.CVE for e in inputs["raw_entities"]):
        raise ValueError("a CVE row: its metadata is in the job store, not offline")
    upload_matches = list(uploads_dir().glob(f"{job['id']}.*"))
    source_hash, source_bytes = load_file_bytes(upload_matches[0] if upload_matches else None)
    try:
        source = next((p for p in upload_matches if p.suffix.lower() in (".txt", ".html", ".htm")),
                      upload_matches[0] if upload_matches else None)
        anchor = extract_anchor(str(source) if source else None, job["report_text"] or "")
    except Exception:  # noqa: BLE001 — the worker logs it and builds without an anchor: the same here
        anchor = None

    ledger = MappingLedger()
    inputs["named"].record(ledger)
    bundle = build_bundle(
        inputs["raw_entities"], inputs["llm_result"],
        report_name=report_name, report_text=job["report_text"] or "",
        original_filename=original_filename, source_hash=source_hash, source_bytes=source_bytes,
        policy=policy, tlp_level=job["tlp_level"], pap_level=job["pap_level"], cve_metadata={},
        ledger=ledger, document_anchor=anchor, baseline=baseline,
    )
    bundle_json = bs.serialize_bundle(bundle, baseline.verbatim)
    verdict = validate_bundle(bs.validation_json(bundle_json, baseline.trusted), quiet=True)
    return {"baseline": baseline, "bundle_json": bundle_json, "verdict": verdict,
            "upload_found": bool(upload_matches)}


# ── Comparison ─────────────────────────────────────────────────────────────

def canonical(obj: Mapping[str, Any]) -> str:
    """An object as JSON with sorted keys: two objects are the same when these match."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def fold(value: str) -> str:
    return " ".join(value.casefold().split())


def named_key(obj: Mapping[str, Any]) -> tuple[str, str] | None:
    """(type, name or value, folded), or None for an object with neither (or a type not compared)."""
    if obj.get("type") in _NOT_NAMED:
        return None
    text = obj.get("name") or obj.get("value")
    return (obj["type"], fold(text)) if isinstance(text, str) and text else None


def lost_ids(baseline: Mapping[str, dict], enriched: Mapping[str, dict]) -> list[str]:
    """Baseline ids the enriched bundle does not hold."""
    return sorted(set(baseline) - set(enriched))


def altered_ids(baseline: Mapping[str, dict], enriched: Mapping[str, dict]) -> list[str]:
    """Baseline ids the enriched bundle holds with a different JSON (verbatim: none, bar the Report)."""
    both = set(baseline) & set(enriched)
    return sorted(oid for oid in both if canonical(baseline[oid]) != canonical(enriched[oid]))


def added_objects(baseline: Mapping[str, dict], enriched: Mapping[str, dict]) -> dict[str, dict]:
    """The enriched objects the baseline does not hold, by id."""
    return {oid: obj for oid, obj in enriched.items() if oid not in baseline}


def duplicates_of_baseline(baseline: Mapping[str, dict], added: Mapping[str, dict]) -> list[dict[str, Any]]:
    """The added objects whose (type, name or value) is a baseline object's."""
    by_key: dict[tuple[str, str], list[str]] = {}
    for oid, obj in baseline.items():
        key = named_key(obj)
        if key is not None:
            by_key.setdefault(key, []).append(oid)
    out = []
    for oid, obj in added.items():
        key = named_key(obj)
        if key is not None and key in by_key:
            out.append({"id": oid, "type": obj["type"], "name": obj.get("name") or obj.get("value"),
                        "baseline_ids": sorted(by_key[key])})
    return out


def compare(baseline_objects: Mapping[str, dict], bundle_json: str) -> dict[str, Any]:
    """Lost, altered, added and duplicated objects of the enriched bundle against the baseline."""
    enriched = {o["id"]: o for o in json.loads(bundle_json)["objects"] if isinstance(o.get("id"), str)}
    added = added_objects(baseline_objects, enriched)
    dups = duplicates_of_baseline(baseline_objects, added)
    return {
        "baseline_objects": len(baseline_objects), "enriched_objects": len(enriched),
        "lost": lost_ids(baseline_objects, enriched), "altered": altered_ids(baseline_objects, enriched),
        "added": {"count": len(added), "by_type": dict(Counter(o["type"] for o in added.values()))},
        "added_duplicates": dups, "enriched": enriched,
    }


def audit_findings(bundles: Sequence[tuple[str, dict]]) -> list[dict[str, Any]]:
    """The audit's checks over every enriched bundle, as the audit runs them, one
    row per check; `jobs` names the jobs a check failed on."""
    findings = audit.run_all(list(bundles))
    out = []
    for f in findings:
        faulty = sorted(audit._FAULTY_JOBS.get(f.name, set()))
        out.append({"name": f.name, "severity": f.severity, "status": f.status, "count": f.count, "total": f.total,
                    "jobs": faulty, "detail": f.detail})
    return out


# ── Read the measurement database (read only) ─────────────────────────────

def load_inputs(dsn: str, only: Sequence[str]) -> tuple[list[dict[str, Any]], dict | None]:
    """Every job with its rows, and the saved policy (None when none is saved), in one
    read-only session.  The `held_reason`, `enrichment_status`, `times_json`,
    `pipeline_mode` and `decision_origin` columns are absent here: the rows are read
    as they are, so no accept counts as the analyst's type (ADR-0092)."""
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, options="-c default_transaction_read_only=on", row_factory=dict_row) as conn:
        jobs = conn.execute("SELECT id, original_filename, report_text, bundle_json, llm_result_json, tlp_level, "
                            "pap_level FROM jobs ORDER BY id").fetchall()
        entity_rows = conn.execute("SELECT job_id, value, entity_type, context, confidence, mitre_id, accepted, "
                                   "source FROM entities ORDER BY id").fetchall()
        relationship_rows = conn.execute("SELECT job_id, source_value, relationship_type, target_value, confidence, "
                                         "accepted, evidence_text, evidence_label, start_time, stop_time "
                                         "FROM relationships ORDER BY id").fetchall()
        policy_row = conn.execute("SELECT policy_json FROM relationship_policy WHERE id=1").fetchone()
    entities: dict[str, list[dict]] = {}
    for row in entity_rows:
        entities.setdefault(row["job_id"], []).append(row)
    relationships: dict[str, list[dict]] = {}
    for row in relationship_rows:
        relationships.setdefault(row["job_id"], []).append(row)
    selected = [j for j in jobs if not only or any(j["id"].startswith(p) for p in only)]
    items = [{"job": j, "entities": entities.get(j["id"], []), "relationships": relationships.get(j["id"], [])}
             for j in selected]
    policy = None
    if policy_row and policy_row["policy_json"] not in ("", "{}"):
        policy = json.loads(policy_row["policy_json"])
    return items, policy


# ── Output ─────────────────────────────────────────────────────────────────

def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _verdict_line(verdict: Any) -> str:
    return f"{verdict.status}" + (f" ({len(verdict.errors)} error(s))" if verdict.errors else "")


def render(results: Sequence[Mapping[str, Any]], skipped: Sequence[tuple[str, str]],
           findings: Sequence[Mapping[str, Any]],
           out: Path) -> str:
    lines = ["## Round trip: the enriched bundle of each job over its own stored bundle",
             "",
             "| job | file | Stage 5 | baseline objects | enriched objects | lost | altered | added | added by type | "
             "duplicates of a baseline object | rows used | rows unreadable |",
             "|---|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|"]
    for r in results:
        by_type = ", ".join(f"{t} {n}" for t, n in sorted(r["added"]["by_type"].items())) or "none"
        lines.append(f"| {r['id'][:8]} | {_cell(r['filename'][:40])} | {r['verdict']} | {r['baseline_objects']} | "
                     f"{r['enriched_objects']} | {len(r['lost'])} | {len(r['altered'])} | {r['added']['count']} | "
                     f"{by_type} | {len(r['added_duplicates'])} | {r['entity_rows']} + {r['relationship_rows']} | "
                     f"{len(r['unreadable'])} |")
    lines += ["", "### Audit findings (every check, over all enriched bundles)", "",
              "| check | status | severity | count | jobs | detail |", "|---|---|---|---:|---|---|"]
    apart = [f for f in findings if f["name"] == "check_orphan_objects"]
    main = [f for f in findings if f["name"] != "check_orphan_objects"]
    for f in main:
        jobs = ", ".join(j[:8] for j in f["jobs"]) or "-"
        lines.append(f"| {f['name']} | {f['status']} | {f['severity']} | {f['count']}/{f['total']} | {jobs} | "
                     f"{_cell(f['detail'])} |")
    fails = [f for f in main if f["status"] == "FAIL"]
    lines += ["", f"Invariant checks: {len(main)}, FAIL {len(fails)}.", ""]
    for f in apart:
        lines += [f"### Apart: {f['name']} ({f['status']}, {f['count']}/{f['total']} objects, "
                  f"jobs {len(f['jobs'])})", "", _cell(f["detail"]), ""]
    for r in results:
        if r["lost"] or r["altered"] or r["added_duplicates"]:
            lines += [f"### {r['id'][:8]}", ""]
            if r["lost"]:
                lines.append(f"- lost ({len(r['lost'])}): " + ", ".join(r["lost"][:_SHOWN]))
            if r["altered"]:
                lines.append(f"- altered ({len(r['altered'])}): " + ", ".join(r["altered"][:_SHOWN]))
            for d in r["added_duplicates"][:_SHOWN]:
                lines.append(f"- duplicate: {d['type']} \"{_cell(str(d['name']))}\" {d['id']} of "
                             f"{', '.join(d['baseline_ids'])}")
            lines.append("")
    if skipped:
        lines += ["Jobs not run:", ""] + [f"- {jid[:8]}: {reason}" for jid, reason in skipped] + [""]
    lines.append(f"JSON: {out}")
    return "\n".join(lines)


def run(items: Sequence[Mapping[str, Any]],
        policy: dict | None) -> tuple[list[dict], list[tuple[str, str]], list[tuple[str, dict]]]:
    results: list[dict[str, Any]] = []
    skipped: list[tuple[str, str]] = []
    bundles: list[tuple[str, dict]] = []
    for item in items:
        job = item["job"]
        if job["bundle_json"] is None or job["llm_result_json"] is None or not job["report_text"]:
            skipped.append((job["id"], "bundle_json, llm_result_json or report_text is missing"))
            continue
        try:
            inputs = job_inputs(job, item["entities"], item["relationships"])
            built = build_enriched(job, inputs, policy)
        except Exception as exc:  # noqa: BLE001 — one job that cannot be built is reported, the others go on
            skipped.append((job["id"], f"{type(exc).__name__}: {str(exc)[:300]}"))
            continue
        baseline = built["baseline"]
        cmp = compare(baseline.objects, built["bundle_json"])
        bundles.append((job["id"], json.loads(built["bundle_json"])))
        results.append({
            "id": job["id"], "filename": job["original_filename"], "verdict": _verdict_line(built["verdict"]),
            "verdict_errors": built["verdict"].errors[:_SHOWN], "upload_found": built["upload_found"],
            "entity_rows": inputs["entity_rows"], "relationship_rows": inputs["relationship_rows"],
            "unreadable": inputs["unreadable"],
            "baseline_objects": cmp["baseline_objects"], "enriched_objects": cmp["enriched_objects"],
            "lost": cmp["lost"], "altered": cmp["altered"], "added": cmp["added"],
            "added_duplicates": cmp["added_duplicates"],
        })
    return results, skipped, bundles


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Round trip of the real reports, offline and read only (ADR-0090, A2)")
    parser.add_argument("--db", default=DEFAULT_DB, help="PostgreSQL DSN of the measurement database (read only)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="JSON evidence file")
    parser.add_argument("--jobs", action="append", default=[], help="job id prefix (repeatable)")
    args = parser.parse_args(argv)

    try:
        items, policy = load_inputs(args.db, args.jobs)
    except Exception as exc:  # noqa: BLE001 — no driver, refused connection, no table or column: all "cannot be read"
        print(f"cannot read the database: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    results, skipped, bundles = run(items, policy)
    findings = audit_findings(bundles)
    evidence = {
        "database": re.sub(r"://[^@/]*@", "://", args.db),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "policy": "saved" if policy else "none saved (the worker builds without one)",
        "differences_from_the_worker": [
            "no held_reason column: a row ships when accepted is 1, or NULL",
            "no enrichment_status column: no row is a baseline_stix row",
            "no times_json column: relationship dates are the legacy start/stop",
            "no pipeline_mode column: each job is built as the enrich job it simulates",
            "no upload file on disk for these jobs" if not any(r["upload_found"] for r in results) else
            "upload files found for some jobs: source hash and anchor from the file",
            "cve_metadata is {}: no CVE row in these jobs (a job with one is skipped)",
            "long-distance inference off: the policy does not enable it (no LLM call)",
        ],
        "jobs": results, "skipped": [{"id": jid, "reason": reason} for jid, reason in skipped],
        "audit": findings,
    }
    markdown = render(results, skipped, findings, args.out)
    try:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
        args.out.with_suffix(".md").write_text(markdown + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"cannot write {args.out}: {exc}", file=sys.stderr)
        return 2
    print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
