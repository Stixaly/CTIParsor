"""Read a migrated database back through this code's HTTP routes (ADR-0094
item 2): what scripts/check_migration_from.py seeded comes back out of the API
as the rows the seed wrote say it should — the expectations are derived from
those rows (`Seeded`), the one source of truth.

    python scripts/migration_readback.py <seeded.json> <result.json>

runs in a process of its own, with DATABASE_URL, CTIPARSOR_STATE_DIR,
CTIPARSOR_UPLOADS_DIR and CTIPARSOR_OUTPUT_DIR naming the migrated database
and the state directory, CTIPARSOR_ROLE=api (no queue loop claims a job) and
API_ALLOWED_HOSTS=testserver: the app starts as a deployment's does — its
lifespan runs init_db, which finds nothing left to migrate — under Starlette's
TestClient, no network.  The result is written to <result.json>; exit 1 on a
mismatch.

What the release had no column or table for the seed did not write, and
nothing here expects it (the script lists those columns and tables with the
seed).  A check that cannot run is listed in `skipped`.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:      # run as a script: the repository root is not on the path
    sys.path.insert(0, str(ROOT))

from scripts.migration_seed import Seeded

_ABSENT = "<absent>"
_TERMINAL = ("for_review", "completed", "failed")   # a progress stream on any other status waits
EXCLUDED_LISTED = 200                               # api.baseline_store: the intake's exclusions a job lists


def _flag(value: Any) -> bool | None:
    return None if value is None else bool(value)


def _label(value: Any) -> str:
    return value or "reported"


# Route field: (the column it shows, how the route turns the stored value into it).
Fields = dict[str, tuple[str, Callable[[Any], Any] | None]]
_JOB_LISTED: Fields = {c: (c, None) for c in ("id", "original_filename", "status", "tlp_level", "pap_level",
                                              "pipeline_mode", "created_at", "updated_at")}
_JOB: Fields = {**_JOB_LISTED, "report_text": ("report_text", None)}
_ENTITY: Fields = {
    **{c: (c, None) for c in ("id", "job_id", "value", "entity_type", "context", "confidence", "mitre_id",
                              "source", "decision_origin", "held_reason", "enrichment_status", "baseline_stix_id")},
    "accepted": ("accepted", _flag), "control_sample": ("control_sample", bool),
}
_RELATIONSHIP: Fields = {
    **{c: (c, None) for c in ("id", "job_id", "source_value", "relationship_type", "target_value", "confidence",
                              "evidence_text", "decision_origin", "held_reason", "enrichment_status",
                              "baseline_stix_id")},
    "accepted": ("accepted", _flag), "evidence_label": ("evidence_label", _label),
}
_OVERRIDE: Fields = {c: (c, None) for c in ("id", "term", "entity_type", "action", "status", "display",
                                            "accepted_count", "rejected_count", "job_count", "origin", "note",
                                            "created_at", "updated_at")}
_THRESHOLD: Fields = {c: (c, None) for c in ("source", "entity_type", "threshold", "sample_size",
                                             "target_precision", "precision_at", "recall_retained", "origin",
                                             "updated_at")}
_RULE: Fields = {c: (c, None) for c in ("id", "corpus", "title", "description", "severity", "license",
                                        "source_ref", "platform", "format", "raw")}


def expected_fields(row: dict[str, Any], fields: Fields) -> dict[str, Any]:
    """What a route shows of a seeded row: a column the seed skipped decides nothing."""
    return {name: (fn(row[col]) if fn else row[col]) for name, (col, fn) in fields.items() if col in row}


def _short(value: Any, width: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= width else f"{text[:width]}... ({len(text)} chars)"


@dataclass
class ReadBack:
    passed: int = 0
    mismatches: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches


class _Check:
    def __init__(self, client: Any) -> None:
        self.client = client
        self.result = ReadBack()

    def same(self, where: str, expected: Any, got: Any) -> None:
        if expected == got:
            self.result.passed += 1
        else:
            self.result.mismatches.append(f"{where}: expected {_short(expected)}, got {_short(got)}")

    def status(self, where: str, response: Any, code: int) -> bool:
        self.same(f"{where} status", code, response.status_code)
        return bool(response.status_code == code)

    def fields(self, where: str, expected: dict[str, Any], got: Any) -> None:
        if not isinstance(got, dict):
            self.result.mismatches.append(f"{where}: not returned")
            return
        for name, value in expected.items():
            self.same(f"{where} {name}", value, got.get(name, _ABSENT))

    def get_json(self, path: str) -> Any:
        response = self.client.get(path)
        if response.status_code != 200:
            self.result.mismatches.append(f"GET {path}: status {response.status_code}")
            return None
        return response.json()


def _of(rows: dict[str, list[dict[str, Any]]], table: str, job_id: str) -> list[dict[str, Any]]:
    return [r for r in rows.get(table, []) if r.get("job_id") == job_id]


def _sse(text: str) -> list[tuple[str, str]]:
    """(event, data) of each event of a text/event-stream body."""
    out = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            name, sep, value = line.partition(": ")
            if sep:
                fields[name] = value
        if "event" in fields:
            out.append((fields["event"], fields.get("data", "")))
    return out


def read_back(client: Any, seeded: Seeded) -> ReadBack:
    """Every seeded row a route shows, read through that route."""
    check = _Check(client)
    jobs = seeded.rows.get("jobs", [])
    listed = {j["id"]: j for j in check.get_json("/api/jobs") or []}
    for job in jobs:
        check.fields(f"GET /api/jobs [{job['id']}]", expected_fields(job, _JOB_LISTED), listed.get(job["id"]))
    for job in jobs:
        _job(check, seeded, job)
    _settings(check, seeded.rows)
    return check.result


def _job(check: _Check, seeded: Seeded, job: dict[str, Any]) -> None:
    rows, path = seeded.rows, f"/api/jobs/{job['id']}"
    entities, relationships = _of(rows, "entities", job["id"]), _of(rows, "relationships", job["id"])
    detail = check.get_json(path)
    check.fields(f"GET {path}", {**expected_fields(job, _JOB), "entity_count": len(entities),
                                 "relationship_count": len(relationships)}, detail)
    baseline = next(iter(_of(rows, "job_baselines", job["id"])), None)
    if job.get("pipeline_mode") == "enrich" and baseline is not None and isinstance(detail, dict):
        intake = json.loads(baseline["intake_json"])
        counts = {table: dict(Counter(r["enrichment_status"] for r in _of(rows, table, job["id"])
                                      if r.get("enrichment_status")))
                  for table in ("entities", "relationships")}
        check.fields(f"GET {path} enrichment", {
            "validated": bool(baseline["validated"]), "counts": counts,
            "intake": {**intake, "excluded": intake["excluded"][:EXCLUDED_LISTED],
                       "excluded_total": len(intake["excluded"])},
        }, detail.get("enrichment"))
    got = {e["id"]: e for e in check.get_json(f"{path}/entities") or []}
    for row in entities:
        check.fields(f"GET {path}/entities [{row['id']}]", expected_fields(row, _ENTITY), got.get(row["id"]))
    got = {r["id"]: r for r in check.get_json(f"{path}/relationships") or []}
    for row in relationships:
        where = f"GET {path}/relationships [{row['id']}]"
        check.fields(where, expected_fields(row, _RELATIONSHIP), got.get(row["id"]))
        _dates(check, where, row, got.get(row["id"]))
    _bundle(check, path, job)
    if baseline is not None:
        for suffix, column in (("baseline", "bundle_json"), ("baseline/intake", "intake_json")):
            response = check.client.get(f"{path}/{suffix}")
            if check.status(f"GET {path}/{suffix}", response, 200):
                check.same(f"GET {path}/{suffix} body", baseline[column], response.content.decode("utf-8"))
    source = seeded.sources.get(job["id"])
    if source is not None:
        response = check.client.get(f"{path}/source")
        if check.status(f"GET {path}/source", response, 200):
            check.same(f"GET {path}/source sha256 ({source})", seeded.files[source],
                       hashlib.sha256(response.content).hexdigest())
    _progress(check, path, job, _of(rows, "progress_events", job["id"]))


def _dates(check: _Check, where: str, row: dict[str, Any], got: Any) -> None:
    if not isinstance(got, dict):
        return
    if row.get("times_json"):
        stored = json.loads(row["times_json"])
        shown = got.get("times") or []
        check.same(f"{where} times", len(stored), len(shown))
        for i, (assertion, seen) in enumerate(zip(stored, shown, strict=False)):
            check.fields(f"{where} times[{i}]", assertion, seen)
    elif "start_time" in row:          # a row from before ADR-0063: its bounds, as stored
        check.same(f"{where} start_time", row["start_time"], got.get("start_time", _ABSENT))
        check.same(f"{where} stop_time", row.get("stop_time"), got.get("stop_time", _ABSENT))


def _bundle(check: _Check, path: str, job: dict[str, Any]) -> None:
    if "bundle_json" in job:
        where, response = f"GET {path}/bundle", check.client.get(f"{path}/bundle")
        if not job["bundle_json"]:
            check.status(where, response, 404)
        elif job.get("bundle_validation") == "invalid":
            if check.status(where, response, 409):
                errors = json.loads(job.get("bundle_validation_errors") or "[]")
                check.same(f"{where} detail", {"validation": "invalid", "errors": errors},
                           response.json().get("detail"))
        elif check.status(where, response, 200):
            check.same(f"{where} body", json.loads(job["bundle_json"]), response.json())
            if "bundle_validation" in job:
                check.same(f"{where} X-Bundle-Validation", job["bundle_validation"] or "unknown",
                           response.headers.get("x-bundle-validation"))
    if job.get("bundle_json") and "bundle_ledger_json" in job:
        where, response = f"GET {path}/bundle/ledger", check.client.get(f"{path}/bundle/ledger")
        if not job["bundle_ledger_json"]:
            check.status(where, response, 404)
        elif check.status(where, response, 200):
            check.same(f"{where} body", json.loads(job["bundle_ledger_json"]), response.json())


def _progress(check: _Check, path: str, job: dict[str, Any], events: list[dict[str, Any]]) -> None:
    if job.get("status") not in _TERMINAL:
        check.result.skipped.append(f"GET {path}/progress: a job in {job.get('status')!r} streams until it ends")
        return
    expected = [("connected", json.dumps({"job_id": job["id"]}))]
    for event in sorted(events, key=lambda e: e["id"]):
        expected.append((event["event_type"], event["data"]))
        if event["event_type"] == "done":
            break
    else:                              # no `done` stored: the route sends one with the job's status
        expected.append(("done", json.dumps({"status": job["status"]})))
    response = check.client.get(f"{path}/progress")
    if check.status(f"GET {path}/progress", response, 200):
        check.same(f"GET {path}/progress events", expected, _sse(response.text))


def _settings(check: _Check, rows: dict[str, list[dict[str, Any]]]) -> None:
    """What an analyst grows beside the reports: overrides, thresholds, the
    relationship policy, the detection rules."""
    got = {r["id"]: r for r in (check.get_json("/api/overrides") or {}).get("rows", [])}
    for row in rows.get("entity_overrides", []):
        check.fields(f"GET /api/overrides [{row['id']}]", expected_fields(row, _OVERRIDE), got.get(row["id"]))
    got = {(r["source"], r["entity_type"]): r for r in (check.get_json("/api/thresholds") or {}).get("rows", [])}
    for row in rows.get("model_thresholds", []):
        check.fields(f"GET /api/thresholds [{row['source']}/{row['entity_type']}]",
                     expected_fields(row, _THRESHOLD), got.get((row["source"], row["entity_type"])))
    for row in rows.get("relationship_policy", []):
        if row.get("id") == 1 and "policy_json" in row:
            check.same("GET /api/relationship-policy", json.loads(row["policy_json"]),
                       check.get_json("/api/relationship-policy"))
    canonical = [r for r in rows.get("detection_rules", []) if r.get("is_canonical", 1)]
    if not canonical:
        return
    response = check.client.post("/api/rules/lookup",
                                 json={"rule_ids": [r["id"] for r in canonical], "include_body": True})
    ok = check.status("POST /api/rules/lookup", response, 200)
    got = {r["id"]: r for r in response.json().get("rules", [])} if ok else {}
    for row in canonical:
        expected = expected_fields(row, _RULE)
        expected["bytes"] = next((b["bytes"] for b in rows.get("rule_bytes", []) if b["rule_id"] == row["id"]), 0)
        expected["techniques"] = sorted(t["technique_id"] for t in rows.get("rule_techniques", [])
                                        if t["rule_id"] == row["id"])
        check.fields(f"POST /api/rules/lookup [{row['id']}]", expected, got.get(row["id"]))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    seeded = Seeded.from_json(Path(args[0]).read_text(encoding="utf-8"))
    from fastapi.testclient import TestClient

    import api.main
    with TestClient(api.main.app, raise_server_exceptions=False) as client:
        result = read_back(client, seeded)
    Path(args[1]).write_text(json.dumps(asdict(result), indent=1) + "\n", encoding="utf-8")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
