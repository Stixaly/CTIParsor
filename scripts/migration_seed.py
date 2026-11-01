"""What `scripts/check_migration_from.py` writes into a database an older
release created, before migrating it (ADR-0094 item 2): the rows and files a
deployment holds after some use, as a spec, table by table.

Four reports — one finalized and completed (its source file, entities of every
kind accepted, rejected and pending, a control sample, a held entity and a held
relationship, dated and legacy-dated relationships, the decision journal, the
bundle with its verdict, ledger and build record, progress events, a figure),
one whose bundle the STIX schemas refused, one enriching an analyst's STIX
bundle (ADR-0090: its baseline, rows imported from it), one that failed — and
what an analyst grows beside them: entity overrides, calibrated thresholds, the
relationship policy, a detection rule with its side tables, the figure and CVE
caches; and the row a worker that crashed leaves in `worker_heartbeats`
(ADR-0094 item 7).  Uploaded sources and exported bundles are files of the
state volume, not rows: `files()`.

The spec is this code's; the schema is the release's.  `seed` reads the
database's columns first: a column the spec names that the release did not have
yet is skipped (an older release), and a NOT NULL column without a default that
a row of the spec leaves out stops the seed (SeedError: the spec must learn
it).  `coverage_errors`: every table of the release's schema receives rows, and
every column of it a non-NULL value in at least one of them, unless `NOT_SEEDED`
says why not: a column NULL in every row is one a migration could wipe unseen.

Payloads are real ones: the bundles and ledgers of three Stage 4 reference
builds (tests/fixtures/stage4_reference/expected/, their random ids and build
times replaced by fixed ones), a STIX baseline from tests/fixtures/baselines/
with the index and intake the intake wrote for it, a run config, a build record
and an LLM result as the worker writes them.  The Stage 4 builds come from the
release's own tree when it has them (`release_stage4`): the bundles and ledgers
a deployment of that release stored are in its shape, not in this code's.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

# Tables ("table") of a release's schema that receive no row, and columns
# ("table.column") that stay NULL in every seeded row, and why.  The version
# table is the migration runner's own, and so are its `_pre_vNNNN_<table>` copies.
NOT_SEEDED: dict[str, str] = {}
RUNNER_TABLES = ("schema_migrations",)
RUNNER_PREFIX = "_pre_v"


class SeedError(RuntimeError):
    """The spec cannot be written into this schema."""


# ── Reading a schema ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Column:
    data_type: str
    required: bool      # NOT NULL, no default, not an identity, not generated
    generated: bool


def schema_columns(conn: Any) -> dict[str, dict[str, Column]]:
    """{table: {column: Column}} for every base table of the connection's schema."""
    rows = conn.execute(
        "SELECT c.table_name, c.column_name, c.data_type, c.is_nullable, c.column_default, "
        "c.is_identity, c.is_generated FROM information_schema.columns c "
        "JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name "
        "WHERE c.table_schema = current_schema() AND t.table_type = 'BASE TABLE' "
        "ORDER BY c.table_name, c.ordinal_position").fetchall()
    out: dict[str, dict[str, Column]] = {}
    for r in rows:
        generated = r["is_generated"] == "ALWAYS"
        required = (r["is_nullable"] == "NO" and r["column_default"] is None
                    and r["is_identity"] == "NO" and not generated)
        out.setdefault(r["table_name"], {})[r["column_name"]] = Column(r["data_type"], required, generated)
    return out


def primary_keys(conn: Any) -> dict[str, tuple[str, ...]]:
    """{table: primary key columns, in key order}; a table without one is absent."""
    rows = conn.execute(
        "SELECT c.relname AS table_name, a.attname AS column_name FROM pg_index i "
        "JOIN pg_class c ON c.oid = i.indrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
        "JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true "
        "JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum "
        "WHERE i.indisprimary AND n.nspname = current_schema() ORDER BY c.relname, k.ord").fetchall()
    out: dict[str, tuple[str, ...]] = {}
    for r in rows:
        out[r["table_name"]] = (*out.get(r["table_name"], ()), r["column_name"])
    return out


def is_runner_table(table: str) -> bool:
    return table in RUNNER_TABLES or table.startswith(RUNNER_PREFIX)


# ── Payloads ─────────────────────────────────────────────────────────────────

def fixed_uuid4(*parts: str) -> str:
    """A uuid4-shaped id that is the same at every run."""
    digest = hashlib.sha256("/".join(parts).encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


_BUILD_TIME = "2026-10-20T09:15:41.512Z"
_RANDOM_ID = re.compile(r"\b([a-z][a-z0-9-]*)--R(\d+)\b")


def _strings(value: Any, fn: Any) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_strings(v, fn) for v in value]
    if isinstance(value, dict):
        return {fn(k): _strings(v, fn) for k, v in value.items()}
    return value


STAGE4 = FIXTURES / "stage4_reference"
STAGE4_BUILDS = ("long_distance", "minimal", "policy_pin")


def stage4_build(name: str, stage4: Path = STAGE4) -> tuple[str, str]:
    """(bundle_json, bundle_ledger_json) of the Stage 4 reference build `name`.
    The expected file is a canonical form (tests/stage4_reference.py): its
    build times and the labels of its random ids become fixed values, and the
    bundle gets its envelope back."""
    canon = json.loads((stage4 / "expected" / f"{name}.json").read_text(encoding="utf-8"))

    def real(text: str) -> str:
        text = text.replace("<build-time>", _BUILD_TIME)
        return _RANDOM_ID.sub(lambda m: f"{m.group(1)}--{fixed_uuid4(name, m.group(0))}", text)

    bundle = {"type": "bundle", "id": f"bundle--{fixed_uuid4(name, 'bundle')}",
              "objects": _strings(canon["objects"], real)}
    return json.dumps(bundle, indent=4, ensure_ascii=False), json.dumps(_strings(canon["ledger"], real))


def stage4_report_text(name: str, stage4: Path = STAGE4) -> str:
    scenario = stage4 / "scenarios" / f"{name}.json"
    return json.loads(scenario.read_text(encoding="utf-8"))["report_text"]


def release_stage4(tree: Path) -> Path | None:
    """The Stage 4 reference builds of a release's tree (a `git archive` of
    it), when it has the three the seed uses in a shape it reads: a bundle's
    objects, a ledger, the report's text.  None otherwise (v0.1.0 has none):
    the seed then writes this code's."""
    stage4 = tree / "tests" / "fixtures" / "stage4_reference"
    try:
        for name in STAGE4_BUILDS:
            canon = json.loads((stage4 / "expected" / f"{name}.json").read_text(encoding="utf-8"))
            text = stage4_report_text(name, stage4)
            if not (isinstance(canon, dict) and isinstance(canon.get("objects"), list)
                    and isinstance(canon.get("ledger"), dict) and isinstance(text, str)):
                return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return stage4


_BASELINE_FILE = FIXTURES / "baselines" / "report_with_confidence.json"
_BASELINE_REPORT = "report--b0008d3d-2c27-40dd-908b-a9e4b9081537"
_BASELINE_AUTHOR = "identity--c89d98a7-0e51-431d-844c-564af15409aa"
_BASELINE_MALWARE = "malware--075f056c-2977-44fe-bbac-7c1fcc514e18"
_BASELINE_SHA = "4fae528442e7440be8ab82111ed0d2b61c8ad620aed289b75c2f0df9b3d06ca7"
_BASELINE_BUNDLE_ID = "bundle--fe796f44-3538-4570-8f21-8b9083c91552"
# What the intake wrote for that file, schemas checked (api.baseline_store).
_BASELINE_INDEX = {
    "version": 1, "sha256": _BASELINE_SHA, "bundle_id": _BASELINE_BUNDLE_ID,
    "entries": [{
        "entry_id": _BASELINE_MALWARE, "stix_type": "malware", "entity_type": "malware",
        "value": "WellMess", "mitre_id": "S0514",
        "keys": [["id", _BASELINE_MALWARE], ["mitre", "S0514"], ["named", "software", "s0514"],
                 ["named", "software", "wellmess"]],
        "weak_keys": [], "sco_id": None, "indicator_ids": [], "object_ids": [_BASELINE_MALWARE],
        "surface_forms": ["wellmess"]}],
    "relations": [],
    "imported_ids": [_BASELINE_AUTHOR, _BASELINE_MALWARE, _BASELINE_REPORT],
    "passthrough_ids": [_BASELINE_AUTHOR, _BASELINE_REPORT],
    "report_ids": [_BASELINE_REPORT], "scope_report_id": _BASELINE_REPORT,
}
_BASELINE_INTAKE = {
    "sha256": _BASELINE_SHA, "bundle_id": _BASELINE_BUNDLE_ID,
    "counts": {"identity": 1, "malware": 1, "report": 1, "out_of_scope": 0, "dangling_refs": 0},
    "excluded": [], "warnings": [],
    "reports": [{"id": _BASELINE_REPORT, "name": "A report the analyst already rated",
                 "published": "2026-03-01T00:00:00.000Z", "refs": 1}],
    "scope_report_id": _BASELINE_REPORT, "needs_report_choice": False, "min_tlp": None, "min_pap": None,
}

_GIT_REV = "ce59cfb7025daf46fcb661b71c1ac7cd23f3f16b"
_MANIFEST = {
    "llm": {"model": "anthropic/claude-sonnet-4-5", "prompt_fingerprint": "606528fb5beba5c6",
            "sampling": "provider default"},
    "models": {"embedding": "all-MiniLM-L6-v2", "cyner": "PranavaKailash/CyNER-2.0-DeBERTa-v3-base",
               "gliner": "urchade/gliner_large-v2.1"},
    "attack": {"release": "19.2", "default": True, "requested": None, "directory": "pipeline/data",
               "manifest_sha256": "215377cb6bf6d692", "built_with": None,
               "sources": {"enterprise-attack": "f7eaf37fe53b5040", "mobile-attack": None, "ics-attack": None},
               "exceptions": ["attack_relationships.json", "gazetteer.json", "mitre_index.json (CAPEC)"],
               "modified_files": []},
    "data": {"mitre_index.json": "52409d46e5a10a56", "attack_relationships.json": "76c7aec28a0bc4e8"},
    "packages": {"stix2": "3.0.1", "pydantic": "2.12.4", "stix2-validator": "3.2.0"},
}
_ENV = {"LLM_PROVIDER": "anthropic", "ANTHROPIC_MODEL": "claude-sonnet-4-5", "STIX_TLP": "GREEN",
        "ENABLE_STIX_VERIFICATION": "true", "SKIP_HEAVY_MODELS": "0"}
_POLICY = {
    "version": 1, "global": "enforce",
    "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware", "mode": "pin", "enabled": True},
              {"src": "malware", "verb": "uses", "tgt": "tool", "mode": "auto", "enabled": False}],
    "max_pinned_edges": 200, "pin_budget_mode": "fair-share",
    "pin_evidence": {"mode": "cooccurrence", "window": 3},
    "completion": {"transitive": True, "alias": True, "reference": True, "long_distance": True,
                   "max_new_edges": 200},
    "temporal_export": {"mode": "faithful"},
}


def _run_config(recorded_at: str) -> dict:
    """`jobs.run_config_json` as the worker writes it (api.run_config), with
    the stage report it adds at the end of the run."""
    return {
        "recorded_at": recorded_at, "git_rev": _GIT_REV, "policy": _POLICY, "embedding_model": "all-MiniLM-L6-v2",
        "ttp_thresholds": {"high": 0.62, "medium": 0.48},
        "ner_thresholds": {"calibration_enabled": True,
                           "cyner": {"default": 0.7, "overrides": {}},
                           "gliner": {"default": 0.4, "overrides": {"malware": 0.62}}},
        "entity_overrides": {"enabled": True, "deny": 1, "promote": 0, "fingerprint": "50d01b4100fb3536"},
        "stages": {"gazetteer": True, "semantic": True, "cyner": True, "gliner": True, "llm": True,
                   "stix_verification": True, "ttp_verification": True, "consensus": False,
                   "skip_heavy_models": False},
        "env": _ENV, "manifest": _MANIFEST,
        "stage_report": [
            {"stage": "1", "status": "ran", "reason": "", "seconds": 0.412, "counts": {"chars": 212, "chunks": 1}},
            {"stage": "3", "status": "ran", "reason": "", "seconds": 18.73, "counts": {"relationships": 1}},
            {"stage": "5", "status": "ran", "reason": "", "seconds": 1.204,
             "counts": {"valid": 1, "unverified": 0, "warnings": 0}},
        ],
    }


def _build_record(kind: str, built_at: str, baseline_sha256: str | None = None) -> dict:
    """`jobs.bundle_build_json` (api.run_config.build_record)."""
    record: dict[str, Any] = {"kind": kind, "built_at": built_at, "git_rev": _GIT_REV, "policy": _POLICY,
                              "env": _ENV, "manifest": _MANIFEST}
    if baseline_sha256 is not None:
        record["baseline_sha256"] = baseline_sha256
    return record


def _llm_result(**changes: Any) -> str:
    """`jobs.llm_result_json`: LLMEnrichmentResult.model_dump_json()."""
    result = {
        "threat_actors": ["Frost Spider"], "malware_families": ["Nightbell"], "tools": ["Rclone"], "ttps": [],
        "relationships": [{"source_value": "Frost Spider", "relationship_type": "uses",
                           "target_value": "Nightbell", "confidence": 0.9,
                           "evidence_text": "Frost Spider operates the Nightbell backdoor.",
                           "evidence_label": "reported", "times": []}],
        "ioc_associations": [], "targeted_sectors": [], "targeted_countries": [], "campaign_name": None,
        "course_of_action": [], "ttp_review": [],
        "rel_review": [{"source_value": "Frost Spider", "relationship_type": "uses", "target_value": "Rclone",
                        "confidence": 0.6,
                        "evidence_text": "Frost Spider staged archives with Rclone before exfiltration.",
                        "evidence_label": "reported", "times": [], "reason": "unverified"}],
    }
    return json.dumps({**result, **changes}, separators=(",", ":"))


# A dated relationship (ADR-0063), as pipeline.temporal.times_to_json writes it.
_TIMES = [{"id": "5c1f0e2a9b7d", "role": "start", "time_text": "since March 2023", "value": "2023-03",
           "precision": "month", "qualifier": "none", "model_value": "2023-03", "alternatives": [],
           "anchor": "explicit", "evidence_label": "reported", "status": "verified", "origin": "llm"}]
_AUTO_POLICY = "auto-accept/1 level=0.90 control=0.05"
_PDF = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
_RULE_RAW = ("title: Rclone Exfiltration To Cloud Storage\nid: 5f1c3c3e-8f9e-4b44-a6a0-3a2d7c1e9b10\n"
             "status: stable\nlogsource:\n  category: process_creation\n  product: windows\n"
             "detection:\n  selection:\n    Image|endswith: '\rclone.exe'\n    CommandLine|contains: 'copy'\n"
             "  condition: selection\nlevel: high\ntags:\n  - attack.exfiltration\n  - attack.t1567.002\n")
_FIGURE_SHA = hashlib.sha256(b"figure 0 of nightbell_notes").hexdigest()


# ── The spec ─────────────────────────────────────────────────────────────────

JOB_A = "6f1d9a3e-2b7c-4e58-9a41-3c0e7b5d2f18"    # finalized and completed
JOB_B = "a2c4e6f8-1b3d-4f5a-8c7e-9d0b2a4c6e81"    # a URL capture whose bundle the schemas refused
JOB_C = "0b9e8d7c-6a5f-4e3d-9c2b-1a0f9e8d7c6b"    # enriches an analyst's STIX bundle (ADR-0090)
JOB_D = "d4c3b2a1-9f8e-4d7c-8b6a-5f4e3d2c1b0a"    # failed in Stage 1
JOB_GONE = "e7f6a5b4-c3d2-4e1f-8a9b-0c1d2e3f4a5b"  # deleted since: its decisions stay (version 7)
RULE = "sigmahq:5f1c3c3e-8f9e-4b44-a6a0-3a2d7c1e9b10"
RULE_COPY = "community:5f1c3c3e-8f9e-4b44-a6a0-3a2d7c1e9b10"
C_TEXT = "WellMess beacons to its C2 every 30 minutes; the operators reused it in 2026.\n"


def _e(key: str) -> str:
    return fixed_uuid4("entity", key)


def _r(key: str) -> str:
    return fixed_uuid4("relationship", key)


def _t(day: int, hms: str) -> str:
    """A timestamp as api.db.now_iso writes it."""
    return f"2026-10-{day:02d}T{hms}+00:00"


def files(stage4: Path = STAGE4) -> dict[str, bytes]:
    """The state volume's files, by path under it (the image links
    /app/uploads and /app/output into /app/state)."""
    bundle_a, _ = stage4_build("long_distance", stage4)
    bundle_b, _ = stage4_build("minimal", stage4)
    meta = {"url": "https://advisories.example.test/coldriver",
            "candidates": [{"key": "article:published_time", "value": "2026-10-18T07:00:00Z"}]}
    return {
        f"uploads/{JOB_A}.txt": stage4_report_text("long_distance", stage4).encode("utf-8"),
        f"uploads/{JOB_B}.pdf": _PDF,
        f"uploads/{JOB_B}.txt": stage4_report_text("minimal", stage4).encode("utf-8"),
        f"uploads/meta/{JOB_B}.json": json.dumps(meta).encode("utf-8"),
        f"uploads/{JOB_C}.txt": C_TEXT.encode("utf-8"),
        f"uploads/{JOB_D}.docx": b"PK\x03\x04\x14\x00\x06\x00 a docx cut short\x00\x00",
        f"output/nightbell_notes_{JOB_A}_bundle.json": bundle_a.encode("utf-8"),
        f"output/coldriver-advisory_{JOB_B}_bundle_invalid.json": bundle_b.encode("utf-8"),
    }


# The file GET /api/jobs/{id}/source serves, per job: a URL capture serves its PDF.
SOURCES = {
    JOB_A: f"uploads/{JOB_A}.txt",
    JOB_B: f"uploads/{JOB_B}.pdf",
    JOB_C: f"uploads/{JOB_C}.txt",
    JOB_D: f"uploads/{JOB_D}.docx",
}


def _jobs(stage4: Path) -> list[dict[str, Any]]:
    bundle_a, ledger_a = stage4_build("long_distance", stage4)
    bundle_b, ledger_b = stage4_build("minimal", stage4)
    bundle_c, ledger_c = stage4_build("policy_pin", stage4)
    return [
        {"id": JOB_A, "original_filename": "nightbell_notes.txt", "status": "completed",
         "report_text": stage4_report_text("long_distance", stage4), "bundle_json": bundle_a,
         "llm_result_json": _llm_result(), "tlp_level": "GREEN", "pap_level": "GREEN",
         "created_at": _t(20, "09:14:03.512345"), "updated_at": _t(21, "16:02:44.120931"),
         "run_config_json": json.dumps(_run_config("2026-10-20T09:14:05Z")),
         "worker_id": "worker-7f3a2c", "heartbeat_at": _t(20, "09:15:40.004112"),
         "bundle_ledger_json": ledger_a, "bundle_validation": "validated", "bundle_validation_errors": None,
         "review_revision": 9, "bundle_review_revision": 9,
         "bundle_build_json": json.dumps(_build_record("finalize", "2026-10-21T16:02:44Z")),
         "pipeline_mode": "full"},
        {"id": JOB_B, "original_filename": "coldriver-advisory.pdf", "status": "for_review",
         "report_text": stage4_report_text("minimal", stage4), "bundle_json": bundle_b,
         "llm_result_json": _llm_result(threat_actors=[], malware_families=[], tools=[], relationships=[],
                                        rel_review=[]),
         "tlp_level": "AMBER+STRICT", "pap_level": "AMBER",
         "created_at": _t(22, "11:40:00.000001"), "updated_at": _t(22, "11:41:12.734002"),
         "run_config_json": json.dumps(_run_config("2026-10-22T11:40:02Z")),
         "worker_id": "worker-7f3a2c", "heartbeat_at": _t(22, "11:41:10.000000"),
         "bundle_ledger_json": ledger_b, "bundle_validation": "invalid",
         "bundle_validation_errors": json.dumps([
             "indicator--8e8354cb-f2f9-5e91-9027-16f761042512: 'valid_from' is a required property",
             "identity--df314057-d669-5e4d-aa9c-5257582a7ecd: 'identity_class' is not one of the allowed values"]),
         "review_revision": 2, "bundle_review_revision": 2,
         "bundle_build_json": json.dumps(_build_record("run", "2026-10-22T11:41:12Z")),
         "pipeline_mode": "full"},
        {"id": JOB_C, "original_filename": "wellmess-followup.txt", "status": "for_review",
         "report_text": C_TEXT, "bundle_json": bundle_c,
         "llm_result_json": _llm_result(threat_actors=[], malware_families=["WellMess"], tools=[],
                                        relationships=[], rel_review=[]),
         "tlp_level": "AMBER", "pap_level": None,
         "created_at": _t(25, "08:00:00.250000"), "updated_at": _t(25, "08:03:31.900000"),
         "run_config_json": json.dumps(_run_config("2026-10-25T08:00:01Z")),
         "worker_id": None, "heartbeat_at": None,
         "bundle_ledger_json": ledger_c, "bundle_validation": "unverified", "bundle_validation_errors": None,
         "review_revision": 4, "bundle_review_revision": 4,
         "bundle_build_json": json.dumps(_build_record("quick", "2026-10-25T08:03:31Z", _BASELINE_SHA)),
         "pipeline_mode": "enrich"},
        {"id": JOB_D, "original_filename": "broken.docx", "status": "failed", "report_text": None,
         "bundle_json": None, "llm_result_json": None, "tlp_level": None, "pap_level": None,
         "created_at": _t(26, "17:20:00.000000"), "updated_at": _t(26, "17:20:02.500000"),
         "run_config_json": None, "worker_id": None, "heartbeat_at": None, "bundle_ledger_json": None,
         "bundle_validation": None, "bundle_validation_errors": None, "review_revision": 0,
         "bundle_review_revision": None, "bundle_build_json": None, "pipeline_mode": "full"},
    ]


def _entities() -> list[dict[str, Any]]:
    return [
        {"id": _e("a-actor"), "job_id": JOB_A, "value": "Frost Spider", "entity_type": "threat_actor",
         "context": "Frost Spider operates the Nightbell backdoor.", "confidence": 0.96, "mitre_id": None,
         "accepted": 1, "source": "gazetteer", "decision_origin": "auto_policy",
         "decided_at": _t(20, "09:15:39.100000"), "policy_version": _AUTO_POLICY, "control_sample": 0},
        {"id": _e("a-malware"), "job_id": JOB_A, "value": "Nightbell", "entity_type": "malware",
         "context": "the Nightbell backdoor", "confidence": 0.93, "accepted": None, "source": "gliner",
         "decision_origin": None, "control_sample": 1},
        {"id": _e("a-tool"), "job_id": JOB_A, "value": "Rclone", "entity_type": "tool",
         "context": "the tool Rclone on the file server", "confidence": 0.71, "accepted": 1, "source": "llm",
         "decision_origin": "human", "decided_at": _t(21, "15:58:10.000000"), "control_sample": 0},
        {"id": _e("a-ip"), "job_id": JOB_A, "value": "203.0.113.77", "entity_type": "ipv4", "context": "",
         "confidence": 1.0, "accepted": 0, "source": "regex", "decision_origin": "human_bulk",
         "decided_at": _t(21, "15:59:02.000000"), "control_sample": 0},
        {"id": _e("a-ttp"), "job_id": JOB_A, "value": "Exfiltration to Cloud Storage", "entity_type": "ttp",
         "context": "staged archives with Rclone before exfiltration", "confidence": 0.58,
         "mitre_id": "T1567.002", "accepted": None, "source": "semantic",
         "evidence_text": "Frost Spider staged archives with Rclone before exfiltration.",
         "evidence_label": "observed", "evidence_start": 135, "evidence_end": 196,
         "held_reason": "unverified", "decision_origin": None, "control_sample": 0},
        {"id": _e("a-legacy"), "job_id": JOB_A, "value": "T1059", "entity_type": "technique",
         "context": "", "confidence": 0.9, "mitre_id": "T1059", "accepted": 1, "source": "llm",
         "decision_origin": "legacy", "control_sample": 0},
        {"id": _e("b-ip"), "job_id": JOB_B, "value": "185.220.101.45", "entity_type": "ipv4",
         "context": "Seen: 185.220.101.45", "confidence": 1.0, "accepted": None, "source": "regex",
         "control_sample": 0},
        {"id": _e("b-domain"), "job_id": JOB_B, "value": "evil-update.test", "entity_type": "domain",
         "context": "and evil-update.test.", "confidence": 1.0, "accepted": 1, "source": "regex",
         "decision_origin": "human", "decided_at": _t(22, "12:00:00.000000"), "control_sample": 0},
        {"id": _e("c-imported"), "job_id": JOB_C, "value": "WellMess", "entity_type": "malware", "context": "",
         "confidence": 1.0, "mitre_id": "S0514", "accepted": 1, "source": "baseline_stix",
         "decision_origin": "baseline_stix", "decided_at": _t(25, "08:03:30.000000"), "control_sample": 0,
         "enrichment_status": "baseline_in_text", "baseline_stix_id": _BASELINE_MALWARE},
        {"id": _e("c-new"), "job_id": JOB_C, "value": "wellmess-c2.test", "entity_type": "domain",
         "context": "beacons to its C2", "confidence": 1.0, "accepted": None, "source": "regex",
         "control_sample": 0, "enrichment_status": "new"},
    ]


def _relationships() -> list[dict[str, Any]]:
    return [
        # policy_version: no code writes one on a relationship yet (auto-accept
        # decides entities only); the value makes the comparison guard the column.
        {"id": _r("a-uses-malware"), "job_id": JOB_A, "source_value": "Frost Spider",
         "relationship_type": "uses", "target_value": "Nightbell", "confidence": 0.9, "accepted": 1,
         "evidence_text": "Frost Spider operates the Nightbell backdoor.", "evidence_label": "reported",
         "times_json": json.dumps(_TIMES), "decision_origin": "default", "decided_at": None,
         "policy_version": _AUTO_POLICY},
        {"id": _r("a-uses-tool"), "job_id": JOB_A, "source_value": "Frost Spider", "relationship_type": "uses",
         "target_value": "Rclone", "confidence": 0.6, "accepted": None,
         "evidence_text": "Frost Spider staged archives with Rclone before exfiltration.",
         "evidence_label": "reported", "held_reason": "unverified", "decision_origin": None},
        {"id": _r("a-legacy"), "job_id": JOB_A, "source_value": "Nightbell",
         "relationship_type": "communicates-with", "target_value": "203.0.113.77", "confidence": 0.8,
         "accepted": 0, "evidence_text": None, "evidence_label": "inferred",
         "start_time": "2023-01-01T00:00:00Z", "stop_time": "2023-12-31T00:00:00Z",
         "decision_origin": "human", "decided_at": _t(21, "16:00:00.000000"), "policy_version": None},
        {"id": _r("c-new"), "job_id": JOB_C, "source_value": "WellMess",
         "relationship_type": "communicates-with", "target_value": "wellmess-c2.test", "confidence": 0.85,
         "accepted": 1, "evidence_text": "WellMess beacons to its C2 every 30 minutes",
         "evidence_label": "reported", "decision_origin": "default", "enrichment_status": "new"},
        {"id": _r("c-imported"), "job_id": JOB_C, "source_value": "WellMess", "relationship_type": "attributed-to",
         "target_value": "APT29", "confidence": 1.0, "accepted": 1, "evidence_text": None,
         "evidence_label": None, "decision_origin": "baseline_stix", "decided_at": _t(25, "08:03:30.000000"),
         "enrichment_status": "baseline_only",
         "baseline_stix_id": "relationship--" + fixed_uuid4("baseline", "attributed-to")},
    ]


def _journal() -> list[dict[str, Any]]:
    """`review_decisions`, as pipeline.decisions.record writes it."""
    def row(job: str, kind: str, target: str, previous: int | None, accepted: int | None, origin: str,
            at: str, policy: str | None = None, actor: str | None = None) -> dict[str, Any]:
        return {"job_id": job, "target_kind": kind, "target_id": target, "previous": previous,
                "accepted": accepted, "origin": origin, "actor": actor, "policy_version": policy, "created_at": at}
    return [
        row(JOB_A, "entity", _e("a-actor"), None, 1, "auto_policy", _t(20, "09:15:39.100000"), _AUTO_POLICY),
        # actor stays NULL until the app has an identity (ADR-0058); the value
        # makes the comparison guard the column.
        row(JOB_A, "entity", _e("a-tool"), None, 1, "human", _t(21, "15:58:10.000000"), actor="analyst"),
        row(JOB_A, "entity", _e("a-ip"), None, 0, "human_bulk", _t(21, "15:59:02.000000")),
        row(JOB_A, "relationship", _r("a-legacy"), 1, 0, "human", _t(21, "16:00:00.000000")),
        row(JOB_B, "entity", _e("b-domain"), None, 1, "human", _t(22, "12:00:00.000000")),
        row(JOB_GONE, "entity", _e("gone"), None, 1, "human", _t(15, "10:00:00.000000")),
    ]


def _progress() -> list[dict[str, Any]]:
    def event(job: str, kind: str, data: dict, at: str) -> dict[str, Any]:
        return {"job_id": job, "event_type": kind, "data": json.dumps(data), "created_at": at}
    return [
        event(JOB_A, "queued", {"status": "queued", "position": 0}, _t(20, "09:14:03.600000")),
        event(JOB_A, "stage", {"stage": 1, "label": "Ingestion", "chars": 212, "chunks": 1},
              _t(20, "09:14:06.020000")),
        event(JOB_A, "stage", {"stage": 5, "label": "Validation", "valid": True, "validation": "validated"},
              _t(20, "09:15:41.300000")),
        event(JOB_A, "done", {"status": "for_review"}, _t(20, "09:15:41.700000")),
        event(JOB_B, "stage", {"stage": 5, "label": "Validation", "valid": False, "validation": "invalid"},
              _t(22, "11:41:12.500000")),
        event(JOB_B, "done", {"status": "for_review"}, _t(22, "11:41:12.800000")),
        event(JOB_D, "done", {"status": "failed", "error": "Stage 1: the document could not be read"},
              _t(26, "17:20:02.400000")),
    ]


def _rules() -> dict[str, list[dict[str, Any]]]:
    """A detection rule as pipeline.detection.store writes it, and the copy
    another corpus holds of it (ADR-0010: not canonical)."""
    common = {"native_key": RULE.split(":", 1)[1], "format": "sigma",
              "title": "Rclone Exfiltration To Cloud Storage", "severity": "high", "dedup_key": "rclone-exfil",
              "platform": "windows", "raw": _RULE_RAW}
    return {
        "detection_rules": [
            {"id": RULE, "corpus": "sigmahq", **common, "description": "Detects rclone copying to a remote.",
             "license": "DRL-1.1", "source_ref": "rules/windows/process_creation/proc_creation_win_rclone.yml",
             "content_hash": hashlib.sha256(_RULE_RAW.encode("utf-8")).hexdigest(), "is_canonical": 1,
             "data_sources": json.dumps(["process_creation"])},
            {"id": RULE_COPY, "corpus": "community", **common, "description": "", "license": "unknown",
             "source_ref": "", "content_hash": "", "is_canonical": 0, "data_sources": "[]"},
        ],
        "rule_bytes": [{"rule_id": RULE, "bytes": len(_RULE_RAW)}, {"rule_id": RULE_COPY, "bytes": len(_RULE_RAW)}],
        "rule_techniques": [{"rule_id": RULE, "technique_id": "T1567.002"},
                            {"rule_id": RULE, "technique_id": "T1048"}],
        "rule_text": [{"rule_id": RULE, "body": "Rclone Exfiltration To Cloud Storage Detects rclone copying "
                                                "to a remote."}],
        "rule_atoms": [{"rule_id": RULE, "atom_class": "process", "value": "rclone.exe"},
                       {"rule_id": RULE, "atom_class": "commandline", "value": "copy"}],
        "rule_related": [{"rule_id": RULE, "related_key": "sigmahq:0a3e5c11-2d4f-4b6a-8c9e-1f2a3b4c5d6e",
                          "rel_type": "derived"}],
    }


def spec(stage4: Path = STAGE4) -> dict[str, list[dict[str, Any]]]:
    """{table: rows}, parents first.  Identity columns are left to the
    database; `seed` reads them back.  `stage4`: where the Stage 4 builds
    come from (`release_stage4`)."""
    baseline = _BASELINE_FILE.read_text(encoding="utf-8")
    figure_read = {"kind": "diagram", "verbatim_text": ["Frost Spider", "Nightbell"],
                   "edges": [{"src": "Frost Spider", "dst": "Nightbell", "label": "operates"}], "iocs": [],
                   "provider": "anthropic", "model": "claude-sonnet-4-5", "elapsed_s": 3.2,
                   "input_tokens": 1530, "output_tokens": 212, "error": None}
    return {
        "jobs": _jobs(stage4),
        "entities": _entities(),
        "relationships": _relationships(),
        "review_decisions": _journal(),
        "progress_events": _progress(),
        "job_baselines": [
            {"job_id": JOB_C, "sha256": _BASELINE_SHA, "size_bytes": len(baseline.encode("utf-8")),
             "report_id": _BASELINE_REPORT, "bundle_json": baseline,
             "index_json": json.dumps(_BASELINE_INDEX, separators=(",", ":")),
             "intake_json": json.dumps(_BASELINE_INTAKE, ensure_ascii=True), "validated": 1,
             "created_at": _t(25, "08:00:00.250000"), "updated_at": _t(25, "08:00:09.000000")},
        ],
        "report_figures": [
            {"id": fixed_uuid4("figure", JOB_A, "0"), "job_id": JOB_A, "ordinal": 0, "page": 1,
             "bbox": "72.00,140.50,523.20,410.00", "kind": "diagram", "char_start": 120, "char_end": 168,
             "provider": "anthropic", "model": "claude-sonnet-4-5", "sha256": _FIGURE_SHA},
        ],
        "figure_reads": [
            {"sha256": _FIGURE_SHA, "model": "claude-sonnet-4-5", "prompt_version": 2,
             "read_json": json.dumps(figure_read), "created_at": _t(20, "09:14:30.000000")},
        ],
        "cve_cache": [
            {"cve_id": "CVE-2023-23397", "description": "Microsoft Outlook Elevation of Privilege Vulnerability",
             "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "fetched_at": _t(20, "09:14:50.000000")},
            # A remembered miss: no description and no score.
            {"cve_id": "CVE-2026-49999", "description": None, "cvss_score": None, "cvss_vector": None,
             "fetched_at": _t(20, "09:14:51.000000")},
        ],
        "relationship_policy": [{"id": 1, "policy_json": json.dumps(_POLICY)}],
        "model_thresholds": [
            {"source": "gliner", "entity_type": "malware", "threshold": 0.62, "sample_size": 148,
             "target_precision": 0.9, "precision_at": 0.913, "recall_retained": 0.84, "origin": "calibrated",
             "updated_at": _t(19, "10:00:00.000000")},
            {"source": "cyner", "entity_type": "tool", "threshold": 0.8, "sample_size": 0,
             "target_precision": None, "precision_at": None, "recall_retained": None, "origin": "manual",
             "updated_at": _t(19, "10:05:00.000000")},
        ],
        "entity_overrides": [
            {"id": fixed_uuid4("override", "deny"), "term": "203.0.113.77", "entity_type": "ipv4",
             "action": "deny", "status": "active", "display": None, "accepted_count": 0, "rejected_count": 6,
             "job_count": 4, "origin": "manual", "note": "Our own scanner: never an indicator.",
             "created_at": _t(18, "14:00:00.000000"), "updated_at": _t(21, "16:01:00.000000")},
            {"id": fixed_uuid4("override", "promote"), "term": "nightbell", "entity_type": "malware",
             "action": "promote", "status": "candidate", "display": "Nightbell", "accepted_count": 5,
             "rejected_count": 0, "job_count": 3, "origin": "auto", "note": None,
             "created_at": _t(21, "16:01:30.000000"), "updated_at": _t(21, "16:01:30.000000")},
        ],
        **_rules(),
        # A worker that crashed: no clean stop deleted its row (ADR-0094 item 7).
        "worker_heartbeats": [
            {"worker_id": "worker-1:7:a1b2c3", "role": "worker", "max_concurrent": 1, "app_version": "0.2.0",
             "started_at": _t(25, "07:58:00.000000"), "heartbeat_at": _t(25, "09:31:30.000000")},
        ],
    }


# ── Writing it ───────────────────────────────────────────────────────────────

@dataclass
class Seeded:
    """What `seed` wrote: each row as inserted (the spec's columns the schema
    has, with the identity values the database chose), what it left out, and
    the files under the state directory."""
    rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    skipped_columns: dict[str, list[str]] = field(default_factory=dict)
    skipped_tables: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)       # path under the state directory: sha256
    sources: dict[str, str] = field(default_factory=dict)     # job id: the file its source route serves

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Seeded:
        return cls(**json.loads(text))

    def row_count(self) -> int:
        return sum(len(rows) for rows in self.rows.values())


def quote(name: str) -> str:
    """A table or column name as an SQL identifier."""
    return '"' + name.replace('"', '""') + '"'


def seed(conn: Any, state_dir: Path | None = None, stage4: Path | None = None) -> Seeded:
    """Write `spec()` into the connection's schema and, given `state_dir`,
    `files()` under it; the Stage 4 builds from `stage4` (`release_stage4`),
    this code's when None.  Raises SeedError, before writing anything, when a
    row leaves out a NOT NULL column that has no default."""
    stage4 = stage4 or STAGE4
    columns = schema_columns(conn)
    keys = primary_keys(conn)
    seeded = Seeded()
    missing: list[str] = []
    plan: list[tuple[str, dict[str, Any]]] = []
    for table, rows in spec(stage4).items():
        have = columns.get(table)
        if have is None:
            seeded.skipped_tables.append(table)
            continue
        skipped = sorted({c for r in rows for c in r} - set(have))
        if skipped:
            seeded.skipped_columns[table] = skipped
        required = [c for c, col in have.items() if col.required]
        for i, row in enumerate(rows):
            missing += [f"{table}.{c} (row {i})" for c in required if c not in row]
            plan.append((table, {c: v for c, v in row.items() if c in have and not have[c].generated}))
    if missing:
        raise SeedError("NOT NULL columns without a default that the seed leaves out "
                        f"(scripts/migration_seed.py): {', '.join(missing)}")
    for table, row in plan:
        key = keys.get(table, ())
        sql = (f"INSERT INTO {quote(table)} ({', '.join(map(quote, row))}) "
               f"VALUES ({', '.join('?' * len(row))})")
        if key:
            sql += f" RETURNING {', '.join(map(quote, key))}"
        cur = conn.execute(sql, tuple(row.values()))
        inserted = dict(row)
        if key:
            got = cur.fetchone()
            inserted.update({k: got[k] for k in key})
        seeded.rows.setdefault(table, []).append(inserted)
    _write_back(conn, seeded, keys)
    if state_dir is not None:
        for rel, data in files(stage4).items():
            path = state_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            seeded.files[rel] = hashlib.sha256(data).hexdigest()
        seeded.sources = dict(SOURCES)
    return seeded


def _write_back(conn: Any, seeded: Seeded, keys: dict[str, tuple[str, ...]]) -> None:
    """A trigger may have changed a row written earlier — from version 12 on,
    every entity or relationship written bumps its job's `review_revision` —
    so the spec's values are written back, the last tables first."""
    for table in reversed(list(seeded.rows)):
        key = keys.get(table)
        if not key:
            continue
        where = " AND ".join(f"{quote(k)} = ?" for k in key)
        for row in seeded.rows[table]:
            cols = [c for c in row if c not in key]
            if not cols:
                continue
            ident = tuple(row[k] for k in key)
            stored = conn.execute(f"SELECT {', '.join(map(quote, cols))} FROM {quote(table)} WHERE {where}",
                                  ident).fetchone()
            changed = [c for c in cols if stored[c] != row[c]]
            if changed:
                conn.execute(f"UPDATE {quote(table)} SET {', '.join(quote(c) + ' = ?' for c in changed)} "
                             f"WHERE {where}", (*(row[c] for c in changed), *ident))


def coverage_errors(conn: Any, seeded: Seeded) -> list[str]:
    """Every table of the connection's schema holds seeded rows, and every
    column of it a non-NULL value in at least one of them (a default counts),
    or NOT_SEEDED says why not: "table", "table.column"."""
    errors: list[str] = []
    for table, columns in sorted(schema_columns(conn).items()):
        if is_runner_table(table) or table in NOT_SEEDED:
            continue
        if not seeded.rows.get(table):
            errors.append(f"{table}: the seed writes no row into it and NOT_SEEDED gives no reason "
                          "(scripts/migration_seed.py)")
            continue
        counts = conn.execute("SELECT " + ", ".join(f"count({quote(c)}) AS {quote(c)}" for c in columns)
                              + f" FROM {quote(table)}").fetchone()
        errors += [f"{table}.{c}: NULL in every seeded row and NOT_SEEDED gives no reason "
                   "(scripts/migration_seed.py)"
                   for c in columns if not counts[c] and f"{table}.{c}" not in NOT_SEEDED]
    return errors
