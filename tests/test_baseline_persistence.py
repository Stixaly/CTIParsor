"""api/worker.py and api/baseline_store.py — what a run against an analyst's
baseline stores (ADR-0090, Stage 3r): the status of each row, the rows the
baseline adds, auto-accept leaving them alone, and `load_index`.  The
reconciliations are built by hand: what `reconcile` decides is tested in
tests/test_baseline_stix.py."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

import api.worker as worker
from api.baseline_store import intake_json, load_index
from api.paths import uploads_dir
from models.schemas import EntityType, RawEntity
from pipeline import baseline_stix
from pipeline.baseline_stix import (
    BASELINE_IN_TEXT,
    BASELINE_ONLY,
    MATCHED,
    BaselineIndex,
    ImportedEntity,
    ImportedRelation,
    Reconciliation,
)
from pipeline.decisions import apply_auto_accept
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, RelationshipReview, TTPExtracted
from pipeline.stage3f_ttp_select import TtpReview

BASELINES = Path(__file__).parent / "fixtures" / "baselines"


@pytest.fixture()
def db(temp_db):
    uploads_dir().mkdir(parents=True)        # under tmp_path (conftest)
    return temp_db


def _job(db, job_id: str = "j1", *, pipeline_mode: str = "full") -> str:
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute("INSERT INTO jobs (id, original_filename, status, pipeline_mode, created_at, updated_at) "
                     "VALUES (?,?,?,?,?,?)", (job_id, "APT report.txt", "processing", pipeline_mode, ts, ts))
        conn.commit()
    return job_id


def _store_baseline(db, job_id: str, *, validated: int = 0) -> BaselineIndex:
    """A job_baselines row from the OpenCTI fixture, written as the HTTP request writes it."""
    raw = (BASELINES / "opencti_report.json").read_bytes()
    index, intake, _ = baseline_stix.intake(raw, validate=False)
    ts = db.now_iso()
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO job_baselines (job_id, sha256, size_bytes, report_id, bundle_json, index_json, "
            "intake_json, validated, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (job_id, intake.sha256, len(raw), intake.scope_report_id, raw.decode("utf-8"), index.to_json(),
             intake_json(intake), validated, ts, ts))
        conn.commit()
    return index


def _entities(db, job_id: str = "j1") -> dict[tuple[str, str], dict]:
    """The stored entities, by (entity_type, value)."""
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM entities WHERE job_id=?", (job_id,)).fetchall()
    return {(r["entity_type"], r["value"]): dict(r) for r in rows}


def _relationships(db, job_id: str = "j1") -> dict[tuple[str, str, str], dict]:
    """The stored relationships, by (source_value, relationship_type, target_value)."""
    with db.get_conn() as conn:
        rows = conn.execute("SELECT * FROM relationships WHERE job_id=?", (job_id,)).fetchall()
    return {(r["source_value"], r["relationship_type"], r["target_value"]): dict(r) for r in rows}


def _reconciliation(*, entities=(), relations=(), imported_entities=(), imported_relations=()) -> Reconciliation:
    """A Reconciliation by hand: `entities` are (entity_type, value, status, baseline_stix_id),
    `relations` are (source_value, relationship_type, target_value, status, baseline_stix_id)."""
    return Reconciliation(
        entity_status={baseline_stix._row_key(t, v): (s, b) for t, v, s, b in entities},
        relation_status={baseline_stix._rel_key(s, t, g): (st, b) for s, t, g, st, b in relations},
        imported_entities=list(imported_entities),
        imported_relations=list(imported_relations),
    )


# ── _save_entities without a baseline (full mode) ────────────────────────────

def test_a_full_run_stores_the_stage_3r_columns_empty(db):
    _job(db)
    raw = [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)]
    llm = LLMEnrichmentResult(
        malware_families=["Emotet"],
        ttps=[TTPExtracted(technique_name="Credential Dumping", mitre_id="T1003", evidence_label="observed")],
        ttp_review=[TtpReview(attack_id="T1078", name="Valid Accounts", reason="the call failed")],
        relationships=[RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="Emotet")],
        rel_review=[RelationshipReview(source_value="APT29", relationship_type="targets", target_value="Acme",
                                       reason="quote not in the text")],
    )

    worker._save_entities("j1", raw, llm, report_text="")

    ents = _entities(db)
    for row in ents.values():
        assert row["enrichment_status"] is None and row["baseline_stix_id"] is None
        assert row["decision_origin"] is None and row["decided_at"] is None
    assert ents[("malware", "Emotet")]["accepted"] is None
    assert ents[("ttp", "Valid Accounts")]["held_reason"] == "the call failed"
    rels = _relationships(db)
    for row in rels.values():
        assert row["enrichment_status"] is None and row["baseline_stix_id"] is None
    uses = rels[("APT29", "uses", "Emotet")]
    assert uses["accepted"] == 1 and uses["decision_origin"] == "default"
    targets = rels[("APT29", "targets", "Acme")]
    assert targets["accepted"] is None and targets["held_reason"] == "quote not in the text"


# ── _save_entities against a baseline (enrich mode) ──────────────────────────

def test_rows_the_baseline_holds_are_pre_accepted_and_the_others_are_not(db):
    _job(db, pipeline_mode="enrich")
    raw = [
        RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
        RawEntity(value="203.0.113.9", entity_type=EntityType.IPV4),
    ]
    llm = LLMEnrichmentResult(
        malware_families=["Emotet"],
        threat_actors=["APT29"],
        ttps=[TTPExtracted(technique_name="Credential Dumping", mitre_id="T1003", evidence_label="observed")],
        ttp_review=[TtpReview(attack_id="T1078", name="Valid Accounts", reason="the call failed")],
    )
    reconciliation = _reconciliation(entities=[
        ("ipv4", "185.220.101.45", MATCHED, "ipv4-addr--1"),
        ("malware", "Emotet", MATCHED, "malware--1"),
        ("ttp", "Credential Dumping", MATCHED, "attack-pattern--1"),
        ("ttp", "Valid Accounts", MATCHED, "attack-pattern--2"),
    ])

    worker._save_entities("j1", raw, llm, report_text="", reconciliation=reconciliation)

    ents = _entities(db)
    for key, bid in [
        (("ipv4", "185.220.101.45"), "ipv4-addr--1"),
        (("malware", "Emotet"), "malware--1"),
        (("ttp", "Credential Dumping"), "attack-pattern--1"),
        (("ttp", "Valid Accounts"), "attack-pattern--2"),
    ]:
        row = ents[key]
        assert row["accepted"] == 1 and row["decision_origin"] == "baseline_stix"
        assert row["decided_at"] and row["enrichment_status"] == "matched" and row["baseline_stix_id"] == bid
    assert ents[("ttp", "Valid Accounts")]["held_reason"] == "the call failed"      # a held row keeps its reason
    for key in [("ipv4", "203.0.113.9"), ("threat_actor", "APT29")]:
        row = ents[key]
        assert row["enrichment_status"] == "new" and row["baseline_stix_id"] is None
        assert row["accepted"] is None and row["decision_origin"] is None and row["decided_at"] is None


def test_the_baseline_entities_no_extraction_found_are_stored_pre_accepted(db):
    _job(db, pipeline_mode="enrich")
    reconciliation = _reconciliation(imported_entities=[
        ImportedEntity(value="Lazarus Group", entity_type="threat_actor", mitre_id=None,
                       status=BASELINE_IN_TEXT, baseline_stix_id="intrusion-set--1",
                       evidence_text="Lazarus", evidence_start=10, evidence_end=17),
        ImportedEntity(value="Cobalt Strike", entity_type="tool", mitre_id=None,
                       status=BASELINE_ONLY, baseline_stix_id="tool--1"),
    ])

    worker._save_entities("j1", [], LLMEnrichmentResult(), report_text="", reconciliation=reconciliation)

    ents = _entities(db)
    assert set(ents) == {("threat_actor", "Lazarus Group"), ("tool", "Cobalt Strike")}
    lazarus = ents[("threat_actor", "Lazarus Group")]
    assert lazarus["source"] == "baseline_stix" and lazarus["accepted"] == 1
    assert lazarus["decision_origin"] == "baseline_stix" and lazarus["decided_at"]
    assert lazarus["enrichment_status"] == "baseline_in_text" and lazarus["baseline_stix_id"] == "intrusion-set--1"
    assert (lazarus["evidence_text"], lazarus["evidence_label"], lazarus["evidence_start"],
            lazarus["evidence_end"]) == ("Lazarus", None, 10, 17)
    assert lazarus["confidence"] == 1.0 and lazarus["context"] == "" and lazarus["held_reason"] is None
    cobalt = ents[("tool", "Cobalt Strike")]
    assert cobalt["source"] == "baseline_stix" and cobalt["accepted"] == 1
    assert cobalt["enrichment_status"] == "baseline_only" and cobalt["baseline_stix_id"] == "tool--1"
    assert cobalt["evidence_text"] is None and cobalt["evidence_start"] is None and cobalt["evidence_end"] is None


def test_relationships_carry_their_baseline_status_and_origin(db):
    _job(db, pipeline_mode="enrich")
    llm = LLMEnrichmentResult(
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="Emotet",
                                  evidence_text="APT29 used Emotet."),
            RelationshipExtracted(source_value="APT29", relationship_type="targets", target_value="Acme",
                                  evidence_text="APT29 targeted Acme."),
        ],
        rel_review=[RelationshipReview(source_value="APT29", relationship_type="uses",
                                       target_value="Cobalt Strike", reason="quote not in the text")],
    )
    reconciliation = _reconciliation(
        relations=[
            ("APT29", "uses", "Emotet", MATCHED, "relationship--1"),
            ("APT29", "uses", "Cobalt Strike", MATCHED, "relationship--2"),
        ],
        imported_relations=[ImportedRelation(source_value="APT29", relationship_type="uses",
                                             target_value="Mimikatz", status=BASELINE_ONLY,
                                             baseline_stix_id="relationship--3")],
    )

    worker._save_entities("j1", [], llm, report_text="", reconciliation=reconciliation)

    rels = _relationships(db)
    assert set(rels) == {
        ("APT29", "uses", "Emotet"), ("APT29", "targets", "Acme"),
        ("APT29", "uses", "Cobalt Strike"), ("APT29", "uses", "Mimikatz"),
    }
    matched = rels[("APT29", "uses", "Emotet")]
    assert matched["accepted"] == 1 and matched["decision_origin"] == "baseline_stix"
    assert matched["enrichment_status"] == "matched" and matched["baseline_stix_id"] == "relationship--1"
    new = rels[("APT29", "targets", "Acme")]
    assert new["accepted"] == 1 and new["decision_origin"] == "default"
    assert new["enrichment_status"] == "new" and new["baseline_stix_id"] is None
    held = rels[("APT29", "uses", "Cobalt Strike")]
    assert held["accepted"] == 1 and held["decision_origin"] == "baseline_stix"
    assert held["held_reason"] == "quote not in the text" and held["enrichment_status"] == "matched"
    imported = rels[("APT29", "uses", "Mimikatz")]
    assert imported["accepted"] == 1 and imported["decision_origin"] == "baseline_stix"
    assert imported["enrichment_status"] == "baseline_only" and imported["baseline_stix_id"] == "relationship--3"
    # A baseline decision is dated like an entity's; the pipeline's default is not.
    assert matched["decided_at"] and imported["decided_at"] and held["decided_at"]
    assert new["decided_at"] is None
    assert imported["evidence_text"] is None and imported["held_reason"] is None


def test_auto_accept_never_touches_the_baseline_rows(db):
    _job(db, pipeline_mode="enrich")
    raw = [
        RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
        RawEntity(value="203.0.113.9", entity_type=EntityType.IPV4),
    ]
    reconciliation = _reconciliation(
        entities=[("ipv4", "185.220.101.45", MATCHED, "ipv4-addr--1")],
        imported_entities=[ImportedEntity(value="Lazarus Group", entity_type="threat_actor", mitre_id=None,
                                          status=BASELINE_ONLY, baseline_stix_id="intrusion-set--1")],
    )
    worker._save_entities("j1", raw, LLMEnrichmentResult(), report_text="", reconciliation=reconciliation)
    before = _entities(db)

    with db.get_conn() as conn:
        counts = apply_auto_accept(conn, "j1", db.now_iso(), rate=0.0)

    after = _entities(db)
    assert counts["accepted"] == 1                                  # the NEW address, and only it
    assert after[("ipv4", "203.0.113.9")]["accepted"] == 1
    assert after[("ipv4", "185.220.101.45")] == before[("ipv4", "185.220.101.45")]
    assert after[("threat_actor", "Lazarus Group")] == before[("threat_actor", "Lazarus Group")]


# ── load_index ───────────────────────────────────────────────────────────────

def test_a_full_job_has_no_baseline_index(db):
    _job(db)
    assert load_index("j1") is None


def test_an_enrich_job_gets_the_index_of_its_baseline(db):
    _job(db, pipeline_mode="enrich")
    index = _store_baseline(db, "j1", validated=1)

    loaded = load_index("j1")

    assert isinstance(loaded, BaselineIndex)
    assert loaded.to_json() == index.to_json()


def test_an_enrich_job_without_its_baseline_row_has_no_index(db):
    _job(db, pipeline_mode="enrich")
    assert load_index("j1") is None


# ── The hooks and the run ────────────────────────────────────────────────────

def test_the_hooks_hand_the_reconciliation_to_the_save(db, monkeypatch):
    _job(db, pipeline_mode="enrich")
    saved: list[dict] = []
    monkeypatch.setattr(worker, "_save_entities", lambda *args, **kwargs: saved.append(kwargs))
    monkeypatch.setattr(worker, "_apply_auto_accept", lambda job_id: None)
    hooks = worker._WorkerHooks("j1", None, time.monotonic())
    reconciliation = _reconciliation(entities=[("malware", "Emotet", MATCHED, "malware--1")])

    hooks.baseline_reconciled(reconciliation)
    hooks.extraction_ready([], LLMEnrichmentResult(), "APT29 used Emotet.")

    assert saved[0]["reconciliation"] is reconciliation
    assert saved[0]["report_text"] == "APT29 used Emotet."


def test_a_run_without_a_baseline_saves_with_no_reconciliation(db, monkeypatch):
    _job(db)
    saved: list[dict] = []
    monkeypatch.setattr(worker, "_save_entities", lambda *args, **kwargs: saved.append(kwargs))
    monkeypatch.setattr(worker, "_apply_auto_accept", lambda job_id: None)
    hooks = worker._WorkerHooks("j1", None, time.monotonic())

    hooks.extraction_ready([], LLMEnrichmentResult(), "text")

    assert saved[0]["reconciliation"] is None


def test_the_run_of_an_enrich_job_is_given_its_baseline_index(db, monkeypatch):
    _job(db, pipeline_mode="enrich")
    index = _store_baseline(db, "j1", validated=1)      # validated: the schemas are not run again
    uploads_dir().joinpath("j1.txt").write_bytes(b"APT29 used Emotet.")
    documents: list = []

    class _NoBundle:
        bundle = None
        ledger = None
        validation = None
        validation_errors: list[str] = []

        def stage_report(self):
            return []

    def run_document(document, options, hooks):
        documents.append(document)
        return _NoBundle()

    monkeypatch.setattr(worker, "run_document", run_document)

    worker._run_pipeline("j1", str(uploads_dir() / "j1.txt"), "report.txt")

    assert documents[0].baseline.to_json() == index.to_json()
