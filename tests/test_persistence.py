"""Worker / DB persistence tests (P1-b).

Covers the write→read round-trip for relationship evidence labels and migration
idempotency — the layer that previously had zero coverage. All tests run against
an isolated temp database (see the `temp_db` fixture in conftest).
"""
import json

from models.schemas import EvidenceLabel
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted


def _insert_job(db, job_id="job-test", report_text="APT29 used WellMess."):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", report_text, db.now_iso(), db.now_iso()),
        )
        conn.commit()
    return job_id


def _llm_result_with_label(label: EvidenceLabel) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(
                source_value="APT29",
                relationship_type="uses",
                target_value="WellMess",
                confidence=0.9,
                evidence_text="APT29 used WellMess.",
                evidence_label=label,
            )
        ],
    )


# ── Migration ───────────────────────────────────────────────────────────────

def test_migration_is_idempotent_and_adds_evidence_label(temp_db):
    # temp_db already ran init_db once; running again must not raise.
    temp_db.init_db()
    cols = [r[1] for r in temp_db.get_conn().execute("PRAGMA table_info(relationships)").fetchall()]
    assert "evidence_label" in cols
    assert "evidence_text" in cols


# ── Write path: _save_entities ───────────────────────────────────────────────

def test_save_entities_persists_evidence_label(temp_db):
    from api import worker

    job_id = _insert_job(temp_db)
    worker._save_entities(job_id, [], _llm_result_with_label(EvidenceLabel.OBSERVED))

    row = temp_db.get_conn().execute(
        "SELECT evidence_label, evidence_text FROM relationships WHERE job_id=?", (job_id,)
    ).fetchone()
    assert row is not None, "relationship was not written"
    assert row["evidence_label"] == "observed"
    assert row["evidence_text"] == "APT29 used WellMess."


# ── Read path: re_run_final_stages reconstructs and carries the label ─────────

def test_finalize_carries_evidence_label_into_bundle(temp_db):
    from api import worker

    job_id = _insert_job(temp_db)
    worker._save_entities(job_id, [], _llm_result_with_label(EvidenceLabel.OBSERVED))

    bundle_json = worker.re_run_final_stages(job_id, skip_rescan=True)
    assert bundle_json, "finalize returned no bundle"
    bundle = json.loads(bundle_json)

    rels = [o for o in bundle["objects"] if o.get("type") == "relationship"]
    assert rels, "no relationship object in the finalized bundle"
    assert any(r.get("x_evidence_label") == "observed" for r in rels), \
        "evidence label did not survive DB → finalize → STIX"


def test_finalize_defaults_missing_label_to_reported(temp_db):
    # Simulate a legacy row written before the column existed (NULL label).
    from api import worker

    job_id = _insert_job(temp_db, job_id="job-legacy")
    worker._save_entities(job_id, [], _llm_result_with_label(EvidenceLabel.REPORTED))
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE relationships SET evidence_label=NULL WHERE job_id=?", (job_id,))
        conn.commit()

    bundle_json = worker.re_run_final_stages(job_id, skip_rescan=True)
    bundle = json.loads(bundle_json)
    rels = [o for o in bundle["objects"] if o.get("type") == "relationship"]
    assert rels and all(r.get("x_evidence_label") == "reported" for r in rels)
