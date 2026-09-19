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


def _llm_result_with_dates(start=None, stop=None) -> LLMEnrichmentResult:
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
                start_time=start,
                stop_time=stop,
            )
        ],
    )


# ── Backup ───────────────────────────────────────────────────────────────────

def test_backup_db_logs_pg_dump_guidance(temp_db, caplog):
    """Both stores are PostgreSQL now (ADR-0053): backup_db() no longer copies
    a local file, it points the operator at pg_dump instead — confirm it runs
    without error and says so, rather than silently doing nothing."""
    with caplog.at_level("INFO"):
        temp_db.backup_db()
    assert "pg_dump" in caplog.text


# ── Output bundle path is job-scoped (no cross-job collision) ─────────────────

def test_bundle_output_path_is_job_scoped():
    from api.worker import bundle_output_path

    p1 = bundle_output_path("job-aaa", "report")
    p2 = bundle_output_path("job-bbb", "report")
    assert p1 != p2
    assert "job-aaa" in p1.name
    assert "job-bbb" in p2.name


def test_finalize_same_filename_jobs_do_not_collide(temp_db):
    """Two uploads sharing a filename must export to distinct bundle files, and
    deleting one job must not remove the other's exported bundle."""
    from api import worker
    from api.routes.jobs import _delete_job_files

    _insert_job(temp_db, job_id="job-a")   # original_filename defaults to report.txt
    _insert_job(temp_db, job_id="job-b")
    worker._save_entities("job-a", [], _llm_result_with_label(EvidenceLabel.OBSERVED))
    worker._save_entities("job-b", [], _llm_result_with_label(EvidenceLabel.OBSERVED))
    worker.re_run_final_stages("job-a", skip_rescan=True)
    worker.re_run_final_stages("job-b", skip_rescan=True)

    pa = worker.bundle_output_path("job-a", "report")
    pb = worker.bundle_output_path("job-b", "report")
    try:
        assert pa.exists() and pb.exists()
        assert pa != pb

        # Deleting job-a's files must leave job-b's bundle intact.
        _delete_job_files("job-a", "report.txt")
        assert not pa.exists()
        assert pb.exists()
    finally:
        pa.unlink(missing_ok=True)
        pb.unlink(missing_ok=True)


# ── Migration ───────────────────────────────────────────────────────────────

def test_migration_is_idempotent_and_adds_evidence_label(temp_db):
    # temp_db already ran init_db once; running again must not raise (the
    # PostgreSQL DDL is IF NOT EXISTS end to end, ADR-0045/ADR-0053).
    temp_db.init_db()
    cols = [
        r[0] for r in temp_db.get_conn().execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'relationships'"
        ).fetchall()
    ]
    assert "evidence_label" in cols
    assert "evidence_text" in cols
    assert "start_time" in cols
    assert "stop_time" in cols


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


# ── start_time / stop_time (STIX 2.1 SRO Sec 5.1.2) round-trip ────────────────

def test_save_entities_persists_start_stop_time(temp_db):
    from datetime import datetime, timezone

    from api import worker

    job_id = _insert_job(temp_db, job_id="job-dates")
    start = datetime(2022, 11, 4, tzinfo=timezone.utc)
    stop = datetime(2023, 3, 1, tzinfo=timezone.utc)
    worker._save_entities(job_id, [], _llm_result_with_dates(start, stop))

    row = temp_db.get_conn().execute(
        "SELECT start_time, stop_time FROM relationships WHERE job_id=?", (job_id,)
    ).fetchone()
    assert row is not None, "relationship was not written"
    assert row["start_time"].startswith("2022-11-04")
    assert row["stop_time"].startswith("2023-03-01")


def test_finalize_carries_start_stop_time_into_bundle(temp_db):
    """The DB round-trip through the analyst-review cycle must not silently
    drop the relationship's temporal bounds — this is exactly the gap that
    previously existed for evidence_text/evidence_label before their columns
    were added."""
    from datetime import datetime, timezone

    from api import worker

    job_id = _insert_job(temp_db, job_id="job-dates-finalize")
    start = datetime(2022, 11, 4, tzinfo=timezone.utc)
    stop = datetime(2023, 3, 1, tzinfo=timezone.utc)
    worker._save_entities(job_id, [], _llm_result_with_dates(start, stop))

    bundle_json = worker.re_run_final_stages(job_id, skip_rescan=True)
    bundle = json.loads(bundle_json)
    rels = [o for o in bundle["objects"] if o.get("type") == "relationship"]
    assert rels, "no relationship object in the finalized bundle"
    assert any(
        r.get("start_time", "").startswith("2022-11-04")
        and r.get("stop_time", "").startswith("2023-03-01")
        for r in rels
    ), "start_time/stop_time did not survive DB -> finalize -> STIX"


def test_finalize_survives_malformed_stored_date(temp_db):
    """A row with a corrupted start_time string (hand-edited DB, bad migration,
    etc.) must not crash the finalize rebuild — it degrades to no date, same as
    the rest of this pipeline's defensive parsing."""
    from api import worker

    job_id = _insert_job(temp_db, job_id="job-dates-bad")
    worker._save_entities(job_id, [], _llm_result_with_dates())
    with temp_db.get_conn() as conn:
        conn.execute("UPDATE relationships SET start_time='not-a-date' WHERE job_id=?", (job_id,))
        conn.commit()

    bundle_json = worker.re_run_final_stages(job_id, skip_rescan=True)
    assert bundle_json, "finalize must not raise on a malformed stored date"
