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


# ── Backup ───────────────────────────────────────────────────────────────────

def test_backup_db_produces_consistent_single_file(temp_db, tmp_path, monkeypatch):
    """backup_db uses the SQLite online backup API: the result must be a single,
    self-contained .db file that already contains committed rows — no -wal/-shm
    sidecars required to read it back."""
    import sqlite3

    backup_dir = tmp_path / "backups"
    monkeypatch.setattr(temp_db, "BACKUP_DIR", backup_dir)

    _insert_job(temp_db, job_id="job-backup")
    temp_db.backup_db()

    backups = list(backup_dir.glob("cti_stix_*.db"))
    assert len(backups) == 1, "expected exactly one backup file"
    # No sidecar files should be needed for a consistent read.
    assert not list(backup_dir.glob("*.db-wal"))
    assert not list(backup_dir.glob("*.db-shm"))

    # Open the backup standalone and confirm the committed row is present.
    conn = sqlite3.connect(str(backups[0]))
    try:
        row = conn.execute("SELECT id FROM jobs WHERE id=?", ("job-backup",)).fetchone()
    finally:
        conn.close()
    assert row is not None, "backup did not capture the committed job row"


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
