"""An ATT&CK id Stage 2 reads from the report, that the bundled release does not
hold, is stored held for review with its reason (#980, ADR-0082).

A known id ships, a revoked one stays as it was written (it is replaced at
Stage 3c, not here), and a malware name is never touched.  Against an isolated
PostgreSQL schema (`temp_db`).
"""
from pipeline import decisions
from pipeline.stage3_llm import LLMEnrichmentResult

_TEXT = "The actor used T9999, T1059.001, T1562 and WellMess."


def _job(db, job_id="job-980"):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", _TEXT, db.now_iso(), db.now_iso()),
        )
        conn.commit()
    return job_id


def _saved(db):
    from api import worker
    from models.schemas import EntityType, RawEntity

    job = _job(db)
    raw = [
        RawEntity(value="T9999", entity_type=EntityType.TTP, mitre_id="T9999", source="ioc"),
        RawEntity(value="T1059.001", entity_type=EntityType.TTP, mitre_id="T1059.001", source="ioc"),
        RawEntity(value="T1562", entity_type=EntityType.TTP, mitre_id="T1562", source="ioc"),
        RawEntity(value="WellMess", entity_type=EntityType.MALWARE, source="ioc"),
    ]
    worker._save_entities(job, raw, LLMEnrichmentResult(), _TEXT)
    return job


def _row(db, job, value):
    return db.get_conn().execute(
        "SELECT * FROM entities WHERE job_id=? AND value=?", (job, value)).fetchone()


def test_an_unknown_stage2_technique_is_held_with_the_reason(temp_db):
    job = _saved(temp_db)
    row = _row(temp_db, job, "T9999")
    assert row["accepted"] is None
    assert "absent from ATT&CK" in row["held_reason"]


def test_a_held_unknown_technique_is_outside_what_ships(temp_db):
    job = _saved(temp_db)
    shipped = {r["value"] for r in temp_db.get_conn().execute(
        f"SELECT value FROM entities WHERE job_id=? AND {decisions.SHIPS}", (job,))}
    assert "T9999" not in shipped
    assert {"T1059.001", "WellMess"} <= shipped


def test_a_known_technique_is_stored_without_a_reason(temp_db):
    job = _saved(temp_db)
    row = _row(temp_db, job, "T1059.001")
    assert (row["accepted"], row["held_reason"]) == (None, None)


def test_a_revoked_technique_is_stored_without_a_reason(temp_db):
    job = _saved(temp_db)
    row = _row(temp_db, job, "T1562")
    assert row["held_reason"] is None


def test_a_malware_name_is_not_touched(temp_db):
    job = _saved(temp_db)
    row = _row(temp_db, job, "WellMess")
    assert (row["entity_type"], row["held_reason"]) == ("malware", None)


def test_the_sentence_that_writes_an_id_is_stored_as_its_evidence(temp_db):
    """Stage 2's citation reaches the store, located in the report (#980)."""
    from api import worker
    from models.schemas import EntityType, RawEntity

    job = _job(temp_db, "job-980-evidence")
    quote = "The actor used T9999, T1059.001, T1562 and WellMess."
    raw = [
        RawEntity(value="T1059.001", entity_type=EntityType.TTP, mitre_id="T1059.001", source="ioc",
                  evidence_text=quote, evidence_start=0),
        RawEntity(value="T9999", entity_type=EntityType.TTP, mitre_id="T9999", source="ioc",
                  evidence_text=quote, evidence_start=0),
    ]
    worker._save_entities(job, raw, LLMEnrichmentResult(), _TEXT)
    known = _row(temp_db, job, "T1059.001")
    assert (known["evidence_text"], known["evidence_label"]) == (quote, "reported")
    assert _TEXT[known["evidence_start"]:known["evidence_end"]] == quote
    held = _row(temp_db, job, "T9999")
    assert held["evidence_text"] == quote and "absent from ATT&CK" in held["held_reason"]
