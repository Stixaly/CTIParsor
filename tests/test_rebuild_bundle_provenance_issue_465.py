"""scripts/rebuild_bundle_provenance.py (issue #465): the bundle it rebuilds is the one
the worker's finalize builds from the same job.  A rejected entity stays out, and
the named objects of the accepted rows come in, as the product's do.

Runs on a disposable PostgreSQL schema (the temp_db fixture)."""
from __future__ import annotations

from pipeline.stage3_llm import LLMEnrichmentResult
from scripts import rebuild_bundle_provenance as rbp

POLICY = {"version": 1, "global": "enforce", "max_pinned_edges": 200, "rules": []}


def _insert_job(conn, job_id: str, llm: LLMEnrichmentResult) -> None:
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, report_text, llm_result_json, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (job_id, "report.txt", "completed", "Emotet, Lazarus and Qakbot were seen.",
         llm.model_dump_json(), "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )


def _insert_entity(conn, job_id: str, value: str, accepted: int | None, source: str) -> None:
    conn.execute(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (f"{job_id}-{value}", job_id, value, "malware", "", 0.9, accepted, source),
    )


def test_rebuilt_bundle_leaves_out_rejected_and_keeps_named_objects_issue_465(temp_db):
    db = temp_db
    job_id = "job-465"
    # The LLM listed Emotet and Qakbot; the analyst accepted Emotet and rejected Qakbot.
    # Lazarus is not in the LLM's JSON: it is a gazetteer row the analyst accepted.
    llm = LLMEnrichmentResult(malware_families=["Emotet", "Qakbot"])
    with db.get_conn() as conn:
        _insert_job(conn, job_id, llm)
        _insert_entity(conn, job_id, "Emotet", 1, "llm")
        _insert_entity(conn, job_id, "Qakbot", 0, "llm")
        _insert_entity(conn, job_id, "Lazarus", 1, "gazetteer")
        conn.commit()

    with db.get_conn() as conn:
        loaded = rbp._load_job(conn, job_id)
    assert loaded is not None
    raw_entities, llm_in, report_text, filename = loaded
    bundle = rbp._build_bundle(raw_entities, llm_in, filename, report_text, POLICY)

    # The bundle spells a canonical name its own way (Qakbot -> QakBot): compare folded.
    malware = {o.name.lower() for o in bundle.objects if getattr(o, "type", "") == "malware"}
    assert "qakbot" not in malware
    assert "emotet" in malware
    assert "lazarus" in malware
