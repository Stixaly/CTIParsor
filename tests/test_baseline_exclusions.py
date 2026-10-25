"""Rows a STIX baseline imported never feed learning or evaluation (ADR-0090).

The baseline's objects come from an analyst's bundle, not from the report text:
promotion would learn them as analyst decisions, and grounding would score the
ones an enrich job shipped as hallucinated edges.
"""
from __future__ import annotations

import json
from uuid import uuid4

from pipeline import baseline_stix
from pipeline import promotion as pm
from tests.eval_pipeline import load_grounding_from_bundle


def test_baseline_source_constant_matches_the_baseline_module():
    assert pm._BASELINE_SOURCE == baseline_stix.SOURCE


def test_load_decisions_never_reads_a_baseline_row(temp_db):
    conn = temp_db.get_conn()
    now = temp_db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("job-baseline", "report.pdf", "for_review", now, now),
    )
    rows = [
        # value, entity_type, source, accepted, decision_origin
        ("Lazarus", "threat_actor", baseline_stix.SOURCE, 0, "human"),
        ("APT28", "threat_actor", baseline_stix.SOURCE, 1, "human"),
        ("Emotet", "malware", "llm", 0, "human"),
        ("Qakbot", "malware", "llm", 1, "human"),
        ("Ryuk", "malware", None, 1, "human"),
        ("Mimikatz", "tool", "manual", None, None),
    ]
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source, "
        "decision_origin) VALUES (?,?,?,?,?,?,?,?,?)",
        [(str(uuid4()), "job-baseline", v, t, "", 0.9, a, s, o) for v, t, s, a, o in rows],
    )
    conn.commit()

    # Both human-decided baseline rows (accepted 0 and 1) are left out; a NULL
    # source is not a baseline row and is still read.
    got = {(value, source) for value, _, source, _, _ in pm.load_decisions(conn)}
    assert got == {("Emotet", "llm"), ("Qakbot", "llm"), ("Ryuk", None), ("Mimikatz", "manual")}


def test_grounding_reads_full_jobs_only(temp_db):
    conn = temp_db.get_conn()
    now = temp_db.now_iso()
    bundle = json.dumps({"type": "bundle", "objects": [
        {"id": "malware--1", "type": "malware", "name": "Malware A"},
        {"id": "indicator--1", "type": "indicator", "name": "Ind A"},
        {"id": "rel--1", "type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1",
         "x_evidence_label": "observed"},
    ]})
    for job_id, mode in (("11111111-full", "full"), ("22222222-enrich", "enrich")):
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, bundle_json, pipeline_mode, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (job_id, f"{job_id}.txt", "for_review", "some report text", bundle, mode, now, now),
        )
    conn.commit()

    # The enrich job's observed edge would make the census 2 if it were read.
    samples, census = load_grounding_from_bundle("all")
    assert [s.description for s in samples] == ["job 11111111"]
    assert census == {"observed": 1}

    # Asked for by id, the enrich job still yields nothing.
    assert load_grounding_from_bundle("22222222-enrich") == ([], {})
