"""What Stage 3d / 3f could not decide waits for an analyst (ADR-0082).

A held row is stored pending with `held_reason`.  It is not in the bundle, not
in the report's technique set, never auto-accepted and never accepted by a
click over a group; one analyst's accept ships it.  Against an isolated
PostgreSQL schema (`temp_db`).
"""
import json

from pipeline import decisions
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, RelationshipReview
from pipeline.stage3f_ttp_select import TtpReview

_TEXT = ("APT29 used WellMess. APT29 also ran ZeroLoader. "
         "The operators scheduled tasks for persistence on every host.")


def _job(db, job_id="job-held"):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", _TEXT, db.now_iso(), db.now_iso()),
        )
        conn.commit()
    return job_id


def _result() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        tools=["ZeroLoader"],
        relationships=[RelationshipExtracted(
            source_value="APT29", relationship_type="uses", target_value="WellMess",
            confidence=0.9, evidence_text="APT29 used WellMess.")],
        rel_review=[RelationshipReview(
            source_value="APT29", relationship_type="uses", target_value="ZeroLoader",
            confidence=0.8, evidence_text="APT29 also ran ZeroLoader.",
            reason="verification call failed")],
        ttp_review=[
            TtpReview(attack_id="T1053.005", name="Scheduled Task",
                      reason="quote missing, too short or not found verbatim",
                      evidence_quote="scheduled tasks for persistence on every host"),
        ],
    )


def _saved(db):
    from api import worker
    job = _job(db)
    worker._save_entities(job, [], _result(), _TEXT)
    return job


def _held_rel(db, job):
    return db.get_conn().execute(
        "SELECT * FROM relationships WHERE job_id=? AND target_value='ZeroLoader'", (job,)).fetchone()


def _held_ttp(db, job):
    return db.get_conn().execute(
        "SELECT * FROM entities WHERE job_id=? AND mitre_id='T1053.005'", (job,)).fetchone()


def _shipped_rels(db, job) -> set[tuple[str, str, str]]:
    from api import worker
    objs = json.loads(worker.re_run_final_stages(job, skip_rescan=True))["objects"]
    names = {o["id"]: o.get("name") or o.get("value") for o in objs}
    return {(names.get(o["source_ref"]), o["relationship_type"], names.get(o["target_ref"]))
            for o in objs if o["type"] == "relationship"}


# ── Stored pending, with the reason ──────────────────────────────────────────

def test_held_claims_and_techniques_are_stored_pending_with_the_reason(temp_db):
    job = _saved(temp_db)
    rel = _held_rel(temp_db, job)
    assert (rel["accepted"], rel["decision_origin"], rel["held_reason"]) == (
        None, None, "verification call failed")
    assert rel["evidence_text"] == "APT29 also ran ZeroLoader."
    shipped = temp_db.get_conn().execute(
        "SELECT * FROM relationships WHERE job_id=? AND target_value='WellMess'", (job,)).fetchone()
    assert (shipped["accepted"], shipped["decision_origin"], shipped["held_reason"]) == (1, "default", None)

    ttp = _held_ttp(temp_db, job)
    assert (ttp["entity_type"], ttp["accepted"], ttp["evidence_label"]) == ("ttp", None, "gap")
    assert ttp["held_reason"] == "quote missing, too short or not found verbatim"
    assert _TEXT[ttp["evidence_start"]:ttp["evidence_end"]] == "scheduled tasks for persistence on every host"


def test_a_held_technique_already_stored_from_another_source_is_not_listed_twice(temp_db):
    from api import worker
    from models.schemas import EntityType, RawEntity
    job = _job(temp_db)
    raw = [RawEntity(value="T1053.005", entity_type=EntityType.TTP, mitre_id="T1053.005", source="ioc")]
    worker._save_entities(job, raw, _result(), _TEXT)
    rows = temp_db.get_conn().execute(
        "SELECT held_reason FROM entities WHERE job_id=? AND mitre_id='T1053.005'", (job,)).fetchall()
    assert [r["held_reason"] for r in rows] == [None]


def test_the_api_says_why_a_row_was_held(temp_db, temp_db_client):
    job = _saved(temp_db)
    rels = temp_db_client.get(f"/api/jobs/{job}/relationships").json()
    assert {r["target_value"]: r["held_reason"] for r in rels} == {
        "WellMess": None, "ZeroLoader": "verification call failed"}
    ents = temp_db_client.get(f"/api/jobs/{job}/entities").json()
    assert [e["held_reason"] for e in ents if e["mitre_id"] == "T1053.005"] == [
        "quote missing, too short or not found verbatim"]


# ── Not shipped until an analyst accepts ─────────────────────────────────────

def test_a_held_claim_ships_only_once_an_analyst_accepts_it(temp_db, temp_db_client):
    job = _saved(temp_db)
    assert _shipped_rels(temp_db, job) >= {("APT29", "uses", "WellMess")}
    assert ("APT29", "uses", "ZeroLoader") not in _shipped_rels(temp_db, job)

    rid = _held_rel(temp_db, job)["id"]
    temp_db_client.patch(f"/api/jobs/{job}/relationships/{rid}", json={"accepted": True})
    assert ("APT29", "uses", "ZeroLoader") in _shipped_rels(temp_db, job)


def test_a_held_technique_is_outside_the_report_until_accepted(temp_db, temp_db_client):
    from pipeline.detection.coverage import job_technique_ids
    job = _saved(temp_db)
    assert "T1053.005" not in job_technique_ids(temp_db.get_conn(), job)

    eid = _held_ttp(temp_db, job)["id"]
    temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json={"accepted": True})
    assert "T1053.005" in job_technique_ids(temp_db.get_conn(), job)


def test_auto_accept_never_takes_a_held_row(temp_db):
    job = _saved(temp_db)      # the held technique is stored at 0.9, the auto-accept level
    decisions.apply_auto_accept(temp_db.get_conn(), job, temp_db.now_iso(), rate=0.0)
    assert _held_ttp(temp_db, job)["accepted"] is None
    names = temp_db.get_conn().execute(
        "SELECT accepted FROM entities WHERE job_id=? AND value='WellMess'", (job,)).fetchone()
    assert names["accepted"] == 1


def test_a_click_over_a_group_accepts_no_held_row_but_may_reject_it(temp_db, temp_db_client):
    job = _saved(temp_db)
    held_rel = _held_rel(temp_db, job)["id"]

    temp_db_client.post(f"/api/jobs/{job}/entities/accept-pending")
    temp_db_client.post(f"/api/jobs/{job}/entities/bulk",
                        json={"entity_type": "ttp", "action": "accept", "scope": "all"})
    temp_db_client.post(f"/api/jobs/{job}/relationships/bulk", json={"ids": [held_rel], "action": "accept"})
    assert _held_ttp(temp_db, job)["accepted"] is None
    assert _held_rel(temp_db, job)["accepted"] is None

    # A single write that says it is part of a group is refused too.
    bulk_one = {"accepted": True, "decision_origin": "human_bulk"}
    eid = _held_ttp(temp_db, job)["id"]
    assert temp_db_client.patch(f"/api/jobs/{job}/entities/{eid}", json=bulk_one).status_code == 409
    assert temp_db_client.patch(f"/api/jobs/{job}/relationships/{held_rel}", json=bulk_one).status_code == 409
    assert _held_ttp(temp_db, job)["accepted"] is None

    temp_db_client.post(f"/api/jobs/{job}/relationships/bulk", json={"ids": [held_rel], "action": "reject"})
    assert _held_rel(temp_db, job)["accepted"] == 0
