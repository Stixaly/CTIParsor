"""The analyst's deny rows reach the CLI's bundle as they reach the worker's (issue #382, ADR-0052).

The NER stages drop a denied name at their output, and the worker drops the
LLM's name lists when it stores them.  Nothing filtered the LLM's lists on the
CLI path, nor its targeted countries and sectors on either path.  The helper
`pipeline.overrides.without_denied` is now the one filter both paths call.
Against an isolated PostgreSQL schema (`temp_db`).
"""
from __future__ import annotations

from pipeline import overrides as ov
from pipeline import promotion as pm
from pipeline.orchestrator import Document, Hooks, RunOptions, _Run
from pipeline.stage3_llm import LLMEnrichmentResult

_TEXT = "APT29 used WellMess and Emotet against France."

# (value, entity_type) of every deny row the tests set.  Each one names a list
# the LLM fills: malware, threat actor, tool, campaign, location, identity.
_DENIED = [
    ("Emotet", "malware"),
    ("Microsoft", "threat_actor"),
    ("PsExec", "tool"),
    ("Operation Quiet", "campaign"),
    ("France", "location"),
    ("government", "identity"),
]


def _deny_all(db) -> None:
    conn = db.get_conn()
    for value, etype in _DENIED:
        pm.add_manual(conn, value, etype, "deny", db.now_iso())
    ov.reload()


def _llm() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29", "Microsoft"],
        malware_families=["WellMess", "Emotet"],
        tools=["PsExec"],
        campaign_name="Operation Quiet",
        targeted_countries=["France", "Brazil"],
        targeted_sectors=["government", "finance"],
    )


def _job(db, job_id: str = "job-382") -> str:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", _TEXT, db.now_iso(), db.now_iso()),
        )
        conn.commit()
    return job_id


# ── The helper ───────────────────────────────────────────────────────────────

def test_without_denied_drops_each_list_by_its_type_issue_382(temp_db):
    _deny_all(temp_db)
    llm = _llm()

    kept = ov.without_denied(llm)

    assert kept.malware_families == ["WellMess"]
    assert kept.threat_actors == ["APT29"]
    assert kept.tools == []
    assert kept.campaign_name is None
    assert kept.targeted_countries == ["Brazil"]
    assert kept.targeted_sectors == ["finance"]
    assert llm.malware_families == ["WellMess", "Emotet"]       # the argument is not changed


def test_a_deny_row_names_one_type_only_issue_382(temp_db):
    _deny_all(temp_db)
    # "Emotet" is denied as malware, not as a tool; "France" as a location, not an identity.
    kept = ov.without_denied(LLMEnrichmentResult(tools=["Emotet"], targeted_sectors=["France"]))
    assert kept.tools == ["Emotet"]
    assert kept.targeted_sectors == ["France"]


def test_without_denied_hands_back_the_same_object_when_nothing_is_denied_issue_382(temp_db):
    llm = _llm()
    assert ov.without_denied(llm) is llm


# ── The CLI path: Stage 4 of a run ───────────────────────────────────────────

def test_the_cli_bundle_drops_the_denied_llm_names_and_targets_issue_382(temp_db):
    _deny_all(temp_db)
    run = _Run(Document(text=_TEXT), RunOptions(disabled=frozenset({"2f", "4b", "4c"})), Hooks())
    run.r.text = _TEXT
    run.r.llm_result = _llm()

    run.map_to_stix()

    shipped = {(getattr(o, "type", None), getattr(o, "name", None)) for o in run.r.bundle.objects}
    assert ("malware", "WellMess") in shipped                    # the control: a name not denied ships
    assert ("location", "Brazil") in shipped
    assert ("identity", "finance") in shipped
    for denied in [("malware", "Emotet"), ("threat-actor", "Microsoft"), ("tool", "PsExec"),
                   ("campaign", "Operation Quiet"), ("location", "France"), ("identity", "government")]:
        assert denied not in shipped, denied


# ── The worker: the LLM's name rows on the store ─────────────────────────────

def test_the_worker_stores_no_row_for_a_denied_llm_name_issue_382(temp_db):
    from api import worker

    _deny_all(temp_db)
    job = _job(temp_db)
    worker._save_entities(job, [], _llm(), _TEXT)

    rows = {(r["value"], r["entity_type"]) for r in temp_db.get_conn().execute(
        "SELECT value, entity_type FROM entities WHERE job_id=? AND source='llm'", (job,)).fetchall()}
    assert ("WellMess", "malware") in rows                       # the control
    assert ("APT29", "threat_actor") in rows
    assert ("Emotet", "malware") not in rows
    assert ("Microsoft", "threat_actor") not in rows
    assert ("Operation Quiet", "campaign") not in rows
