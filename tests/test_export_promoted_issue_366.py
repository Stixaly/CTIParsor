"""Issue #366: the rule-id export packages promoted rules outside the report's coverage.

A promotion from the Detections panel is a canonical rule the report's techniques
do not reach, so `rule_bodies_for_job` never returns it. The POST used to intersect
the ids with that set and drop the promoted rule silently (or 404 when it was the
only one). It now packages every requested canonical rule, and the manifest says
which ones were promoted by hand.
"""
import io
import json
import zipfile
from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline.detection.store import replace_corpus_rules


def _rule(corpus, key, techniques, *, raw=None):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license="proprietary",
        raw=raw if raw is not None else f"title: rule {key}\nlogsource: {corpus}\n",
    )


def _job_with_technique(temp_db, job_id, mitre_id):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, mitre_id, "technique", mitre_id, 1, "llm"),
    )
    conn.commit()


def test_promoted_rule_is_packaged_next_to_a_covered_one_issue_366(temp_db, temp_db_client):
    """The regression: P is canonical but outside the report's techniques. Before the
    fix the ZIP held only A; now it holds A and P, and P is marked promoted."""
    temp_db.get_conn()
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "sig", [
        _rule("sig", "a", ["T1059"], raw="body-A"),
        _rule("sig", "p", ["T1486"], raw="body-P"),
    ])
    _job_with_technique(temp_db, "j366a", "T1059")

    resp = temp_db_client.post(
        "/api/jobs/j366a/detections/export",
        json={"rule_ids": ["sig:a", "sig:p"]},
    )
    assert resp.status_code == 200, resp.text

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    rule_files = [n for n in zf.namelist() if n.startswith("rules/")]
    assert {zf.read(n).decode() for n in rule_files} == {"body-A", "body-P"}

    manifest = json.loads(zf.read("MANIFEST.json"))
    by_id = {r["id"]: r for r in manifest["rules"]}
    assert by_id["sig:a"]["promoted"] is False
    assert by_id["sig:a"]["techniques"] == ["T1059"]
    assert by_id["sig:p"]["promoted"] is True
    assert by_id["sig:p"]["techniques"] == []
    assert manifest["rule_count"] == 2
    assert manifest["excluded"]["total"] == 0


def test_promoted_rule_alone_is_not_a_404_issue_366(temp_db, temp_db_client):
    """A report with no linked rule at all still exports a promoted one."""
    temp_db.get_conn()
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "sig", [_rule("sig", "p", ["T1486"], raw="body-P")])
    _job_with_technique(temp_db, "j366b", "T1001")

    resp = temp_db_client.post("/api/jobs/j366b/detections/export", json={"rule_ids": ["sig:p"]})
    assert resp.status_code == 200, resp.text

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    manifest = json.loads(zf.read("MANIFEST.json"))
    assert manifest["rule_count"] == 1
    assert manifest["rules"][0]["id"] == "sig:p"
    assert manifest["rules"][0]["promoted"] is True


def test_unknown_id_is_ignored_next_to_a_promoted_one_issue_366(temp_db, temp_db_client):
    """An id that is neither in the report nor in the store is dropped silently; the
    promoted id beside it is still packaged."""
    temp_db.get_conn()
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "sig", [_rule("sig", "p", ["T1486"], raw="body-P")])
    _job_with_technique(temp_db, "j366c", "T1001")

    resp = temp_db_client.post(
        "/api/jobs/j366c/detections/export",
        json={"rule_ids": ["sig:p", "ghost:x"]},
    )
    assert resp.status_code == 200, resp.text

    manifest = json.loads(zipfile.ZipFile(io.BytesIO(resp.content)).read("MANIFEST.json"))
    assert [r["id"] for r in manifest["rules"]] == ["sig:p"]


def test_promoted_ids_are_capped_at_the_lookup_maximum_issue_366(temp_db, temp_db_client):
    """501 promoted ids are refused with 400, and the cap is the same RULE_LOOKUP_MAX
    the lookup route uses. The count is taken before any body is read."""
    from api.routes.coverage import RULE_LOOKUP_MAX

    temp_db.get_conn()
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "sig", [
        _rule("sig", f"p{k}", ["T1486"]) for k in range(RULE_LOOKUP_MAX + 1)
    ])
    _job_with_technique(temp_db, "j366d", "T1001")
    ids = [f"sig:p{k}" for k in range(RULE_LOOKUP_MAX + 1)]

    resp = temp_db_client.post("/api/jobs/j366d/detections/export", json={"rule_ids": ids})
    assert resp.status_code == 400, resp.text
    assert str(RULE_LOOKUP_MAX) in resp.json()["detail"]

    # The cap is inclusive: exactly RULE_LOOKUP_MAX promoted ids still export.
    resp_ok = temp_db_client.post(
        "/api/jobs/j366d/detections/export", json={"rule_ids": ids[:RULE_LOOKUP_MAX]},
    )
    assert resp_ok.status_code == 200, resp_ok.text
