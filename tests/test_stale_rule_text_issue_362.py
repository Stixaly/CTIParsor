"""A stale rule_text index never serves a demoted rule (#362).

`dedupe_store` can re-elect the canonical rule of a cluster on its own, and the
rule_text index only follows on the next `rebuild_rule_text`. Until then the
index still names the rule that lost its canonical flag, so every title read
must join on `is_canonical = 1`. Otherwise the coverage panel proposes it, and
the export ships it with an empty body.
"""
from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline.detection.brands import cve_evidence, rebuild_rule_text
from pipeline.detection.coverage import rule_bodies_for_job, rules_for_job
from pipeline.detection.dedup import dedupe_store
from pipeline.detection.store import lookup_rules, replace_corpus_rules

_CVE = "CVE-2024-3400"
_TITLE = f"Exploit for {_CVE} on PAN-OS"


def _rule(corpus, key, title):
    """Two rules with the same dedup_key: one detection logic, two corpora."""
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=title, technique_ids=[],
        severity=Severity.HIGH, license="proprietary", format="sigma",
        dedup_key="same-logic", raw=f"title: {title}\n",
    )


def _job_with_cve(temp_db):
    """A report whose only observable is the CVE, so only title evidence can reach a rule."""
    job_id = str(uuid4())
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES (?,?,?,?,?)", (job_id, "r.txt", "reviewing", temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), job_id, _CVE, "cve", None, 1, "llm"),
    )
    conn.commit()
    return job_id


def _canonical(rconn):
    return {r[0] for r in rconn.execute("SELECT id FROM detection_rules WHERE is_canonical=1").fetchall()}


def _indexed(rconn):
    return {r[0] for r in rconn.execute("SELECT rule_id FROM rule_text").fetchall()}


def _served(temp_db, job_id):
    rconn = temp_db.get_rule_conn()
    return {
        r["id"] for g in rules_for_job(rconn, job_id, jobs_conn=temp_db.get_conn())["techniques"]
        for r in g["rules"]
    }


def _exported(temp_db, job_id):
    rconn = temp_db.get_rule_conn()
    return rule_bodies_for_job(rconn, job_id, jobs_conn=temp_db.get_conn())


def test_a_reelected_rule_is_not_served_from_a_stale_index_issue_362(temp_db):
    job_id = _job_with_cve(temp_db)
    rconn = temp_db.get_rule_conn()
    replace_corpus_rules(rconn, "alpha", [_rule("alpha", "a", _TITLE)])
    replace_corpus_rules(rconn, "beta", [_rule("beta", "b", _TITLE)])

    # beta wins and is indexed: the control, the panel serves it.
    dedupe_store(rconn, {"beta": 1, "alpha": 2})
    rebuild_rule_text(rconn)
    rconn.commit()
    assert _canonical(rconn) == {"beta:b"}
    assert _indexed(rconn) == {"beta:b"}
    assert _served(temp_db, job_id) == {"beta:b"}
    assert [r["id"] for r in _exported(temp_db, job_id)] == ["beta:b"]

    # Priorities inverted, dedupe alone: alpha is elected, the index still names beta.
    dedupe_store(rconn, {"alpha": 1, "beta": 2})
    assert _canonical(rconn) == {"alpha:a"}
    assert _indexed(rconn) == {"beta:b"}

    assert cve_evidence(rconn, [_CVE]) == {}
    assert _served(temp_db, job_id) == set()
    exported = {r["id"] for r in _exported(temp_db, job_id)}
    assert "beta:b" not in exported
    assert lookup_rules(rconn, ["beta:b"]) == []

    # The rebuild that follows restores the title match on the elected rule.
    rebuild_rule_text(rconn)
    rconn.commit()
    assert _indexed(rconn) == {"alpha:a"}
    assert set(cve_evidence(rconn, [_CVE])) == {"alpha:a"}
    assert _served(temp_db, job_id) == {"alpha:a"}
    body = {r["id"]: r["raw"] for r in _exported(temp_db, job_id)}
    assert body == {"alpha:a": f"title: {_TITLE}\n"}
