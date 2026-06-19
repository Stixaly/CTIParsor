"""Tests for detection coverage scoring + store + API (ADR-0006)."""
from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline.detection.coverage import compute_for_job, score_techniques
from pipeline.detection.store import (
    corpus_counts,
    replace_corpus_rules,
    rule_refs_for_techniques,
)

# ── Scoring policy (pure) ─────────────────────────────────────────────────────

def test_independent_corpora_corroborate_to_3():
    refs = [("T1059", "core", "k1"), ("T1059", "cloud", "k2")]
    cell = score_techniques(["T1059"], refs)[0]
    assert cell.score == 3
    assert cell.corpora == ["cloud", "core"]
    assert cell.rule_count == 2


def test_forked_rule_does_not_inflate_score():
    # same native_key in two corpora = one logical rule (a fork) → score 2, not 3
    refs = [("T1059", "core", "k1"), ("T1059", "cloud", "k1")]
    cell = score_techniques(["T1059"], refs)[0]
    assert cell.score == 2
    assert cell.corpora == ["core"]   # first-seen corpus owns the shared rule
    assert cell.rule_count == 1


def test_single_corpus_scores_2():
    assert score_techniques(["T1059"], [("T1059", "core", "k1")])[0].score == 2


def test_no_rules_scores_0():
    assert score_techniques(["T1003"], [])[0].score == 0


def test_telemetry_only_scores_1():
    cell = score_techniques(["T1003"], [], telemetry_techniques={"T1003"})[0]
    assert cell.score == 1


# ── Store round-trip + compute_for_job (temp DB) ──────────────────────────────

def _rule(corpus, key, techniques):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=techniques, severity=Severity.HIGH, license="proprietary",
    )


def test_store_replace_and_query(temp_db):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059", "T1027"])])
    replace_corpus_rules(conn, "cloud", [_rule("cloud", "k2", ["T1059"])])

    refs = rule_refs_for_techniques(conn, ["T1059"])
    assert {(c, k) for _t, c, k in refs} == {("core", "k1"), ("cloud", "k2")}
    assert {r["corpus"]: r["rules"] for r in corpus_counts(conn)} == {"core": 1, "cloud": 1}

    # replace is idempotent — re-running one corpus doesn't duplicate
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059", "T1027"])])
    assert {r["corpus"]: r["rules"] for r in corpus_counts(conn)}["core"] == 1


def test_compute_for_job_scores_accepted_techniques(temp_db):
    conn = temp_db.get_conn()
    # two independent corpora cover T1059; nothing covers T1003
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"])])
    replace_corpus_rules(conn, "cloud", [_rule("cloud", "k2", ["T1059"])])

    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    for mid, accepted in (("T1059", 1), ("T1003", 1), ("T1110", 0)):  # T1110 rejected → excluded
        conn.execute(
            "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
            "VALUES (?,?,?,?,?,?,?)",
            (str(uuid4()), "j1", mid, "technique", mid, accepted, "llm"),
        )
    conn.commit()

    result = compute_for_job(conn, "j1")
    cells = {c["technique_id"]: c for c in result["cells"]}
    assert set(cells) == {"T1059", "T1003"}          # rejected T1110 excluded
    assert cells["T1059"]["score"] == 3               # corroborated
    assert cells["T1003"]["score"] == 0               # no rules
    assert result["validated"] is False               # readiness, not validation


# ── API ───────────────────────────────────────────────────────────────────────

def test_coverage_api(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [_rule("core", "k1", ["T1059"])])
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j2','r.txt','reviewing',?,?)", (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "j2", "PowerShell", "technique", "T1059", 1, "llm"),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j2/coverage")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["techniques_total"] == 1
    assert body["cells"][0]["technique_id"] == "T1059" and body["cells"][0]["score"] == 2

    assert temp_db_client.get("/api/jobs/does-not-exist/coverage").status_code == 404
    assert temp_db_client.get("/api/detection-corpora").json()["corpora"][0]["corpus"] == "core"
