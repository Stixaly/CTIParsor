from uuid import uuid4

from models.detection import DetectionRule, Severity
from pipeline.detection.store import replace_corpus_rules

THE_HASH = "a" * 64


def _rule(corpus, key, techniques, *, atoms=(), title=""):
    return DetectionRule(
        id=f"{corpus}:{key}",
        corpus=corpus,
        title=title or f"rule {key}",
        technique_ids=techniques,
        severity=Severity.HIGH,
        license="proprietary",
        atoms=list(atoms),
        raw=f"title: rule {key}\n",
    )


def test_artifact_coverage_route_returns_artifacts_and_phases(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _rule("core", "k1", ["T1190"], atoms=[("hash", THE_HASH)]),
    ])
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.pdf','reviewing',?,?)",
        (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "j1", THE_HASH, "sha256", None, 1, "llm"),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j1/coverage/artifacts")
    assert resp.status_code == 200
    data = resp.json()
    assert "artifacts" in data
    assert "totals" in data
    assert "by_tier" in data
    assert "phases" in data
    assert "matched_rules" in data
    assert "vocabulary_threshold" in data
    assert "canonical_rules" in data
    assert "report" in data["phases"]
    assert "covered" in data["phases"]
    assert "gap" in data["phases"]


def test_artifact_route_returns_the_coverage_payload_shape(temp_db, temp_db_client):
    """Contract test for the payload, NOT a route-ordering test.

    It was written as one — asserting `/coverage/artifacts` is not shadowed by
    `/coverage/{technique_id}/rules` — but that cannot happen: the second
    template carries a trailing `/rules` segment, so the two never compete.
    Moving the route below it left every test passing, which is how the false
    premise was caught. What is worth locking is the shape the frontend reads.
    """
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.pdf','reviewing',?,?)",
        (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j1/coverage/artifacts")
    assert resp.status_code == 200
    data = resp.json()

    assert set(data) == {
        "job_id", "artifacts", "totals", "by_tier", "phases",
        "matched_rules", "vocabulary_threshold", "canonical_rules",
    }
    assert set(data["totals"]) == {
        "artifacts", "covered", "weak", "uncovered", "excluded",
    }
    assert set(data["phases"]) == {"report", "covered", "gap"}
    assert [t["tier"] for t in data["by_tier"]] == [1, 2, 3, 4]


def test_artifact_coverage_404_on_unknown_job(temp_db, temp_db_client):
    resp = temp_db_client.get("/api/jobs/nonexistent/coverage/artifacts")
    assert resp.status_code == 404


def test_excluded_artifacts_do_not_feed_the_phase_band(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "core", [
        _rule("core", "k1", ["T1190"], atoms=[("hash", THE_HASH)]),
    ])
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.pdf','reviewing',?,?)",
        (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.execute(
        "INSERT INTO entities (id,job_id,value,entity_type,mitre_id,accepted,source) "
        "VALUES (?,?,?,?,?,?,?)",
        (str(uuid4()), "j1", THE_HASH, "sha256", None, 1, "llm"),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j1/coverage/artifacts")
    assert resp.status_code == 200
    data = resp.json()
    phases = data["phases"]
    for key in ("report", "covered", "gap"):
        if key in phases and isinstance(phases[key], dict):
            assert "T1190" not in phases[key]


def test_empty_job_returns_zero_totals_and_full_band(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
        "VALUES ('j1','r.pdf','reviewing',?,?)",
        (temp_db.now_iso(), temp_db.now_iso()),
    )
    conn.commit()

    resp = temp_db_client.get("/api/jobs/j1/coverage/artifacts")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totals"]["artifacts"] == 0
    assert data["totals"]["covered"] == 0
    assert data["totals"]["weak"] == 0
    assert data["totals"]["uncovered"] == 0
    assert "gap" in data["phases"]
