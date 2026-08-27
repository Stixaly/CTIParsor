from models.detection import DetectionRule, Severity
from pipeline.detection.store import replace_corpus_rules


def _rule(corpus, key, *, techniques=(), raw="detection:\n  sel: x\n", license="DRL-1.1"):
    return DetectionRule(
        id=f"{corpus}:{key}", corpus=corpus, title=f"rule {key}",
        technique_ids=list(techniques), severity=Severity.HIGH,
        license=license, raw=raw,
    )

def test_lookup_returns_metadata_without_body_by_default(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a")])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a"]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["rules"]) == 1
    rule = data["rules"][0]
    assert rule["raw"] == ""
    assert rule["title"] == "rule a"
    assert rule["corpus"] == "sig"
    assert rule["license"] == "DRL-1.1"
    assert rule["format"] == "sigma"

def test_lookup_returns_the_body_when_asked(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a")])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a"], "include_body": True})
    assert resp.status_code == 200
    data = resp.json()
    rule = data["rules"][0]
    assert "detection:" in rule["raw"]

def test_lookup_carries_the_technique_tags(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a", techniques=["T1059", "T1027"])])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a"]})
    assert resp.status_code == 200
    data = resp.json()
    rule = data["rules"][0]
    assert rule["techniques"] == ["T1027", "T1059"]

def test_an_unknown_id_is_absent_not_an_error(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a")])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a", "sig:unknown"]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["rules"]) == 1
    assert data["rules"][0]["id"] == "sig:a"

def test_duplicate_ids_yield_one_entry(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a")])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a", "sig:a", "sig:a"]})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["rules"]) == 1
    assert data["requested"] == 1

def test_an_empty_list_is_rejected(temp_db_client):
    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": []})
    assert resp.status_code == 400

def test_too_many_ids_is_rejected(temp_db_client):
    ids = [f"sig:{i}" for i in range(501)]
    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ids})
    assert resp.status_code == 413

def test_license_travels_with_the_rule(temp_db, temp_db_client):
    conn = temp_db.get_conn()
    replace_corpus_rules(conn, "sig", [_rule("sig", "a", license="none")])

    resp = temp_db_client.post("/api/rules/lookup", json={"rule_ids": ["sig:a"]})
    assert resp.status_code == 200
    data = resp.json()
    rule = data["rules"][0]
    assert rule["license"] == "none"
