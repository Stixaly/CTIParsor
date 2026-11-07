# tests/test_brand_maximal_issue_423.py
"""#423: `_maximal` ran inside `campaign_tokens`, before `brand_tokens` filtered
the candidates by rule count. A longer token that names no rule (`oktalogin`,
from `oktalogin.com/.net/.org`) therefore removed `okta` as a substring, and
then `brand_tokens` dropped `oktalogin` for naming nothing: the real brand left
the report with no token at all.

Maximality now runs on the survivors of the rule filter: `s` is dropped only
when a longer `t` with df(t) >= df(s) is itself a brand the corpus names.
"""

from pipeline.detection.brands import brand_tokens, rebuild_rule_text


def _index(conn, rows):
    """rows = list of (id, title, description) -> canonical rules, indexed by the
    same rebuild that scripts/build_rule_text.py and rebuild_store run."""
    for rid, title, description in rows:
        conn.execute(
            "INSERT INTO detection_rules (id, corpus, native_key, title, description, is_canonical) "
            "VALUES (?,?,?,?,?,1)",
            (rid, "test", rid, title, description),
        )
    conn.commit()
    rebuild_rule_text(conn)
    conn.commit()
    return conn


def test_a_brand_survives_a_longer_token_naming_no_rule_issue_423(temp_db):
    # The reported case: `oktalogin` recurs in 3 domains but names no rule, so
    # it must not take `okta` (which names one) down with it.
    conn = _index(temp_db.get_rule_conn(), [("r1", "Okta phishing", "")])
    domains = ["oktalogin.com", "oktalogin.net", "oktalogin.org"]
    tokens = brand_tokens(conn, domains)
    assert [(t.token, t.domains, t.rules) for t in tokens] == [("okta", 3, 1)]


def test_a_longer_token_naming_a_rule_still_removes_its_substring_issue_423(temp_db):
    # Control: once a rule names `oktalogin`, it is the brand, and `okta` (df 3,
    # a substring of it) is removed by maximality as before.
    conn = _index(temp_db.get_rule_conn(), [
        ("r1", "Okta phishing", ""),
        ("r2", "Oktalogin kit", ""),
    ])
    domains = ["oktalogin.com", "oktalogin.net", "oktalogin.org"]
    tokens = brand_tokens(conn, domains)
    assert [t.token for t in tokens] == ["oktalogin"]


def test_a_multi_tld_brand_is_found_issue_423(temp_db):
    # Issue #361's case end to end: three TLDs of one name are three domains,
    # and the label `frostledger` names a rule, so it is the brand.
    conn = _index(temp_db.get_rule_conn(), [("r1", "Frostledger stealer", "")])
    domains = ["frostledger.com", "frostledger.net", "frostledger.org"]
    tokens = brand_tokens(conn, domains)
    assert [(t.token, t.domains) for t in tokens] == [("frostledger", 3)]
