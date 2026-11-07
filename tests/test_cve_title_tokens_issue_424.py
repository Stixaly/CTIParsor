# tests/test_cve_title_tokens_issue_424.py
"""#424: PostgreSQL's `simple` parser keeps a hyphen inside a number, so the
title `CVE-2024-3400` is indexed as 'cve' '-2024' '-3400' and a query for the
id never found a rule that wrote it with underscores or spaces (`CVE_2024_3400`
gives 'cve' '2024' '3400'). rebuild_rule_text and cve_evidence now both turn
`-` and `_` into spaces, so every spelling meets as 'cve' <-> '2024' <-> '3400'.
"""

from pipeline.detection.brands import BrandToken, brand_evidence, cve_evidence, rebuild_rule_text


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


def test_a_cve_written_with_underscores_is_found_issue_424(temp_db):
    conn = _index(temp_db.get_rule_conn(), [("r1", "PAN-OS CVE_2024_3400 exploit", "")])
    evidence = cve_evidence(conn, ["CVE-2024-3400"])
    assert set(evidence) == {"r1"}
    assert evidence["r1"][0]["value"] == "cve-2024-3400"


def test_a_cve_written_with_spaces_is_found_issue_424(temp_db):
    conn = _index(temp_db.get_rule_conn(), [("r1", "Exploit CVE 2024 3400 on PAN-OS", "")])
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == {"r1"}


def test_a_cve_written_with_hyphens_is_still_found_issue_424(temp_db):
    # Control: the spelling that already matched before the normalisation.
    conn = _index(temp_db.get_rule_conn(), [("r1", "Exploit for CVE-2024-3400 on PAN-OS", "")])
    assert set(cve_evidence(conn, ["CVE-2024-3400"])) == {"r1"}


def test_the_separator_spellings_do_not_match_another_cve_issue_424(temp_db):
    conn = _index(temp_db.get_rule_conn(), [
        ("r1", "Exploit CVE_2024_34000", ""),   # a longer number is not 3400
        ("r2", "Exploit CVE_2024_3401", ""),
    ])
    assert cve_evidence(conn, ["CVE-2024-3400"]) == {}


def test_a_brand_is_still_found_across_separators_issue_424(temp_db):
    # Control for the brand side: brand tokens are alphanumeric, so the
    # normalisation of the indexed body leaves their matches unchanged.
    conn = _index(temp_db.get_rule_conn(), [("r1", "Phishing apt_okta_phishing", "okta-login page")])
    tokens = [BrandToken(token="okta", domains=3, rules=1)]
    assert set(brand_evidence(conn, tokens)) == {"r1"}


def test_a_run_of_digits_is_no_brand_token_issue_424():
    from pipeline.detection.brands import campaign_tokens
    tokens = campaign_tokens(["2024login.com", "pay2024.net", "x2024y.org"])
    assert "2024" not in tokens
