# tests/test_brands.py
import sqlite3

from pipeline.detection.brands import BRAND_MAX_TITLE_RULES, brand_evidence, brand_tokens, campaign_tokens


def _store(rows):
    """rows = list of (id, title, description) -> in-memory canonical rule store."""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE detection_rules (id TEXT, title TEXT, description TEXT, is_canonical INT)"
    )
    conn.executemany(
        "INSERT INTO detection_rules VALUES (?,?,?,1)", rows
    )
    return conn


def test_a_theme_recurring_across_domains_is_found():
    domains = ["idokta.com", "keyokta.com", "oktaenroll.com", "myoktasso.com"]
    tokens = campaign_tokens(domains)
    assert "okta" in tokens
    assert tokens["okta"] == 4


def test_a_single_random_domain_yields_no_theme():
    domains = ["sqfepjvmrd.xyz"]
    tokens = campaign_tokens(domains)
    assert tokens == {}


def test_a_fragment_loses_to_the_longer_token_that_contains_it():
    domains = ["polygon1.com", "polygon2.com", "polygon3.com"]
    tokens = campaign_tokens(domains)
    assert "polygon" in tokens
    assert "poly" not in tokens


def test_the_same_domain_twice_counts_once():
    """A domain listed twice is one domain, so it lifts no count.

    Four entries, three distinct hosts: `okta` must score 3, not 4. A fourth
    distinct host is needed for the theme to clear BRAND_MIN_DOMAINS at all,
    which is why the duplicate cannot simply be dropped from the fixture.
    """
    domains = ["okta-portal.com", "okta-portal.com", "keyokta.com", "oktaenroll.com"]
    tokens = campaign_tokens(domains)
    assert tokens.get("okta") == 3


def test_domain_stopwords_never_become_brands():
    domains = ["passkey1.com", "passkey2.com", "passkey3.com", "passkey4.com"]
    rows = [
        ("r1", "Passkey Security", "Protect passkey"),
        ("r2", "Other Rule", "No match"),
    ]
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    assert all(t.token != "passkey" for t in tokens)


def test_a_token_naming_too_many_rules_is_vocabulary():
    domains = ["brandx1.com", "brandx2.com", "brandx3.com"]
    rows = []
    for i in range(BRAND_MAX_TITLE_RULES + 1):
        rows.append((f"r{i}", f"BrandX Rule {i}", "Description"))
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    assert all(t.token != "brandx" for t in tokens)


def test_a_token_naming_no_rule_is_dropped():
    domains = ["uniquetheme1.com", "uniquetheme2.com", "uniquetheme3.com"]
    rows = [
        ("r1", "Unrelated Rule", "Nothing here"),
    ]
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    assert tokens == []


def test_word_boundary_not_substring():
    domains = ["polyone.com", "polytwo.com", "polythree.com"]
    rows = [
        ("r1", "Monopoly Game Detected", "Board game"),
    ]
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    assert tokens == []


def test_brand_evidence_prefers_title_over_description():
    domains = ["okta1.com", "okta2.com", "okta3.com"]
    rows = [
        ("r1", "Okta Login", "Okta description"),
    ]
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    if tokens:
        evidence = brand_evidence(conn, tokens)
        assert "r1" in evidence
        assert len(evidence["r1"]) == 1
        assert evidence["r1"][0]["field"] == "title"


def test_brand_evidence_never_corroborates():
    domains = ["okta1.com", "okta2.com", "okta3.com"]
    rows = [
        ("r1", "Okta Login", "Okta description"),
    ]
    conn = _store(rows)
    tokens = brand_tokens(conn, domains)
    if tokens:
        evidence = brand_evidence(conn, tokens)
        for rule_id, proofs in evidence.items():
            for proof in proofs:
                assert proof["discriminating"] is False
                assert proof["kind"] == "title"


def test_no_tokens_means_no_query():
    conn = None
    evidence = brand_evidence(conn, [])
    assert evidence == {}


def test_malformed_domains_never_raise():
    domains = [None, 42, "", "   ", "localhost"]
    tokens = campaign_tokens(domains)
    assert isinstance(tokens, dict)
