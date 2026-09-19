# tests/test_brands.py
"""ADR-0031/ADR-0053: brand and CVE evidence match through PostgreSQL's
tsvector now, not SQLite FTS5. The tests that exercise `rule_text` build a
real store against `temp_db` (a disposable PostgreSQL schema) rather than a
bare `detection_rules`-only table — a prior version of this file built no
`rule_text` table at all, so `rule_text_built()` always returned False and
every brand/CVE match silently short-circuited to an empty result before a
single query ran. The assertions passed, but proved nothing about matching.
"""

from pipeline.detection.brands import (
    BRAND_MAX_TITLE_RULES,
    brand_evidence,
    brand_tokens,
    campaign_tokens,
    cve_evidence,
)


def _store(conn, rows):
    """rows = list of (id, title, description) -> populates detection_rules
    AND rule_text (body_tsv is a generated column, so only `body` is written,
    matching what scripts/build_rule_text.py writes in production: the
    lower-cased "title description" concatenation)."""
    for rid, title, description in rows:
        conn.execute(
            "INSERT INTO detection_rules (id, corpus, native_key, title, description, is_canonical) "
            "VALUES (?,?,?,?,?,1)",
            (rid, "test", rid, title, description),
        )
        body = f"{title} {description}".strip().lower()
        if body:
            conn.execute(
                "INSERT INTO rule_text (rule_id, body) VALUES (?,?)",
                (rid, body),
            )
    conn.commit()
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


def test_domain_stopwords_never_become_brands(temp_db):
    domains = ["passkey1.com", "passkey2.com", "passkey3.com", "passkey4.com"]
    rows = [
        ("r1", "Passkey Security", "Protect passkey"),
        ("r2", "Other Rule", "No match"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert all(t.token != "passkey" for t in tokens)


def test_a_token_naming_too_many_rules_is_vocabulary(temp_db):
    domains = ["brandx1.com", "brandx2.com", "brandx3.com"]
    rows = []
    for i in range(BRAND_MAX_TITLE_RULES + 1):
        rows.append((f"r{i}", f"BrandX Rule {i}", "Description"))
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert all(t.token != "brandx" for t in tokens)


def test_a_token_naming_no_rule_is_dropped(temp_db):
    domains = ["uniquetheme1.com", "uniquetheme2.com", "uniquetheme3.com"]
    rows = [
        ("r1", "Unrelated Rule", "Nothing here"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert tokens == []


def test_word_boundary_not_substring(temp_db):
    """ADR-0031's founding case: a `poly` match must not fire on `Monopoly` —
    that is the whole reason this module uses tsvector's word-tokenized
    matching rather than a LIKE/substring scan."""
    domains = ["polyone.com", "polytwo.com", "polythree.com"]
    rows = [
        ("r1", "Monopoly Game Detected", "Board game"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert tokens == []


def test_reat_does_not_match_inside_threat_or_great(temp_db):
    """The exact regression ADR-0031 was written to fix: a substring match
    on `reat` used to fire inside `threat`/`great` (52,775 rules on the real
    corpus). `to_tsvector('simple', ...)` tokenizes on word boundaries, so a
    phrase query for `reat` must match none of these rules."""
    rows = [
        ("r1", "Great Detection Rule", "A great rule"),
        ("r2", "Threat Hunting Ruleset", "Hunts for threats"),
        ("r3", "Retreat Pattern", "Detects a retreat"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    domains = ["reat1.com", "reat2.com", "reat3.com"]
    tokens = brand_tokens(conn, domains)
    assert all(t.token != "reat" for t in tokens)


def test_brand_evidence_prefers_title_over_description(temp_db):
    domains = ["okta1.com", "okta2.com", "okta3.com"]
    rows = [
        ("r1", "Okta Login", "Okta description"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert tokens, "expected 'okta' to be found as a brand token"
    evidence = brand_evidence(conn, tokens)
    assert "r1" in evidence
    assert len(evidence["r1"]) == 1
    assert evidence["r1"][0]["field"] == "title"


def test_brand_evidence_never_corroborates(temp_db):
    domains = ["okta1.com", "okta2.com", "okta3.com"]
    rows = [
        ("r1", "Okta Login", "Okta description"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    tokens = brand_tokens(conn, domains)
    assert tokens, "expected 'okta' to be found as a brand token"
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


# ── CVE evidence (ADR-0031 §cve_evidence) ────────────────────────────────────
# tsvector's default parser gives hyphenated identifiers like `cve-2021-44228`
# special handling (indexed as a compound token AND its parts) — this is the
# concrete case flagged as needing real, not assumed, coverage after the
# FTS5 -> tsvector migration.

def test_cve_evidence_matches_the_exact_hyphenated_id(temp_db):
    rows = [
        ("r1", "Log4Shell Exploitation", "Detects CVE-2021-44228 exploitation attempts"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    evidence = cve_evidence(conn, ["CVE-2021-44228"])
    assert "r1" in evidence
    assert evidence["r1"][0]["value"] == "cve-2021-44228"
    assert evidence["r1"][0]["discriminating"] is False


def test_cve_evidence_does_not_match_a_different_cve(temp_db):
    rows = [
        ("r1", "Log4Shell Exploitation", "Detects CVE-2021-44228 exploitation attempts"),
    ]
    conn = _store(temp_db.get_rule_conn(), rows)
    evidence = cve_evidence(conn, ["CVE-2024-3400"])
    assert evidence == {}
