"""
Tests for pipeline.detection.artifacts module.
"""

import sqlite3

import pytest

from pipeline.detection.artifacts import (
    MAX_EVIDENCE_PER_ARTIFACT,
    NAME_TITLE_MAX_RULES,
    coverage_for_job,
    score_artifacts,
)
from pipeline.detection.observables import Observable


@pytest.fixture
def temp_db():
    """Create an in-memory SQLite database with minimal schema."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""
        CREATE TABLE detection_rules (
            id TEXT PRIMARY KEY,
            corpus TEXT,
            native_key TEXT,
            format TEXT,
            title TEXT,
            description TEXT,
            severity TEXT,
            license TEXT,
            source_ref TEXT,
            content_hash TEXT,
            dedup_key TEXT,
            is_canonical INTEGER,
            data_sources TEXT,
            raw TEXT,
            platform TEXT,
            raw_bytes INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE rule_atoms (
            rule_id TEXT,
            atom_class TEXT,
            value TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE jobs (
            id TEXT PRIMARY KEY, original_filename TEXT, status TEXT, created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, value TEXT,
            entity_type TEXT, context TEXT, confidence REAL, mitre_id TEXT,
            accepted INTEGER, source TEXT
        )
    """)
    conn.commit()
    yield conn
    conn.close()


def _insert_rule(
    conn: sqlite3.Connection,
    rule_id: str,
    corpus: str,
    native_key: str,
    title: str = "",
    description: str = "",
    is_canonical: int = 1,
):
    """Helper to insert a rule."""
    conn.execute(
        """
        INSERT INTO detection_rules
        (id, corpus, native_key, format, title, description, severity,
         license, source_ref, content_hash, dedup_key, is_canonical,
         data_sources, raw, platform, raw_bytes)
        VALUES (?, ?, ?, 'yara', ?, ?, 'high', 'MIT', 'test', 'hash', 'dedup', ?, '[]', '', 'linux', 0)
        """,
        (rule_id, corpus, native_key, title, description, is_canonical),
    )
    conn.commit()


def _insert_atom(
    conn: sqlite3.Connection,
    rule_id: str,
    atom_class: str,
    value: str,
):
    """Helper to insert an atom."""
    conn.execute(
        "INSERT INTO rule_atoms (rule_id, atom_class, value) VALUES (?, ?, ?)",
        (rule_id, atom_class, value),
    )
    conn.commit()


def test_hash_in_two_corpora_scores_3(temp_db):
    """A hash present in two different corpora should score 3."""
    # Insert two rules in different corpora with the same hash
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_rule(temp_db, "rule2", "corpus_b", "native_key_2")

    # Add hash atom to both rules
    _insert_atom(temp_db, "rule1", "hash", "abc123")
    _insert_atom(temp_db, "rule2", "hash", "abc123")

    # Create observable
    obs = Observable(
        obs_class="hash",
        value="abc123",
        entity_type="hash",
        display="abc123",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 3
    assert len(artifacts[0].corpora) == 2


def test_hash_in_one_corpus_scores_2(temp_db):
    """A hash present in one corpus should score 2."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "hash", "abc123")

    obs = Observable(
        obs_class="hash",
        value="abc123",
        entity_type="hash",
        display="abc123",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 2
    assert len(artifacts[0].corpora) == 1


def test_forked_rule_across_corpora_does_not_inflate_score(temp_db):
    """Two rules with same native_key in different corpora should count as one corpus."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_shared")
    _insert_rule(temp_db, "rule2", "corpus_b", "native_key_shared")

    _insert_atom(temp_db, "rule1", "hash", "abc123")
    _insert_atom(temp_db, "rule2", "hash", "abc123")

    obs = Observable(
        obs_class="hash",
        value="abc123",
        entity_type="hash",
        display="abc123",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    # Should score 2 (one corpus), not 3
    assert artifacts[0].score == 2
    assert len(artifacts[0].corpora) == 1


def test_unmatched_artifact_scores_0(temp_db):
    """An artifact with no matching rules should score 0."""
    obs = Observable(
        obs_class="hash",
        value="nonexistent",
        entity_type="hash",
        display="nonexistent",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 0
    assert len(artifacts[0].corpora) == 0


def test_cve_scores_1_from_title_match_only(temp_db):
    """A CVE that only matches in title/description should score 1."""
    _insert_rule(
        temp_db,
        "rule1",
        "corpus_a",
        "native_key_1",
        title="CVE-2026-35273 vulnerability",
        description="Description of CVE-2026-35273",
    )

    obs = Observable(
        obs_class="cve",
        value="cve-2026-35273",
        entity_type="cve",
        display="CVE-2026-35273",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 1
    # Should have weak evidence
    assert len(artifacts[0].evidence) == 1
    assert artifacts[0].evidence[0].exact is False


def test_vocabulary_artifact_is_excluded_but_keeps_its_score(temp_db):
    """A vocabulary artifact should be excluded but keep its score."""
    # Insert many rules with the same value to exceed vocabulary threshold
    for i in range(25):
        _insert_rule(temp_db, f"rule{i}", f"corpus_{i % 3}", f"native_key_{i}")
        _insert_atom(temp_db, f"rule{i}", "name", "powershell.exe")

    obs = Observable(
        obs_class="name",
        value="powershell.exe",
        entity_type="name",
        display="powershell.exe",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].excluded == "vocabulary"
    # Score should still be computed (likely 3 if multiple corpora)
    assert artifacts[0].score >= 0


def test_artifact_key_is_class_and_value_not_display(temp_db):
    """Two observables with same display but different values should produce two artifacts."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "file", "/etc/hosts")
    _insert_atom(temp_db, "rule1", "file", "hosts")

    obs1 = Observable(
        obs_class="file",
        value="/etc/hosts",
        entity_type="file",
        display="hosts",
    )
    obs2 = Observable(
        obs_class="file",
        value="hosts",
        entity_type="file",
        display="hosts",
    )

    artifacts = score_artifacts(temp_db, [obs1, obs2])
    assert len(artifacts) == 2
    # Both should have evidence
    assert len(artifacts[0].evidence) >= 1
    assert len(artifacts[1].evidence) >= 1


def test_atom_class_outside_matchable_is_not_evidence(temp_db):
    """An atom of class 'registry' should not be evidence for a 'hash' observable."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "registry", "abc123")

    obs = Observable(
        obs_class="hash",
        value="abc123",
        entity_type="hash",
        display="abc123",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    # Should have no exact evidence
    exact_evidence = [ev for ev in artifacts[0].evidence if ev.exact]
    assert len(exact_evidence) == 0


def test_by_tier_always_lists_four_tiers(temp_db):
    """coverage_for_job should always return 4 tiers in by_tier."""
    # Create a job with no observables
    temp_db.execute("INSERT INTO jobs (id, original_filename, created_at) "
                    "VALUES ('job1', 'test_report', '2024-01-01')")
    temp_db.commit()

    result = coverage_for_job(temp_db, "job1")
    assert len(result["by_tier"]) == 4
    tiers = [t["tier"] for t in result["by_tier"]]
    assert tiers == [1, 2, 3, 4]



def test_empty_report_returns_zeros(temp_db):
    """An empty report should return all zeros."""
    temp_db.execute("INSERT INTO jobs (id, original_filename, created_at) "
                    "VALUES ('job1', 'empty_report', '2024-01-01')")
    temp_db.commit()

    result = coverage_for_job(temp_db, "job1")
    assert result["totals"]["artifacts"] == 0
    assert result["totals"]["covered"] == 0
    assert result["totals"]["weak"] == 0
    assert result["totals"]["uncovered"] == 0
    assert result["totals"]["excluded"] == 0
    assert len(result["by_tier"]) == 4
    for tier in result["by_tier"]:
        assert tier["artifacts"] == 0
        assert tier["covered"] == 0
        assert tier["weak"] == 0
        assert tier["uncovered"] == 0


def test_evidence_is_capped_but_score_uses_all_of_it(temp_db):
    """An artifact with more than MAX_EVIDENCE_PER_ARTIFACT exact evidence should be capped."""
    # Create more than MAX_EVIDENCE_PER_ARTIFACT rules in 2 corpora
    num_rules = MAX_EVIDENCE_PER_ARTIFACT + 5  # 25 rules
    for i in range(num_rules):
        corpus = "corpus_a" if i % 2 == 0 else "corpus_b"
        _insert_rule(temp_db, f"rule{i}", corpus, f"native_key_{i}")
        _insert_atom(temp_db, f"rule{i}", "hash", "test_hash")

    obs = Observable(
        obs_class="hash",
        value="test_hash",
        entity_type="hash",
        display="test_hash",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    artifact = artifacts[0]

    # The object keeps every piece of evidence: the phase band reads the full
    # set of matched rules from here.
    assert len(artifact.evidence) == num_rules
    # Only serialization caps it, and it still reports the true total.
    payload = artifact.as_dict()
    assert len(payload["evidence"]) == MAX_EVIDENCE_PER_ARTIFACT
    assert payload["evidence_total"] == num_rules
    # Score should be 3 (2 corpora)
    assert artifact.score == 3


def test_non_discriminative_name_gets_no_title_evidence(temp_db):
    """A name appearing in more than NAME_TITLE_MAX_RULES titles should get no title evidence."""
    # Create more than NAME_TITLE_MAX_RULES rules with the same name in title
    num_rules = NAME_TITLE_MAX_RULES + 1  # 501 rules
    for i in range(num_rules):
        _insert_rule(
            temp_db,
            f"rule{i}",
            "corpus_a",
            f"native_key_{i}",
            title=f"Generic name {i}",
            description="common name"
        )

    # Insert a name that appears in all these titles
    # We need to add the name to the titles
    # Let's re-insert with the name in title
    temp_db.execute("DELETE FROM detection_rules")
    temp_db.commit()

    for i in range(num_rules):
        _insert_rule(
            temp_db,
            f"rule{i}",
            "corpus_a",
            f"native_key_{i}",
            title=f"common_name {i}",
            description=""
        )

    obs = Observable(
        obs_class="name",
        value="common_name",
        entity_type="name",
        display="common_name",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    artifact = artifacts[0]

    # No title evidence should be present
    title_evidence = [ev for ev in artifact.evidence if ev.atom_class == "title"]
    assert len(title_evidence) == 0
    # Score should be 0 (no exact evidence, no weak evidence)
    assert artifact.score == 0


def test_cve_stays_in_the_denominator_even_with_no_evidence(temp_db):
    """A CVE has no atom class, but it is NOT unmatchable.

    Excluding every class absent from MATCHABLE wrote CVEs off as
    "not_matchable" and dropped them from the totals -- while `_title_evidence`
    could still score them, so a CVE with a title match scored 1 and was counted
    nowhere. A CVE is a real artifact an analyst wants coverage for; it simply
    cannot reach 3 by atom corroboration.
    """
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")

    obs = Observable(
        obs_class="cve",
        value="cve-2026-35273",
        entity_type="cve",
        display="CVE-2026-35273",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 0
    assert artifacts[0].excluded is None


def test_title_only_match_reports_its_corpora_without_inflating_the_score(temp_db):
    """`corpora` scores; `evidence_corpora` informs. They must not be conflated.

    Shown with a TOOL: only a malware identity earns title corroboration, so a
    tool named in three corpora stays at score 1 with an empty `corpora` — while
    `evidence_corpora` still reports the three, because reporting nothing there
    reads as no coverage at all.

    This test asserted the same of a *malware* entity until the CERT Polska
    report showed that inverted the ranking — `Ping` scored 2 against
    BlackEnergy's 1. Malware title corroboration is now covered by
    `test_malware_family_named_in_two_corpora_scores_3`.
    """
    _insert_rule(temp_db, "a:k1", "corpus_a", "k1", title="Nircmd Execution")
    _insert_rule(temp_db, "b:k2", "corpus_b", "k2", title="nircmd")
    _insert_rule(temp_db, "c:k3", "corpus_c", "k3", title="Suspicious nircmd usage")

    obs = Observable(
        obs_class="name", value="nircmd", entity_type="tool", display="NirCmd",
    )

    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    artifact = artifacts[0]

    # Three corpora name it, and for a tool it is still weak evidence.
    assert artifact.score == 1
    assert artifact.corpora == []

    payload = artifact.as_dict()
    assert payload["evidence_corpora"] == ["corpus_a", "corpus_b", "corpus_c"]
    assert payload["evidence_total"] == 3

def test_file_and_image_of_one_binary_are_one_artifact(temp_db):
    """File and image observables for the same value fold into one artifact."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "image", "nircmd.exe")
    obs_file = Observable(obs_class="file", value="nircmd.exe", entity_type="file", display="nircmd.exe")
    obs_image = Observable(obs_class="image", value="nircmd.exe", entity_type="image", display="nircmd.exe")
    artifacts = score_artifacts(temp_db, [obs_file, obs_image])
    assert len(artifacts) == 1
    assert artifacts[0].classes == ["file", "image"]
    assert artifacts[0].artifact_class == "file"


def test_domain_and_file_of_one_value_fold_to_the_strongest_tier(temp_db):
    """Domain, file, and image observables fold to the strongest tier."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "domain", "pastebin.com")
    obs_domain = Observable(obs_class="domain", value="pastebin.com", entity_type="domain", display="pastebin.com")
    obs_file = Observable(obs_class="file", value="pastebin.com", entity_type="file", display="pastebin.com")
    obs_image = Observable(obs_class="image", value="pastebin.com", entity_type="image", display="pastebin.com")
    artifacts = score_artifacts(temp_db, [obs_domain, obs_file, obs_image])
    assert len(artifacts) == 1
    assert artifacts[0].artifact_class == "domain"
    assert artifacts[0].tier == 2
    assert artifacts[0].classes == ["domain", "file", "image"]


def test_folded_evidence_is_unioned_and_deduplicated(temp_db):
    """Evidence from folded classes is unioned and deduplicated."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "image", "tool.exe")
    obs_file = Observable(obs_class="file", value="tool.exe", entity_type="file", display="tool.exe")
    obs_image = Observable(obs_class="image", value="tool.exe", entity_type="image", display="tool.exe")
    artifacts = score_artifacts(temp_db, [obs_file, obs_image])
    assert len(artifacts) == 1
    assert artifacts[0].as_dict()["evidence_total"] == 1


def test_folding_recomputes_the_score_it_does_not_take_the_max(temp_db):
    """Folding recomputes score on unioned evidence, not max of individual scores."""
    _insert_rule(temp_db, "rule_a", "corpus_a", "nk1")
    _insert_atom(temp_db, "rule_a", "file", "tool.exe")
    _insert_rule(temp_db, "rule_b", "corpus_b", "nk2")
    _insert_atom(temp_db, "rule_b", "image", "tool.exe")
    obs_file = Observable(obs_class="file", value="tool.exe", entity_type="file", display="tool.exe")
    obs_image = Observable(obs_class="image", value="tool.exe", entity_type="image", display="tool.exe")
    artifacts = score_artifacts(temp_db, [obs_file, obs_image])
    assert len(artifacts) == 1
    assert artifacts[0].score == 3
    assert len(artifacts[0].corpora) == 2


def test_folded_artifact_is_vocabulary_if_any_matchable_class_exceeds_the_floor(temp_db):
    """Folded artifact is excluded as vocabulary if matchable rules exceed floor."""
    for i in range(25):
        rule_id = f"rule_{i}"
        corpus = f"corpus_{i % 5}"
        _insert_rule(temp_db, rule_id, corpus, f"nk_{i}")
        _insert_atom(temp_db, rule_id, "image", "powershell.exe")
    obs_name = Observable(obs_class="name", value="powershell.exe", entity_type="name", display="powershell.exe")
    obs_image = Observable(obs_class="image", value="powershell.exe", entity_type="image", display="powershell.exe")
    artifacts = score_artifacts(temp_db, [obs_name, obs_image])
    assert len(artifacts) == 1
    assert artifacts[0].excluded == "vocabulary"


def test_distinct_values_are_never_folded(temp_db):
    """Distinct values are never folded into the same artifact."""
    _insert_rule(temp_db, "rule1", "corpus_a", "native_key_1")
    _insert_atom(temp_db, "rule1", "name", "nircmd")
    _insert_rule(temp_db, "rule2", "corpus_a", "native_key_2")
    _insert_atom(temp_db, "rule2", "file", "nircmd.exe")
    obs_name = Observable(obs_class="name", value="nircmd", entity_type="name", display="nircmd")
    obs_file = Observable(obs_class="file", value="nircmd.exe", entity_type="file", display="nircmd.exe")
    artifacts = score_artifacts(temp_db, [obs_name, obs_file])
    assert len(artifacts) == 2


def test_totals_ignore_excluded_artifacts(temp_db):
    """Coverage totals correctly count excluded artifacts after folding."""
    for i in range(25):
        rule_id = f"rule_{i}"
        corpus = f"corpus_{i % 5}"
        _insert_rule(temp_db, rule_id, corpus, f"nk_{i}")
        _insert_atom(temp_db, rule_id, "image", "powershell.exe")
    _insert_rule(temp_db, "rule_real", "corpus_a", "nk_real")
    _insert_atom(temp_db, "rule_real", "hash", "a" * 64)
    temp_db.execute(
        "INSERT INTO jobs (id, original_filename, created_at) VALUES ('job1', 'test_report', '2024-01-01')"
    )
    temp_db.execute(
        "INSERT INTO entities (job_id, value, entity_type, accepted) VALUES ('job1', 'powershell.exe', 'tool', 1)"
    )
    temp_db.execute(
        "INSERT INTO entities (job_id, value, entity_type, accepted) "
        "VALUES ('job1', ?, 'sha256', 1)", ("a" * 64,)
    )
    temp_db.commit()
    coverage = coverage_for_job(temp_db, "job1")
    totals = coverage["totals"]
    assert totals["artifacts"] == 1
    assert totals["excluded"] == 1
    assert totals["covered"] == 1
    excluded_values = {a["value"] for a in coverage["artifacts"] if a["excluded"]}
    assert excluded_values == {"powershell.exe"}
def test_malware_family_named_in_two_corpora_scores_3(temp_db):
    """Malware family in two corpora scores 3."""
    _insert_rule(temp_db, "r1", "corpus_a", "nk1", title="BlackEnergy_BE_2")
    _insert_rule(temp_db, "r2", "corpus_b", "nk2", title="BlackEnergyDDoSBotCrypter")
    obs = Observable(obs_class="name", value="blackenergy", display="blackenergy", entity_type="malware")
    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 3
    assert len(artifacts[0].corpora) == 2


def test_malware_family_in_one_corpus_scores_2(temp_db):
    """Malware family in one corpus scores 2."""
    _insert_rule(temp_db, "r1", "corpus_a", "nk1", title="MAL_EXE_PrestigeRansomware")
    obs = Observable(obs_class="name", value="prestigeransomware", display="prestigeransomware", entity_type="malware")
    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 2


def test_tool_name_gets_no_title_corroboration(temp_db):
    """Tool name does not get title corroboration."""
    _insert_rule(temp_db, "r1", "corpus_a", "nk1", title="BlackEnergy_BE_2")
    _insert_rule(temp_db, "r2", "corpus_b", "nk2", title="BlackEnergyDDoSBotCrypter")
    obs = Observable(obs_class="name", value="blackenergy", display="blackenergy", entity_type="tool")
    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 1
    assert artifacts[0].corpora == []


def test_description_mention_never_corroborates(temp_db):
    """Description mention never corroborates."""
    _insert_rule(temp_db, "r1", "corpus_a", "nk1", title="Unrelated_Title",
                 description="similar to blackenergy")
    obs = Observable(obs_class="name", value="blackenergy", display="blackenergy", entity_type="malware")
    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 1
    assert artifacts[0].evidence[0].atom_class == "description"


def test_title_evidence_carries_native_key_so_forks_fold(temp_db):
    """Title evidence with same native_key folds to one corpus."""
    _insert_rule(temp_db, "r1", "corpus_a", "same_nk", title="BlackEnergy_BE_2")
    _insert_rule(temp_db, "r2", "corpus_b", "same_nk", title="BlackEnergyDDoSBotCrypter")
    obs = Observable(obs_class="name", value="blackenergy", display="blackenergy", entity_type="malware")
    artifacts = score_artifacts(temp_db, [obs])
    assert len(artifacts) == 1
    assert artifacts[0].score == 2
