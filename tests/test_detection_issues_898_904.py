"""Detection fixes from the 2026-11 triage: #898 to #904.

#898 a Sigma or Suricata text that holds no rule is refused, not accepted (pattern_check).
#899 the YAML that synth_sigma writes reloads: U+2028, U+2029 and U+0085 become spaces, and
     the control characters YAML refuses are dropped.
#900 a `www.` host in a Sigma rule gives the same domain atom as the bare host.
#901 refanging handles `[://]`, `h[tt]ps` and the dot that a defanged `@.` leaves behind.
#902 a CVE id written with underscores is an observable, and matches rule text in both spellings.
#903 a trailing dot on a domain, and the long registry hive names, classify as the short ones.
#904 a numeric or a string `tags:` no longer drops the rule or its technique.
"""
from pathlib import Path

import pytest
import yaml

from pipeline.detection.artifacts import _contains
from pipeline.detection.atoms import extract_atoms
from pipeline.detection.control import DISCRIMINATING, UBIQUITOUS, discrimination
from pipeline.detection.observables import Observable, observables_from_entities
from pipeline.detection.pattern_check import ACCEPTED, REFUSED, check_pattern
from pipeline.detection.relevance import _text_matches, _text_rule_ids
from pipeline.detection.sigma import SigmaAdapter
from pipeline.detection.synth_sigma import _yaml_scalar, synthesize_sigma

pytest.importorskip("sigma")
pytest.importorskip("parsuricata")

_SIGMA_RULE = """title: Suspicious PowerShell Download
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: DownloadString
    condition: selection
level: high"""

# A text with no rule in it.  Each one used to be ACCEPTED by the Sigma parser,
# and the Suricata one too for a comment.
_NO_RULE = {
    "a comment": "# just a comment\n",
    "an action: global block": "action: global\nname: Collection\n",
}


# ── #898 a text with no rule is refused ──────────────────────────────────────

@pytest.mark.parametrize("pattern_type", ["sigma", "suricata", "snort"])
@pytest.mark.parametrize("text", list(_NO_RULE.values()), ids=list(_NO_RULE))
def test_text_with_no_rule_is_refused_issue_898(pattern_type, text):
    status, error = check_pattern(pattern_type, text)
    assert status == REFUSED
    assert error


def test_a_real_sigma_rule_is_still_accepted_issue_898():
    # Control: the empty-collection check does not catch a rule.
    assert check_pattern("sigma", _SIGMA_RULE) == (ACCEPTED, None)


# ── #899 the YAML written by synth_sigma reloads ─────────────────────────────

def test_yaml_scalar_turns_unicode_line_breaks_into_spaces_issue_899():
    assert yaml.safe_load("v: " + _yaml_scalar("a\u2028b\u2029c\x85d")) == {"v": "a b c d"}


def test_yaml_scalar_drops_the_control_characters_yaml_refuses_issue_899():
    assert yaml.safe_load("v: " + _yaml_scalar("a\x0cb\x00c\x1bd")) == {"v": "abcd"}


def test_a_synthesized_rule_with_control_characters_reloads_issue_899():
    obs = [Observable("domain", "evil.com", "domain", "evil.com\u2028x\x0c")]
    (rule,) = synthesize_sigma(obs, job_id="job-899", report_title="Report\u2028one")
    doc = yaml.safe_load(rule.yaml_text)
    assert doc["title"] == "Report IoC — DNS query (Report one)"
    assert "Source observables: evil.com x" in doc["description"]


# ── #900 www. is dropped from a Sigma domain atom ────────────────────────────

@pytest.mark.parametrize("hostname", ["www.evil.com", "*.www.evil.com"])
def test_a_www_host_gives_the_bare_domain_atom_issue_900(hostname):
    doc = {"detection": {"sel": {"DestinationHostname": hostname}, "condition": "sel"}}
    assert extract_atoms(doc) == [("domain", "evil.com")]


# ── #901 refanging ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", ["hxxps[://]evil[.]com/a", "h[tt]ps://evil.com/a"])
def test_a_refanged_scheme_gives_the_live_url_issue_901(raw):
    obs = observables_from_entities([{"value": raw, "entity_type": "url"}])
    assert ("url", "https://evil.com/a") in [(o.obs_class, o.value) for o in obs]


def test_an_email_with_a_defanged_dot_after_the_at_issue_901():
    obs = observables_from_entities([{"value": "me@[.]evil[.]com", "entity_type": "email"}])
    assert [(o.obs_class, o.value) for o in obs] == [("domain", "evil.com")]


# ── #902 CVE ids written with underscores ────────────────────────────────────

def test_a_cve_id_written_with_underscores_is_an_observable_issue_902():
    obs = observables_from_entities([{"value": "CVE_2024_3400", "entity_type": "cve"}])
    assert [(o.obs_class, o.value) for o in obs] == [("cve", "cve-2024-3400")]


def test_the_cve_boundary_holds_for_both_spellings_issue_902():
    assert _contains("cve", "cve-2024-3400", "pan-os cve_2024_3400 exploit")
    assert _contains("cve", "cve-2024-3400", "pan-os cve-2024-3400 exploit")
    assert not _contains("cve", "cve-2024-3400", "exploit cve_2024_34000")
    assert not _contains("cve", "cve-2024-3400", "exploit cve_2024_3401")


def test_a_rule_title_with_the_underscore_cve_is_text_evidence_issue_902():
    obs = [Observable("cve", "cve-2024-3400", "cve", "CVE-2024-3400")]
    hits = _text_matches(obs, {"r1": {"title": "PAN-OS CVE_2024_3400 exploit", "description": ""}})
    assert set(hits) == {"r1"}


def test_the_rule_store_finds_the_underscore_cve_title_issue_902(temp_db):
    conn = temp_db.get_rule_conn()
    conn.execute(
        "INSERT INTO detection_rules (id, corpus, native_key, title, description, is_canonical) "
        "VALUES (?,?,?,?,?,1)",
        ("r1", "test", "r1", "PAN-OS CVE_2024_3400 exploit", ""),
    )
    conn.commit()
    obs = [Observable("cve", "cve-2024-3400", "cve", "CVE-2024-3400")]
    assert _text_rule_ids(conn, obs) == {"r1"}


# ── #903 trailing dot and long hive names ────────────────────────────────────

@pytest.mark.parametrize("obs_class, value", [
    ("domain", "gmail.com."),
    ("domain", "mail.gmail.com.:443"),
    ("url", "https://gmail.com./inbox"),
])
def test_a_trailing_dot_host_is_classified_as_its_name_issue_903(obs_class, value):
    assert discrimination(obs_class, value) == UBIQUITOUS


def test_a_trailing_dot_on_an_unknown_host_stays_discriminating_issue_903():
    assert discrimination("domain", "evil-c2.net.") == DISCRIMINATING


@pytest.mark.parametrize("hive", ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"])
def test_a_long_hive_name_is_the_same_registry_key_issue_903(hive):
    key = f"{hive}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"
    assert discrimination("registry", key) == UBIQUITOUS


def test_an_unknown_long_hive_key_stays_discriminating_issue_903():
    assert discrimination("registry", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil\\Run\\x") == DISCRIMINATING


# ── #904 `tags:` that is not a list of strings ───────────────────────────────

def test_a_numeric_tags_value_keeps_the_rule_issue_904(tmp_path: Path):
    (tmp_path / "rule.yml").write_text(_SIGMA_RULE.replace("logsource:", "tags: 5\nlogsource:"),
                                       encoding="utf-8")
    rules = list(SigmaAdapter().parse(tmp_path, corpus="core"))
    assert [r.title for r in rules] == ["Suspicious PowerShell Download"]


def test_a_string_tag_is_one_technique_issue_904(tmp_path: Path):
    (tmp_path / "rule.yml").write_text(
        _SIGMA_RULE.replace("logsource:", "tags: attack.t1059.001\nlogsource:"), encoding="utf-8")
    (rule,) = SigmaAdapter().parse(tmp_path, corpus="core")
    assert rule.technique_ids == ["T1059.001"]


def test_a_string_tag_split_gives_a_technique_and_no_tactic_issue_904():
    assert SigmaAdapter._split_tags("attack.t1059.001") == (["T1059.001"], [])
