"""Suricata metadata keeps every value, across every `metadata:` option (issue #421).

Before the fix `rule_metadata` overwrote a repeated key and stopped at the first
`metadata:` option, so a rule carried a single ATT&CK technique at most.
"""
from __future__ import annotations

from models.detection import Severity
from pipeline.detection.suricata import SuricataAdapter
from pipeline.detection.suricata_atoms import rule_metadata, technique_ids


def _suricata(tmp_path, *lines: str) -> list:
    (tmp_path / "sub").mkdir(exist_ok=True)
    (tmp_path / "sub" / "emerging.rules").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(SuricataAdapter().parse(tmp_path, corpus="et-open", license="MIT"))


def test_repeated_key_in_one_option_keeps_every_technique_issue_421():
    rule = (
        'alert tcp any any -> any any (msg:"x"; '
        "metadata:mitre_technique_id T1071, mitre_technique_id T1095; sid:1;)"
    )
    assert technique_ids(rule) == ["T1071", "T1095"]
    assert rule_metadata(rule) == {"mitre_technique_id": ["T1071", "T1095"]}


def test_second_metadata_option_is_read_issue_421():
    rule = (
        'alert tcp any any -> any any (msg:"x"; '
        "metadata:created_at 2020_01_01; "
        "metadata:mitre_technique_id T1071; sid:1;)"
    )
    assert technique_ids(rule) == ["T1071"]


def test_key_repeated_across_two_options_is_merged_without_duplicates_issue_421():
    rule = (
        'alert tcp any any -> any any (msg:"x"; '
        "metadata:mitre_technique_id T1071, mitre_technique_id T1095; "
        "metadata:mitre_technique_id t1071, mitre_technique_id T1059.001; sid:1;)"
    )
    assert technique_ids(rule) == ["T1071", "T1095", "T1059.001"]
    # rule_metadata keeps values as written; technique_ids upper-cases and dedups them.
    assert rule_metadata(rule)["mitre_technique_id"] == ["T1071", "T1095", "t1071", "T1059.001"]


def test_rule_without_metadata_has_no_technique_issue_421():
    rule = 'alert tcp any any -> any any (msg:"x"; sid:1;)'
    assert rule_metadata(rule) == {}
    assert technique_ids(rule) == []


def test_single_technique_and_first_signature_severity_still_work_issue_421(tmp_path):
    line = (
        'alert tcp any any -> 8.8.8.8 53 (msg:"x"; '
        "metadata:signature_severity Major, mitre_technique_id T1090; "
        "metadata:signature_severity Minor; sid:2;)"
    )
    assert technique_ids(line) == ["T1090"]
    [rule] = _suricata(tmp_path, line)
    assert rule.technique_ids == ["T1090"]
    assert rule.severity == Severity.HIGH
