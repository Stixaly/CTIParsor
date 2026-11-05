"""scripts/audit_bundle_invariants.py: indicators whose pattern is a detection
rule (YARA, Sigma, Suricata, Snort — ADR-0067/0070, and an analyst's bundle,
ADR-0090) are not STIX patterns, and are not audited as such."""
from __future__ import annotations

from scripts import audit_bundle_invariants as audit


def _bundle(*indicators: dict) -> list[tuple[str, dict]]:
    objects = [{"type": "indicator", "id": f"indicator--{i}", "valid_from": "2026-10-25T00:00:00Z", **ind}
               for i, ind in enumerate(indicators)]
    return [("job", {"type": "bundle", "id": "bundle--1", "objects": objects})]


def test_a_detection_rule_is_neither_a_malformed_pattern_nor_a_bad_pattern_type():
    bundles = _bundle({"pattern_type": "yara", "pattern": "rule X { condition: true }"},
                      {"pattern_type": "sigma", "pattern": "title: X\ndetection:\n  condition: sel"},
                      {"pattern_type": "suricata", "pattern": 'alert http any any -> any any (sid:1;)'})
    assert audit.check_indicator_pattern_wellformed(bundles).status == "OK"
    assert audit.check_indicator_required_fields(bundles).status == "OK"


def test_a_stix_pattern_is_still_checked_and_an_unknown_type_still_flagged():
    bundles = _bundle({"pattern_type": "stix", "pattern": "file:name = 'x'"},
                      {"pattern_type": "made-up", "pattern": "[file:name = 'x']"})
    assert audit.check_indicator_pattern_wellformed(bundles).count == 1      # the unbracketed STIX pattern
    assert audit.check_indicator_required_fields(bundles).count == 1         # the unknown pattern_type


def test_every_stix_comparison_operator_is_a_comparison():
    # #315: "=" is one operator among several; a "=" inside a string is none.
    good = ["[ipv4-addr:value IN ('1.2.3.4', '2.3.4.5')]", "[file:name MATCHES '^x.*']",
            "[file:name LIKE 'x%']", "[file:size > 10]", "[file:size <= 10]",
            "[ipv4-addr:value ISSUBSET '10.0.0.0/8']", "[file:name != 'x']",
            "[file:name = 'x'] AND [file:size >= 1]"]
    assert audit.check_indicator_pattern_wellformed(
        _bundle(*({"pattern_type": "stix", "pattern": p} for p in good))).status == "OK"
    bad = audit.check_indicator_pattern_wellformed(_bundle({"pattern_type": "stix", "pattern": "[file:name 'a=b']"}))
    assert bad.count == 1 and "no_comparison=1" in bad.detail

