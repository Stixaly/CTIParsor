"""The mapping ledger keeps every merge an entry went through (issue #416).

An entity that Stage 4b's alias merge resolved, and that the baseline merge then
matched, says both: `reason` is the last merge (what the Baseline panel reads),
`merged_via` the merges before it (ADR-0061).  A relationship a merge removed
points at the objects that replaced its ends, as the refused edges do.
"""
from types import SimpleNamespace

from pipeline.bundle_ledger import MappingLedger


def _baseline(remap, removed=()):
    return SimpleNamespace(remap=remap, removed_relationships=list(removed),
                           remapped_relationships={}, dropped={})


def _entity(led, value, obj_id):
    led.entity(value, "intrusion-set", "emitted",
               obj=SimpleNamespace(id=obj_id, type="intrusion-set", name=value))


def _sro(led, sro_id, source_ref, target_ref):
    rel = SimpleNamespace(source_value="APT29", relationship_type="uses", target_value="WINELOADER")
    led.relationship(rel, "emitted", stix_id=sro_id, source_ref=source_ref, target_ref=target_ref)


def test_alias_merge_then_baseline_match_keeps_the_alias_merge_issue_416():
    led = MappingLedger()
    _entity(led, "APT29", "intrusion-set--dup")
    led.apply_alias_merge({"intrusion-set--dup": "intrusion-set--canon"}, [], {})
    led.apply_baseline_merge(_baseline({"intrusion-set--canon": "intrusion-set--base"}))
    led.baseline_object(SimpleNamespace(id="intrusion-set--base"), status="matched")

    (e,) = led.to_dict()["entities"]
    assert e["outcome"] == "merged"
    assert e["stix_id"] == "intrusion-set--base"
    assert e["reason"] == "baseline_match"
    assert e["merged_via"] == ["alias_merge"]


def test_an_entity_merged_once_has_no_merged_via_issue_416():
    """Control: one merge, one reason, and no key the existing ledgers lack."""
    led = MappingLedger()
    _entity(led, "APT29", "intrusion-set--dup")
    led.apply_alias_merge({"intrusion-set--dup": "intrusion-set--canon"}, [], {})
    (e,) = led.to_dict()["entities"]
    assert e["reason"] == "alias_merge" and "merged_via" not in e

    led = MappingLedger()
    _entity(led, "APT29", "intrusion-set--base")
    led.baseline_object(SimpleNamespace(id="intrusion-set--base"), status="matched")
    (e,) = led.to_dict()["entities"]
    assert e["reason"] == "baseline_match" and "merged_via" not in e


def test_a_removed_relationship_follows_the_alias_merge_issue_416():
    led = MappingLedger()
    _sro(led, "relationship--a", "intrusion-set--dup", "malware--m")
    led.apply_alias_merge({"intrusion-set--dup": "intrusion-set--canon"},
                          [{"id": "relationship--a", "reason": "duplicate_after_alias_merge",
                            "kept": "relationship--k"}], {})
    (e,) = led.to_dict()["relationships"]
    assert e["outcome"] == "merged" and e["merged_with"] == "relationship--k"
    assert e["source_ref"] == "intrusion-set--canon"
    assert e["target_ref"] == "malware--m"


def test_a_removed_relationship_follows_the_baseline_merge_issue_416():
    led = MappingLedger()
    _sro(led, "relationship--a", "intrusion-set--canon", "malware--m")
    led.apply_baseline_merge(_baseline(
        {"intrusion-set--canon": "intrusion-set--base"},
        removed=[{"id": "relationship--a", "reason": "duplicate_after_baseline_merge",
                  "kept": "relationship--k"}]))
    (e,) = led.to_dict()["relationships"]
    assert e["outcome"] == "merged" and e["merged_with"] == "relationship--k"
    assert e["source_ref"] == "intrusion-set--base"
    assert e["target_ref"] == "malware--m"
