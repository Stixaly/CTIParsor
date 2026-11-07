"""The mapping ledger reads STIX objects given as dicts, and keeps the reason of a
relationship that an alias or baseline merge absorbed (issues #504, #505).

Stage 4 hands the ledger stix2 objects, but a dict is a STIX object too (the
baseline's objects, the job store's rows): every accessor goes through
`stix_access.field`, as the rest of the module does.
"""
from collections import namedtuple
from types import SimpleNamespace

from pipeline.bundle_ledger import MappingLedger

DummyRel = namedtuple("DummyRel", ["source_value", "relationship_type", "target_value"])


def _baseline(remap, removed=()):
    return SimpleNamespace(remap=remap, removed_relationships=list(removed),
                           remapped_relationships={}, dropped={})


def test_an_entity_given_as_a_dict_is_recorded_with_its_stix_id_issue_504():
    led = MappingLedger()
    led.entity("Emotet", "malware", "emitted",
               obj={"id": "malware--1", "type": "malware", "name": "Emotet"})

    (e,) = led.to_dict()["entities"]
    assert e["stix_id"] == "malware--1"
    assert e["stix_type"] == "malware"
    assert e["stix_name"] == "Emotet"


def test_an_object_given_as_a_dict_is_recorded_with_its_origin_issue_504():
    led = MappingLedger()
    led.object({"id": "malware--1", "type": "malware"}, "entity")
    led.baseline_object({"id": "intrusion-set--2", "type": "intrusion-set"}, status="matched")

    assert led.objects["malware--1"] == {"origin": "entity"}
    assert led.objects["intrusion-set--2"]["origin"] == "baseline"


def test_an_sro_given_as_a_dict_is_classified_and_listed_outside_the_report_issue_504():
    led = MappingLedger()
    sro = {"id": "relationship--1", "type": "relationship", "x_inference_rule": "long-distance"}
    led.finalize([sro])
    led.outside_report({"id": "relationship--2", "type": "relationship"})

    assert led.objects["relationship--1"] == {"origin": "completion_long_distance"}
    assert led.objects["relationship--2"] == {"origin": "unknown", "outside_report": True}


def test_a_replaced_relationship_given_as_a_dict_is_followed_issue_504():
    led = MappingLedger()
    entry = led.relationship(DummyRel("s", "uses", "t"), "emitted")
    entry["stix_id"] = "relationship--old"
    led.object({"id": "relationship--old", "type": "relationship"}, "extracted")
    led.replace_relationship("relationship--old", {"id": "relationship--new", "type": "relationship"})

    assert entry["stix_id"] == "relationship--new"
    assert entry["merged_with"] == "relationship--new"
    assert led.objects["relationship--new"] == {"origin": "extracted"}


def test_alias_merge_keeps_the_reason_of_an_absorbed_relationship_issue_505():
    led = MappingLedger()
    entry = led.relationship(DummyRel("s", "uses", "t"), "emitted")
    entry["stix_id"] = "relationship--1"
    led.apply_alias_merge({}, [{"id": "relationship--1", "reason": "duplicate_after_alias_merge",
                                "kept": "relationship--2"}], {})

    assert entry["outcome"] == "merged"
    assert entry["merged_with"] == "relationship--2"
    assert entry["reason"] == "duplicate_after_alias_merge"
    assert "merged_via" not in entry


def test_baseline_merge_after_alias_merge_keeps_both_reasons_issue_505():
    led = MappingLedger()
    entry = led.relationship(DummyRel("s", "uses", "t"), "emitted")
    entry["stix_id"] = "relationship--1"
    led.apply_alias_merge({}, [{"id": "relationship--1", "reason": "duplicate_after_alias_merge",
                                "kept": "relationship--2"}], {})
    led.apply_baseline_merge(_baseline({}, removed=[{"id": "relationship--2",
                                                     "reason": "duplicate_after_baseline_merge",
                                                     "kept": "relationship--3"}]))

    assert entry["merged_with"] == "relationship--3"
    assert entry["reason"] == "baseline_match"
    assert entry["merged_via"] == ["duplicate_after_alias_merge"]


def test_baseline_merge_absorbs_a_relationship_with_its_reason_issue_505():
    led = MappingLedger()
    entry = led.relationship(DummyRel("s", "uses", "t"), "emitted")
    entry["stix_id"] = "relationship--1"
    led.apply_baseline_merge(_baseline({}, removed=[{"id": "relationship--1",
                                                     "reason": "duplicate_after_baseline_merge",
                                                     "kept": "relationship--2"}]))

    assert entry["outcome"] == "merged"
    assert entry["merged_with"] == "relationship--2"
    assert entry["reason"] == "baseline_match"
    assert "merged_via" not in entry
