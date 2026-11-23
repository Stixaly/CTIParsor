"""Stage 4 writes what it leaves out of the bundle to the mapping ledger (#997,
ADR-0061): a Sigma rule the report states and the bundle does not carry, and a
relationship stix2 refuses.  A rule that ships, and a build without these,
change nothing."""
import stix2

from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage4_stix_mapping import build_stix_bundle

_PIN_POLICY = {
    "version": 1,
    "global": "enforce",
    "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware",
               "mode": "pin", "enabled": True}],
}


def _sigma_rule(title: str) -> str:
    return (
        f"title: {title}\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        CommandLine|contains: DownloadString\n"
        "    condition: selection\n"
        "level: high\n"
    )


def _dropped_entities(led: MappingLedger) -> list[dict]:
    return [e for e in led.to_dict()["entities"] if e["outcome"] == "dropped"]


def _refuse_every_relationship(monkeypatch) -> None:
    def refuse(**kwargs):
        raise ValueError("relationship refused by the test")

    monkeypatch.setattr(stix2, "Relationship", refuse)


def test_a_sigma_rule_whose_end_is_outside_the_window_is_dropped_in_the_ledger():
    # The rule never ends inside the 200,000-character window: its end is unknown.
    report_text = "title: Endless Rule\ndetection:\n  sel: x\n" + "  - line\n" * 30_000
    led = MappingLedger()
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text, ledger=led)

    assert _dropped_entities(led) == [{
        "value": "Endless Rule", "entity_type": "indicator", "outcome": "dropped",
        "reason": "sigma_rule_end_not_found", "pattern_type": "sigma",
    }]
    assert not any(o.get("type") == "indicator" for o in bundle.objects)


def test_a_sigma_rule_with_invalid_yaml_is_dropped_in_the_ledger():
    # No reduction of the candidate parses with both title and detection.
    report_text = ("Some prose.\n\ntitle: Broken Rule\nlogsource: [unclosed\n"
                   "detection:\n  selection: [also unclosed\n\nMore prose.")
    led = MappingLedger()
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=report_text, ledger=led)

    assert _dropped_entities(led) == [{
        "value": "Broken Rule", "entity_type": "indicator", "outcome": "dropped",
        "reason": "sigma_rule_invalid_yaml", "pattern_type": "sigma",
    }]
    assert not any(o.get("type") == "indicator" for o in bundle.objects)


def test_a_valid_sigma_rule_ships_and_is_not_dropped():
    led = MappingLedger()
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r",
                               report_text="Prose.\n\n" + _sigma_rule("Valid Rule") + "\nMore prose.",
                               ledger=led)

    indicators = [o for o in bundle.objects if o.get("type") == "indicator" and o.get("pattern_type") == "sigma"]
    assert [o.name for o in indicators] == ["Sigma rule: Valid Rule"]
    assert _dropped_entities(led) == []
    assert led.objects[indicators[0].id]["origin"] == "embedded_rule"


def test_a_relationship_stix2_refuses_is_dropped_in_the_ledger(monkeypatch):
    # The Sigma rule's title names the malware, so its `indicates` edge is built
    # from the rule, not from a job-store row, and that is the edge stix2 refuses.
    _refuse_every_relationship(monkeypatch)
    llm = LLMEnrichmentResult(malware_families=["Emotet"])
    led = MappingLedger()
    bundle = build_stix_bundle([], llm, "r", report_text=_sigma_rule("Emotet dropper"), ledger=led)

    assert not any(o.get("type") == "relationship" for o in bundle.objects)
    (entry,) = [e for e in led.to_dict()["relationships"] if e["outcome"] == "dropped"]
    assert entry["reason"] == "stix2_refused"
    assert entry["relationship_type"] == "indicates"
    assert entry["source_value"] == "Sigma rule: Emotet dropper"
    assert entry["target_value"] == "Emotet"
    assert entry["detail"].startswith("relationship refused by the test")
    assert entry["changes"] == []          # nothing was rewritten


def test_a_pinned_edge_stix2_refuses_is_ledgered_and_not_also_counted_as_truncated(monkeypatch):
    _refuse_every_relationship(monkeypatch)
    actor = stix2.ThreatActor(name="APT29")
    malware = stix2.Malware(name="WINELOADER", is_family=True)
    objects = [actor, malware]
    led = MappingLedger()

    stats = s4._materialise_pinned_edges(objects, _PIN_POLICY, set(), "", ledger=led)

    (rule,) = stats.rules
    assert (rule.candidates, rule.emitted, rule.truncated) == (1, 0, 0)
    (entry,) = led.to_dict()["relationships"]
    assert entry["outcome"] == "dropped"
    assert entry["reason"] == "stix2_refused"
    assert entry["relationship_type"] == "uses"
    assert entry["source_value"] == "APT29"
    assert entry["target_value"] == "WINELOADER"


def test_a_context_that_cannot_be_written_is_noted_on_its_object():
    malware = stix2.Malware(name="WINELOADER", is_family=True)
    led = MappingLedger()
    led.object(malware, "entity")

    def describe(d: dict) -> None:
        raise RuntimeError("no names")

    author = s4._authoring_identity()
    stamped = s4._stamp_objects([malware], author.id, [], describe=describe, ledger=led)

    assert [o.id for o in stamped] == [malware.id]
    assert led.objects[malware.id] == {"origin": "entity", "stamp_failed": "RuntimeError: no names"}


def test_a_title_line_in_prose_is_not_a_dropped_rule():
    """A `title:` line with no `detection:` block is a word, not a rule given up on."""
    from pipeline.stage4_stix_mapping import _scan_embedded_sigma_rules

    rules, skipped = _scan_embedded_sigma_rules("Report\ntitle: Quarterly threat review\nThe actor used X.\n")
    assert (rules, skipped) == ([], [])
