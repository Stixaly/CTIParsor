"""Stage 4 never drops an object silently (audit B 8.1.9, ADR-0061).

Three `except Exception: pass` blocks — the Indicators built from IoC
associations, the Indicators built for the remaining IoCs, and the
CourseOfAction SDOs — swallowed a build failure without a ledger entry: the
review graph showed the row, the bundle did not have it, and nothing said why.
"""
from __future__ import annotations

from models.schemas import EntityType, RawEntity
from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult

IP = "185.220.101.45"


def _build(entities=(), llm=None):
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle(list(entities), llm or LLMEnrichmentResult(), "r",
                                  report_text=f"WellMess beaconed to {IP}.", ledger=ledger)
    return bundle, ledger.to_dict()


def _dropped(ledger: dict, value: str) -> list[dict]:
    return [e for e in ledger["entities"] if e["value"] == value and e["outcome"] == "dropped"]


def _boom(*args, **kwargs):
    raise ValueError("pattern refused by the library")


def test_an_indicator_that_fails_to_build_is_in_the_ledger(monkeypatch):
    monkeypatch.setattr(s4.stix2, "Indicator", _boom)
    bundle, ledger = _build([RawEntity(value=IP, entity_type=EntityType.IPV4)])
    assert not [o for o in bundle.objects if o["type"] == "indicator"]
    [entry] = _dropped(ledger, IP)
    assert entry["reason"] == "build_failed"
    assert entry["entity_type"] == "indicator" and entry["input"] == "ipv4"
    assert "pattern refused" in entry["error"]


def test_an_association_indicator_that_fails_to_build_is_in_the_ledger(monkeypatch):
    monkeypatch.setattr(s4.stix2, "Indicator", _boom)
    llm = LLMEnrichmentResult(malware_families=["WellMess"],
                              ioc_associations=[IoCAssociation(ioc_value=IP, malware_name="WellMess")])
    bundle, ledger = _build([RawEntity(value=IP, entity_type=EntityType.IPV4)], llm)
    assert not [o for o in bundle.objects if o["type"] == "indicator"]
    entries = _dropped(ledger, IP)
    assert entries and all(e["reason"] == "build_failed" for e in entries)
    assert any(e.get("input") == "ioc_association" and e.get("malware_name") == "WellMess" for e in entries)


def test_a_course_of_action_that_fails_to_build_is_in_the_ledger(monkeypatch):
    monkeypatch.setattr(s4.stix2, "CourseOfAction", _boom)
    bundle, ledger = _build(llm=LLMEnrichmentResult(course_of_action=["Enable MFA everywhere"]))
    assert not [o for o in bundle.objects if o["type"] == "course-of-action"]
    [entry] = _dropped(ledger, "Enable MFA everywhere")
    assert entry["reason"] == "build_failed" and entry["entity_type"] == "course-of-action"
    assert "pattern refused" in entry["error"]


def test_nothing_is_recorded_when_everything_builds():
    bundle, ledger = _build([RawEntity(value=IP, entity_type=EntityType.IPV4)],
                            LLMEnrichmentResult(course_of_action=["Enable MFA"]))
    assert [o for o in bundle.objects if o["type"] == "indicator"]
    assert [o for o in bundle.objects if o["type"] == "course-of-action"]
    assert not [e for e in ledger["entities"] if e.get("reason") == "build_failed"]


def test_an_actor_named_after_a_malware_keeps_its_name_and_says_so():
    """Audit B 8.1.8: OpenCTI derives the id from type and name, so renaming the
    actor "LockBit 3.0" created a threat-actor beside the malware."""
    bundle, ledger = _build(llm=LLMEnrichmentResult(threat_actors=["LockBit Black"]))
    [actor] = [o for o in bundle.objects if o["type"] == "threat-actor"]
    assert actor["name"] == "LockBit Black"
    [entry] = [e for e in ledger["entities"] if e["value"] == "LockBit Black"]
    assert entry["outcome"] == "emitted" and entry["reason"] == "type_conflict"
    assert entry["mitre_ids"] == ["S1202"] and entry["mitre_types"] == ["malware"]


# ── The fallbacks that returned without a word (8.1.9, continued) ────────────

def test_an_embedded_rule_that_fails_to_build_is_left_out_with_its_reason(monkeypatch):
    monkeypatch.setattr(s4.stix2, "Indicator", _boom)
    ledger = MappingLedger()
    objects: list = []
    s4._add_embedded_rule_indicator(
        objects, {}, set(), pattern_type="yara", pattern="rule Emotet_Loader { condition: true }",
        title="Emotet_Loader", llm_result=LLMEnrichmentResult(), pol_index=None,
        seen_rel_keys=set(), ledger=ledger,
    )
    assert objects == []
    [entry] = ledger.to_dict()["removed"]
    assert entry["reason"] == "build_failed" and entry["name"] == "Yara rule: Emotet_Loader"
    assert "pattern refused" in entry["error"]


def test_a_source_file_that_cannot_be_embedded_is_in_the_ledger(monkeypatch):
    monkeypatch.setattr(s4.stix2, "Artifact", _boom)
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle([], LLMEnrichmentResult(), "r", report_text="text",
                                  original_filename="apt.pdf", source_bytes=b"%PDF-1.7",
                                  ledger=ledger)
    assert not [o for o in bundle.objects if o["type"] == "artifact"]
    [entry] = _dropped(ledger.to_dict(), "apt.pdf")
    assert entry["reason"] == "build_failed" and entry["input"] == "source_artifact"
    assert "pattern refused" in entry["error"]


def test_a_report_rebuilt_without_its_optional_fields_says_which(monkeypatch):
    real_report = s4.stix2.Report

    def only_required(**kwargs):
        if set(kwargs) - {"name", "published", "object_refs"}:
            raise ValueError("an optional field is refused")
        return real_report(**kwargs)

    monkeypatch.setattr(s4.stix2, "Report", only_required)
    ledger = MappingLedger()
    bundle = s4.build_stix_bundle([], LLMEnrichmentResult(threat_actors=["APT29"]), "r",
                                  report_text="APT29 did it.", ledger=ledger)
    [report] = [o for o in bundle.objects if o["type"] == "report"]
    entry = ledger.to_dict()["objects"][report.id]
    assert entry["origin"] == "report" and entry["fallback"] == "optional_fields_dropped"
    assert "an optional field is refused" in entry["error"]
    assert entry["dropped_fields"]          # what the bundle lost is named
