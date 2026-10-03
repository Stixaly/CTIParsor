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
