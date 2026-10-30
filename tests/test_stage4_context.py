"""Stage 4 writes its context into the bundle (ADR-0093).

Each relationship says why it exists and carries the sentence the report quotes
for it in `x_evidence_text`.  The Report carries its source document: a Markdown
description (the file's facts, the count of each object type, the text) and the
file itself in `x_opencti_files`.  A named object the report never describes
gets the report's own sentences about it.
"""
from __future__ import annotations

import base64
import hashlib

from models.schemas import EntityType, RawEntity
from pipeline import baseline_stix as bs
from pipeline import stage4_stix_mapping
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle
from tests.test_stage4_baseline import MALWARE_ID, REPORT_ID, _baseline, _fake_merge

QUOTE = "APT29 used WellMess between November 2022 and March 2023."
REPORT_TEXT = f"{QUOTE} WellMess is a backdoor. The group targets France."
SOURCE = b"%PDF-1.4 the original report"
SHA256 = hashlib.sha256(SOURCE).hexdigest()


def _llm() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        targeted_countries=["France"],
        relationships=[RelationshipExtracted(
            source_value="APT29", relationship_type="uses", target_value="WellMess",
            confidence=0.9, evidence_text=QUOTE)],
    )


def _of(bundle, stix_type):
    return [o for o in bundle.objects if o.type == stix_type]


def test_every_relationship_says_why_it_exists():
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT)
    rels = _of(bundle, "relationship")
    assert rels and all(r.description.strip() for r in rels)

    uses = next(r for r in rels if r.relationship_type == "uses")
    assert uses.x_evidence_text == QUOTE
    assert f"> {QUOTE}" in uses.description and "**Why:**" in uses.description
    assert "**APT29** `uses` **WellMess**" in uses.description
    assert "**Confidence:** 90/100" in uses.description

    targets = next(r for r in rels if r.relationship_type == "targets")
    assert "CTIParsor links every threat actor" in targets.description


def test_the_report_carries_its_source_as_text_and_as_a_file():
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT,
                               original_filename="apt.pdf", source_hash=SHA256, source_bytes=SOURCE)
    (report,) = _of(bundle, "report")
    (entry,) = report["x_opencti_files"]
    assert entry["name"] == "apt.pdf" and entry["mime_type"] == "application/pdf"
    assert entry["no_trigger_import"] is True
    assert base64.b64decode(entry["data"]) == SOURCE

    assert report.description.startswith("## Source document")
    assert f"- **SHA-256:** `{SHA256}`" in report.description
    assert "- **Attached:** the original file is attached to this report." in report.description
    assert "## Document text" in report.description and REPORT_TEXT in report.description

    (artifact,) = _of(bundle, "artifact")
    assert artifact.payload_bin == base64.b64encode(SOURCE).decode("ascii")


def test_without_the_source_file_the_report_attaches_nothing():
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT)
    (report,) = _of(bundle, "report")
    assert "x_opencti_files" not in report
    assert "Attached" not in report.description


def test_a_named_object_the_report_never_describes_quotes_the_report():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WellMess", "SUNBURST"])
    bundle = build_stix_bundle([], llm, "APT29 report", report_text=REPORT_TEXT)
    malware = {m.name: m for m in _of(bundle, "malware")}
    assert malware["WellMess"].description.startswith("Mentioned in *APT29 report*:")
    assert "WellMess is a backdoor." in malware["WellMess"].description
    assert "description" not in malware["SUNBURST"]
    (actor,) = _of(bundle, "threat-actor")
    assert actor.description.startswith("Mentioned in *APT29 report*:")


def test_a_vulnerability_keeps_the_description_from_its_cve_record():
    text = f"{REPORT_TEXT} The group exploits CVE-2023-23397."
    meta = {"CVE-2023-23397": {"description": "Outlook elevation of privilege.",
                               "cvss_score": 9.8, "cvss_vector": None}}
    bundle = build_stix_bundle([RawEntity(value="CVE-2023-23397", entity_type=EntityType.CVE)],
                               _llm(), "APT29 report", report_text=text, cve_metadata=meta)
    (vuln,) = _of(bundle, "vulnerability")
    assert vuln.description == "Outlook elevation of privilege."


def test_a_relationship_without_its_description_still_ships(monkeypatch, caplog):
    def refuse(*args, **kwargs):
        raise RuntimeError("no justification today")

    monkeypatch.setattr(stage4_stix_mapping, "justify", refuse)
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT)
    uses = next(r for r in _of(bundle, "relationship") if r.relationship_type == "uses")
    assert "description" not in uses and uses.x_evidence_text == QUOTE
    assert "no context written" in caplog.text


def test_the_reissued_report_keeps_its_description_and_gets_the_source_file(monkeypatch):
    monkeypatch.setattr(bs, "merge_baseline", _fake_merge)
    baseline = _baseline()
    baseline.objects[REPORT_ID]["description"] = "The description the baseline holds."
    # The kept malware is named in the text: it ships as the baseline holds it, with no description added.
    bundle = build_stix_bundle([], _llm(), "APT29 report",
                               report_text=f"{REPORT_TEXT} Kept Baseline Malware ran too.",
                               original_filename="apt.pdf", source_hash=SHA256, source_bytes=SOURCE,
                               baseline=baseline)
    (report,) = _of(bundle, "report")
    assert report.id == REPORT_ID
    assert report.description == "The description the baseline holds."
    (entry,) = report["x_opencti_files"]
    assert entry["name"] == "apt.pdf" and base64.b64decode(entry["data"]) == SOURCE
    assert baseline.verbatim[REPORT_ID]["x_opencti_files"] == [entry]
    assert MALWARE_ID in report.object_refs
    (kept,) = [o for o in bundle.objects if o.id == MALWARE_ID]
    assert kept.name == "Kept Baseline Malware" and "description" not in kept


def test_the_reissued_report_does_not_attach_a_second_file_of_the_same_name(monkeypatch):
    monkeypatch.setattr(bs, "merge_baseline", _fake_merge)
    baseline = _baseline()
    exported = {"name": "apt.pdf", "data": "AAAA", "mime_type": "application/pdf",
                "no_trigger_import": True}
    baseline.objects[REPORT_ID]["x_opencti_files"] = [exported]
    ledger = MappingLedger()
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT, ledger=ledger,
                               original_filename="apt.pdf", source_hash=SHA256, source_bytes=SOURCE,
                               baseline=baseline)
    (report,) = _of(bundle, "report")
    assert report["x_opencti_files"] == [exported]
    entry = ledger.to_dict()["objects"][REPORT_ID]
    assert entry["origin"] == "baseline_report_upsert" and "attached_file" not in entry


def test_the_ledger_says_the_reissued_report_attached_the_source_file(monkeypatch):
    monkeypatch.setattr(bs, "merge_baseline", _fake_merge)
    ledger = MappingLedger()
    build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT, ledger=ledger,
                      original_filename="apt.pdf", source_hash=SHA256, source_bytes=SOURCE,
                      baseline=_baseline())
    entry = ledger.to_dict()["objects"][REPORT_ID]
    assert entry["origin"] == "baseline_report_upsert" and entry["attached_file"] == "apt.pdf"


def test_when_the_names_fail_no_relationship_or_object_gets_a_description(monkeypatch, caplog):
    normal = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT)

    def no_names(stix_objects):
        raise RuntimeError("no names today")

    monkeypatch.setattr(stage4_stix_mapping, "_display_names", no_names)
    bundle = build_stix_bundle([], _llm(), "APT29 report", report_text=REPORT_TEXT)

    def triples(built):
        return sorted((r.relationship_type, r.source_ref, r.target_ref) for r in _of(built, "relationship"))

    assert triples(bundle) and triples(bundle) == triples(normal)
    assert all("description" not in r for r in _of(bundle, "relationship"))
    for obj in bundle.objects:
        text = obj.get("description", "")
        assert "Mentioned in" not in text
        assert "threat-actor--" not in text and "malware--" not in text
    assert "no context written" in caplog.text


def test_a_name_that_is_also_an_ordinary_word_is_quoted_only_where_it_has_its_capital():
    text = "The group went into silence for a month. Silence used a loader."
    bundle = build_stix_bundle([], LLMEnrichmentResult(threat_actors=["Silence"]), "APT report",
                               report_text=text)
    (actor,) = _of(bundle, "threat-actor")
    assert actor.description == "Mentioned in *APT report*:\n\n> Silence used a loader."
