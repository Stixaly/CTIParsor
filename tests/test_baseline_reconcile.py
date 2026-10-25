"""Stage 3r (ADR-0090 lot 3): `reconcile` matches a run's extractions to a baseline.

The index is the lot-0 fixture opencti_report.json, read by `intake`; the text is
opencti_report.txt.  The text names Cozy Bear (an alias of APT29) and the file's
SHA-256; SUNBURST and T1566.001 are new to the baseline.  The IPv4 address, WellMess
and PowerShell (T1059.001) are in the baseline and not in the text.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from models.schemas import EntityType, RawEntity
from pipeline import baseline_stix as bs
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, RelationshipReview, TTPExtracted
from pipeline.stage3f_ttp_select import TtpReview

BASELINES = Path(__file__).parent / "fixtures" / "baselines"
REPORT = (BASELINES / "opencti_report.txt").read_text(encoding="utf-8")
SHA256 = "9f2b6c1d4a7e3085b1d6f4e2a9c37d58e0b4a1f6c2d93e7a5b80c4d1f6e3a972"
# The entry and relation ids of the fixture (an observable's entry is its SCO).
APT29 = "intrusion-set--4f4f0eaf-960c-43f3-9319-4fb9a8d3ae7c"
WELLMESS = "malware--ce12e6b1-5ad7-4fc6-a2ed-2a3ca268a445"
POWERSHELL = "attack-pattern--7d05d478-43c5-4a43-8e80-ca34d16324f6"
IPV4 = "ipv4-addr--dac4ca46-8fa0-52fb-94df-2a9acd2636bf"
FILE = "file--c7abdbaa-36f3-531e-8ce2-78743f8252dd"
USES = "relationship--fd3e7a73-f3b2-485d-a28b-111fadd6bea1"
INDICATES = "relationship--75b18d1d-5f66-4989-a19f-33ebd8c660f6"


@pytest.fixture(scope="module")
def index() -> bs.BaselineIndex:
    baseline, _, _ = bs.intake((BASELINES / "opencti_report.json").read_bytes(), validate=False)
    assert baseline is not None
    return baseline


def _raw(value: str, entity_type: str) -> RawEntity:
    return RawEntity(value=value, entity_type=EntityType(entity_type))


def _imported(rec: bs.Reconciliation) -> dict[str, bs.ImportedEntity]:
    return {row.baseline_stix_id: row for row in rec.imported_entities}


def _entry(entry_id: str, stix_type: str, entity_type: str, value: str,
           keys: tuple = (), forms: tuple = ()) -> bs.Entry:
    return bs.Entry(entry_id, stix_type, entity_type, value, None, frozenset(keys), frozenset(),
                    surface_forms=tuple(forms))


def _index(*entries: bs.Entry, relations: tuple[bs.Relation, ...] = ()) -> bs.BaselineIndex:
    return bs.BaselineIndex(version=bs.INDEX_VERSION, sha256="", bundle_id="", entries=list(entries),
                            relations=list(relations), imported_ids=frozenset(), passthrough_ids=frozenset(),
                            report_ids=())


def test_a_threat_actor_named_by_an_alias_is_matched_to_the_intrusion_set(index):
    rec = bs.reconcile([], LLMEnrichmentResult(threat_actors=["Cozy Bear"]), REPORT, index)
    assert rec.entity("threat_actor", "Cozy Bear") == (bs.MATCHED, APT29)
    assert APT29 not in _imported(rec)


def test_a_sha256_raw_entity_is_matched_to_the_file_entry(index):
    rec = bs.reconcile([_raw(SHA256, "sha256")], LLMEnrichmentResult(), REPORT, index)
    assert rec.entity("sha256", SHA256) == (bs.MATCHED, FILE)
    assert FILE not in _imported(rec)


def test_a_name_the_baseline_lacks_is_new(index):
    llm = LLMEnrichmentResult(
        malware_families=["SUNBURST"], tools=["Cobalt Strike"], campaign_name="Ministry campaign",
        ttps=[TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")],
    )
    rec = bs.reconcile([], llm, REPORT, index)
    assert rec.entity("malware", "SUNBURST") == (bs.NEW, None)
    assert rec.entity("tool", "Cobalt Strike") == (bs.NEW, None)
    assert rec.entity("campaign", "Ministry campaign") == (bs.NEW, None)
    assert rec.entity("ttp", "Spearphishing Attachment") == (bs.NEW, None)


def test_a_baseline_entry_nothing_extracted_and_not_in_the_text_is_baseline_only(index):
    rec = bs.reconcile([_raw(SHA256, "sha256")], LLMEnrichmentResult(threat_actors=["Cozy Bear"]), REPORT, index)
    imported = _imported(rec)
    assert set(imported) == {IPV4, WELLMESS, POWERSHELL}
    assert all(row.status == bs.BASELINE_ONLY and row.evidence_text is None for row in imported.values())
    assert imported[WELLMESS] == bs.ImportedEntity(value="WellMess", entity_type="malware", mitre_id="S0514",
                                                   status=bs.BASELINE_ONLY, baseline_stix_id=WELLMESS)
    assert imported[POWERSHELL].mitre_id == "T1059.001"


def test_an_entry_the_text_names_and_nothing_extracted_is_baseline_in_text(index):
    rec = bs.reconcile([], LLMEnrichmentResult(), REPORT, index)
    imported = _imported(rec)
    assert imported[APT29].status == bs.BASELINE_IN_TEXT
    assert imported[FILE].status == bs.BASELINE_IN_TEXT
    assert imported[WELLMESS].status == bs.BASELINE_ONLY
    assert imported[IPV4].status == bs.BASELINE_ONLY
    assert imported[POWERSHELL].status == bs.BASELINE_ONLY

    apt = imported[APT29]
    start = REPORT.index("Cozy Bear")
    assert (apt.evidence_text, apt.evidence_start, apt.evidence_end) == ("Cozy Bear", start, start + len("Cozy Bear"))
    entry = next(e for e in index.entries if e.entry_id == APT29)
    assert REPORT[apt.evidence_start:apt.evidence_end].lower() in entry.surface_forms

    sha = imported[FILE]
    assert REPORT[sha.evidence_start:sha.evidence_end] == sha.evidence_text == SHA256


@pytest.mark.parametrize(("text", "status", "start"), [
    ("the botnet", bs.BASELINE_ONLY, None),        # "bot" inside a word
    ("a_bot", bs.BASELINE_ONLY, None),             # "_" is part of a word
    ("bot-net", bs.BASELINE_IN_TEXT, 0),           # a hyphen ends the word
    ("the botnet and a bot.", bs.BASELINE_IN_TEXT, 17),
    ("BOT", bs.BASELINE_IN_TEXT, 0),
])
def test_a_form_counts_only_as_a_whole_word(text, status, start):
    bot = _index(_entry("malware--00000000-0000-4000-8000-000000000001", "malware", "malware", "Bot",
                        forms=("bot",)))
    [row] = bs.reconcile([], LLMEnrichmentResult(), text, bot).imported_entities
    assert row.status == status
    assert row.evidence_start == start


@pytest.mark.parametrize("forms", [("cozy bear", "nobelium"), ("nobelium", "cozy bear")])
def test_the_earliest_form_in_the_text_is_the_evidence(index, forms):
    apt = dataclasses.replace(next(e for e in index.entries if e.entry_id == APT29), surface_forms=forms)
    others = [e for e in index.entries if e.entry_id != APT29]
    rec = bs.reconcile([], LLMEnrichmentResult(), "NOBELIUM, then Cozy Bear.", _index(apt, *others))
    row = _imported(rec)[APT29]
    assert (row.status, row.evidence_text, row.evidence_start) == (bs.BASELINE_IN_TEXT, "NOBELIUM", 0)


@pytest.mark.parametrize(("field", "item"), [
    ("relationships", RelationshipExtracted(source_value="Cozy Bear", relationship_type="uses",
                                            target_value="WellMess")),
    ("rel_review", RelationshipReview(source_value="Cozy Bear", relationship_type="uses",
                                      target_value="WellMess", reason="the quote is not in the text")),
])
def test_an_extracted_relationship_between_matched_rows_is_matched_to_the_baseline_relation(index, field, item):
    llm = LLMEnrichmentResult(threat_actors=["Cozy Bear"], malware_families=["WellMess"], **{field: [item]})
    rec = bs.reconcile([], llm, REPORT, index)
    assert rec.relation("Cozy Bear", "uses", "WellMess") == (bs.MATCHED, USES)
    assert USES not in {row.baseline_stix_id for row in rec.imported_relations}


def test_a_relationship_of_another_type_or_with_an_unknown_end_is_new(index):
    llm = LLMEnrichmentResult(
        threat_actors=["Cozy Bear"], malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(source_value="Cozy Bear", relationship_type="targets", target_value="WellMess"),
            RelationshipExtracted(source_value="Ghost Group", relationship_type="uses", target_value="WellMess"),
        ],
    )
    rec = bs.reconcile([], llm, REPORT, index)
    assert rec.relation("Cozy Bear", "targets", "WellMess") == (bs.NEW, None)
    assert rec.relation("Ghost Group", "uses", "WellMess") == (bs.NEW, None)


def test_an_endpoint_no_row_names_is_resolved_through_the_baseline_forms(index):
    llm = LLMEnrichmentResult(
        relationships=[RelationshipExtracted(source_value="Cozy Bear", relationship_type="uses",
                                             target_value="WellMess")],
    )
    rec = bs.reconcile([], llm, "", index)
    assert rec.relation("Cozy Bear", "uses", "WellMess") == (bs.MATCHED, USES)


def test_a_value_two_entries_share_resolves_to_no_entry(index):
    foo = _entry("malware--a", "malware", "malware", "Foo", keys=(("named", "software", "foo"),), forms=("foo",))
    actor = _entry("intrusion-set--b", "intrusion-set", "threat-actor", "Foo", keys=(("named", "actor", "foo"),),
                   forms=("foo",))
    bar = _entry("malware--c", "malware", "malware", "Bar", keys=(("named", "software", "bar"),), forms=("bar",))
    link = bs.Relation("relationship--d", "uses", "malware--a", "malware--c", "malware--a", "malware--c")
    llm = LLMEnrichmentResult(
        malware_families=["Foo"], threat_actors=["Foo"],
        relationships=[RelationshipExtracted(source_value="Foo", relationship_type="uses", target_value="Bar")],
    )
    rec = bs.reconcile([], llm, "", _index(foo, actor, bar, relations=(link,)))
    assert rec.entity("malware", "Foo") == (bs.MATCHED, "malware--a")
    assert rec.entity("threat_actor", "Foo") == (bs.MATCHED, "intrusion-set--b")
    assert rec.relation("Foo", "uses", "Bar") == (bs.NEW, None)
    [row] = rec.imported_relations
    assert row == bs.ImportedRelation(source_value="Foo", relationship_type="uses", target_value="Bar",
                                      status=bs.BASELINE_ONLY, baseline_stix_id="relationship--d")


def test_a_baseline_relation_with_one_end_found_is_baseline_only(index):
    rec = bs.reconcile([], LLMEnrichmentResult(threat_actors=["Cozy Bear"]), "Cozy Bear was active.", index)
    relations = {row.baseline_stix_id: row for row in rec.imported_relations}
    assert relations[USES] == bs.ImportedRelation(source_value="APT29", relationship_type="uses",
                                                  target_value="WellMess", status=bs.BASELINE_ONLY,
                                                  baseline_stix_id=USES)
    assert relations[INDICATES].status == bs.BASELINE_ONLY


def test_a_baseline_relation_with_both_ends_in_the_text_is_baseline_in_text(index):
    rec = bs.reconcile([], LLMEnrichmentResult(), "Cozy Bear used WellMess.", index)
    relations = {row.baseline_stix_id: row for row in rec.imported_relations}
    assert relations[USES].status == bs.BASELINE_IN_TEXT
    assert relations[USES].source_value == "APT29" and relations[USES].target_value == "WellMess"
    assert relations[INDICATES].status == bs.BASELINE_ONLY
    assert rec.stats["relations_baseline_in_text"] == 1


def test_a_baseline_relation_with_an_unresolved_end_is_not_imported():
    foo = _entry("malware--a", "malware", "malware", "Foo", keys=(("named", "software", "foo"),))
    dangling = bs.Relation("relationship--x", "uses", "malware--a", "ghost", "malware--a", None)
    rec = bs.reconcile([], LLMEnrichmentResult(), "", _index(foo, relations=(dangling,)))
    assert rec.imported_relations == []


def test_the_stats_count_each_status(index):
    llm = LLMEnrichmentResult(
        threat_actors=["Cozy Bear"],
        malware_families=["SUNBURST"],
        ttps=[TTPExtracted(technique_name="Spearphishing Attachment", mitre_id="T1566.001")],
        relationships=[
            RelationshipExtracted(source_value="Cozy Bear", relationship_type="uses", target_value="WellMess"),
            RelationshipExtracted(source_value="Cozy Bear", relationship_type="targets", target_value="WellMess"),
        ],
    )
    rec = bs.reconcile([], llm, REPORT, index)
    assert rec.stats == {
        "entities_new": 2, "entities_matched": 1, "entities_baseline_in_text": 1, "entities_baseline_only": 3,
        "relations_new": 1, "relations_matched": 1, "relations_baseline_in_text": 0, "relations_baseline_only": 1,
    }


def test_nothing_extracted_and_no_text_imports_the_whole_baseline(index):
    rec = bs.reconcile([], LLMEnrichmentResult(), "", index)
    assert {row.baseline_stix_id for row in rec.imported_entities} == {e.entry_id for e in index.entries}
    assert all(row.status == bs.BASELINE_ONLY and row.evidence_start is None for row in rec.imported_entities)
    assert {row.baseline_stix_id for row in rec.imported_relations} == {USES, INDICATES}
    assert all(row.status == bs.BASELINE_ONLY for row in rec.imported_relations)
    assert rec.entity_status == {} and rec.relation_status == {}
    assert rec.stats["entities_baseline_only"] == len(index.entries)


def test_a_blank_value_is_new_and_raises_nothing(index):
    rec = bs.reconcile([_raw("   ", "sha256")], LLMEnrichmentResult(), REPORT, index)
    assert rec.entity("sha256", "   ") == (bs.NEW, None)


def test_a_row_is_found_whatever_its_spacing_and_case(index):
    rec = bs.reconcile([], LLMEnrichmentResult(threat_actors=["Cozy Bear"]), REPORT, index)
    assert rec.entity("threat_actor", "  cozy  BEAR ") == (bs.MATCHED, APT29)
    assert rec.entity("threat_actor", "Unknown Group") == (bs.NEW, None)


def test_no_offset_is_given_when_lowering_changes_the_length(index):
    text = "İ: Cozy Bear was active."        # its lowercase is two characters long
    rec = bs.reconcile([], LLMEnrichmentResult(), text, index)
    apt = _imported(rec)[APT29]
    assert apt.status == bs.BASELINE_IN_TEXT
    assert (apt.evidence_text, apt.evidence_start, apt.evidence_end) == (None, None, None)


@pytest.mark.parametrize("name", ["PowerShell", ""])
def test_a_held_technique_is_matched_like_an_extracted_one(index, name):
    held = TtpReview(attack_id="T1059.001", name=name, reason="the call failed")
    rec = bs.reconcile([], LLMEnrichmentResult(ttp_review=[held]), REPORT, index)
    assert rec.entity("ttp", name or "T1059.001") == (bs.MATCHED, POWERSHELL)
    assert POWERSHELL not in _imported(rec)


def test_a_matched_row_stays_matched_when_a_row_of_its_name_is_new(index):
    llm = LLMEnrichmentResult(
        ttps=[TTPExtracted(technique_name="Spearphishing", mitre_id="T1059.001")],
        ttp_review=[TtpReview(attack_id="", name="Spearphishing", reason="the call failed")],
    )
    rec = bs.reconcile([], llm, "", index)
    assert rec.entity("ttp", "Spearphishing") == (bs.MATCHED, POWERSHELL)
