"""A revoked ATT&CK id written in a report is the technique that replaced it (#980).

T1562 is revoked: the bundled release names T1685 as its successor.  A raw
technique entity written T1562 becomes T1685's attack-pattern, keeps the id the
report wrote as a `report` reference, and the ledger says so.
"""
from models.schemas import EntityType, RawEntity
from pipeline import aliases, attack_ids, stix_ids
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle

T1685_NAME = aliases.technique_name_for("T1685")


def _attack_patterns(*entities, llm=None, ledger=None):
    bundle = build_stix_bundle(list(entities), llm or LLMEnrichmentResult(), "offline",
                               ledger=ledger, graph_completion=False)
    return [o for o in bundle.objects if o.get("type") == "attack-pattern"]


def _refs(ap):
    return [(r.source_name, r.external_id) for r in ap.external_references]


def test_a_revoked_id_becomes_its_successor_and_keeps_the_id_written():
    led = MappingLedger()
    [ap] = _attack_patterns(
        RawEntity(value="T1562", entity_type=EntityType.TTP, mitre_id="T1562"), ledger=led)

    assert T1685_NAME and ap.name == T1685_NAME
    assert ap.id == stix_ids.attack_pattern_id(T1685_NAME, "T1685")
    assert _refs(ap) == [("mitre-attack", "T1685"), ("report", "T1562")]
    report_ref = ap.external_references[1]
    assert report_ref.description == (
        f"revoked in ATT&CK {attack_ids.release_version()}, replaced by T1685")
    assert "url" not in report_ref

    [row] = [e for e in led.entities if e["value"] == "T1562"]
    assert row["outcome"] == "emitted" and row["stix_id"] == ap.id
    assert row["reason"] == "attack_id_revoked"
    assert row["written"] == "T1562" and row["replaced_by"] == "T1685"
    assert row["attack_release"] == attack_ids.release_version()


def test_a_revoked_id_and_the_model_s_successor_make_one_attack_pattern():
    led = MappingLedger()
    llm = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name=T1685_NAME, mitre_id="T1685")])
    [ap] = _attack_patterns(
        RawEntity(value="T1562", entity_type=EntityType.TTP, mitre_id="T1562"),
        llm=llm, ledger=led)

    assert ap.name == T1685_NAME
    assert _refs(ap) == [("mitre-attack", "T1685"), ("report", "T1562")]
    [row] = [e for e in led.entities if e["value"] == "T1562"]
    assert row["outcome"] == "merged" and row["stix_id"] == ap.id
    assert row["reason"] == "attack_id_revoked" and row["written"] == "T1562"


def test_the_model_s_successor_alone_carries_no_report_reference():
    llm = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name=T1685_NAME, mitre_id="T1685")])
    [ap] = _attack_patterns(llm=llm)

    assert _refs(ap) == [("mitre-attack", "T1685")]


def test_two_raw_entities_for_one_revoked_id_cite_it_once():
    led = MappingLedger()
    [ap] = _attack_patterns(
        RawEntity(value="T1562", entity_type=EntityType.TTP, mitre_id="T1562"),
        RawEntity(value="t1562", entity_type=EntityType.TECHNIQUE, mitre_id="T1562"),
        ledger=led)

    assert _refs(ap) == [("mitre-attack", "T1685"), ("report", "T1562")]
    assert [e["outcome"] for e in led.entities if e["value"] == "t1562"] == ["merged"]


def test_a_bare_id_of_a_sub_technique_keeps_the_known_path():
    led = MappingLedger()
    [ap] = _attack_patterns(
        RawEntity(value="T1059.001", entity_type=EntityType.TTP, mitre_id="T1059.001"), ledger=led)

    assert ap.name == "PowerShell"
    assert _refs(ap) == [("mitre-attack", "T1059.001")]
    [row] = [e for e in led.entities if e["value"] == "T1059.001"]
    assert row["reason"] == "attack_id_named" and "written" not in row


def test_an_unknown_id_keeps_its_value_as_name_and_no_reference():
    led = MappingLedger()
    [ap] = _attack_patterns(
        RawEntity(value="T9999", entity_type=EntityType.TTP, mitre_id="T9999"), ledger=led)

    assert ap.name == "T9999"
    assert _refs(ap) == [("mitre-attack", "T9999")]
    [row] = [e for e in led.entities if e["value"] == "T9999"]
    assert "reason" not in row and "written" not in row


def test_a_relationship_to_the_revoked_id_reaches_the_successor():
    """"Foo uses T1562": the edge ends on T1685's attack-pattern, not nowhere."""
    from pipeline.stage3_llm import RelationshipExtracted

    llm = LLMEnrichmentResult(
        malware_families=["Foo"],
        relationships=[RelationshipExtracted(source_value="Foo", relationship_type="uses",
                                             target_value="T1562",
                                             evidence_text="Foo uses T1562 to stop the agent.")])
    bundle = build_stix_bundle(
        [RawEntity(value="Foo", entity_type=EntityType.MALWARE),
         RawEntity(value="T1562", entity_type=EntityType.TTP, mitre_id="T1562")],
        llm, "Foo uses T1562 to stop the agent.", graph_completion=False)
    [ap] = [o for o in bundle.objects if o.get("type") == "attack-pattern"]
    uses = [o for o in bundle.objects
            if o.get("type") == "relationship" and o.get("relationship_type") == "uses"]
    assert [r.target_ref for r in uses] == [ap.id]
