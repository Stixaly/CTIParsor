"""Stage 4 duplicate and wrong-type objects (issues #778, #779, #781).

#778: two spellings of one pattern (HKLM\\... and HKEY_LOCAL_MACHINE\\...) in
ioc_associations each built an Indicator with the same id.
#779: "AS12345" and "12345" were two observables, both built as the same
autonomous-system, so the bundle held two objects with one id.
#781: a network-traffic took any SCO of the host's value as its destination,
even a File named like the host, and the NetworkTraffic was then never built.
"""
from __future__ import annotations

from models.schemas import EntityType, RawEntity
from pipeline import stage4_stix_mapping as s4
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult


def _of_type(bundle, type_: str) -> list:
    return [o for o in bundle.objects if o.get("type") == type_]


def _sros(bundle) -> set[tuple[str, str, str]]:
    return {(o.source_ref, o.relationship_type, o.target_ref)
            for o in bundle.objects if o.get("type") == "relationship"}


def test_two_spellings_of_one_registry_pattern_give_one_indicator_issue_778():
    key_a = "HKLM\\Software\\Run"
    key_b = "HKEY_LOCAL_MACHINE\\Software\\Run"
    entities = [
        RawEntity(value=key_a, entity_type=EntityType.REGISTRY_KEY, source_stage="regex"),
        RawEntity(value=key_b, entity_type=EntityType.REGISTRY_KEY, source_stage="regex"),
    ]
    llm = LLMEnrichmentResult(
        malware_families=["Emotet"],
        ioc_associations=[
            IoCAssociation(ioc_value=key_a, malware_name="Emotet"),
            IoCAssociation(ioc_value=key_b, malware_name="Emotet"),
        ],
    )
    bundle = s4.build_stix_bundle(entities, llm, "r778", graph_completion=False)

    [indicator] = _of_type(bundle, "indicator")
    [malware] = _of_type(bundle, "malware")
    ids = [o.id for o in bundle.objects if hasattr(o, "id")]
    assert len(ids) == len(set(ids)), "duplicate object ids in bundle"
    assert [(s, t) for s, t, _ in _sros(bundle) if t == "indicates"] == [(indicator.id, "indicates")]
    assert (indicator.id, "indicates", malware.id) in _sros(bundle)


def test_second_spelling_of_one_pattern_is_merged_in_the_ledger_issue_778():
    key_a = "HKLM\\Software\\Run"
    key_b = "HKEY_LOCAL_MACHINE\\Software\\Run"
    entities = [
        RawEntity(value=key_a, entity_type=EntityType.REGISTRY_KEY, source_stage="regex"),
        RawEntity(value=key_b, entity_type=EntityType.REGISTRY_KEY, source_stage="regex"),
    ]
    llm = LLMEnrichmentResult(
        malware_families=["Emotet"],
        ioc_associations=[
            IoCAssociation(ioc_value=key_a, malware_name="Emotet"),
            IoCAssociation(ioc_value=key_b, malware_name="Emotet"),
        ],
    )
    led = MappingLedger()
    bundle = s4.build_stix_bundle(entities, llm, "r778l", ledger=led, graph_completion=False)

    [indicator] = _of_type(bundle, "indicator")
    rows = [e for e in led.entities if e["value"] == key_b and e["entity_type"] == "indicator"]
    assert [(e["outcome"], e["reason"], e["stix_id"]) for e in rows] == [
        ("merged", "same_observable", indicator.id)]
    # The SCO of the second spelling is based-on by the one Indicator, once.
    based_on = [(s, t, d) for s, t, d in _sros(bundle) if t == "based-on"]
    assert len(based_on) == len(set(based_on)) == 1
    assert based_on[0][0] == indicator.id


def test_asn_spellings_share_one_observable_key_issue_779():
    with_prefix = RawEntity(value="AS12345", entity_type=EntityType.ASN)
    bare = RawEntity(value="12345", entity_type=EntityType.ASN)
    assert s4._observable_key(with_prefix) == s4._observable_key(bare)
    # A value that is not a number keeps the old key and does not raise.
    odd = RawEntity(value="AS12X", entity_type=EntityType.ASN)
    assert s4._observable_key(odd) == ("asn", "as12x")


def test_asn_spellings_give_one_autonomous_system_issue_779():
    entities = [
        RawEntity(value="AS12345", entity_type=EntityType.ASN),
        RawEntity(value="12345", entity_type=EntityType.ASN),
    ]
    bundle = s4.build_stix_bundle(entities, LLMEnrichmentResult(), "r779", graph_completion=False)

    [asn] = _of_type(bundle, "autonomous-system")
    assert asn.number == 12345
    ids = [o.id for o in bundle.objects if hasattr(o, "id")]
    assert len(ids) == len(set(ids)), "duplicate object ids in bundle"


def test_network_traffic_destination_is_a_domain_not_a_file_of_the_same_name_issue_781():
    entities = [
        RawEntity(value="evil.com", entity_type=EntityType.FILE, source_stage="regex"),
        RawEntity(value="tcp/443 to evil.com", entity_type=EntityType.NETWORK_TRAFFIC, source_stage="regex"),
    ]
    bundle = s4.build_stix_bundle(entities, LLMEnrichmentResult(), "r781", graph_completion=False)

    [nt] = _of_type(bundle, "network-traffic")
    [domain] = _of_type(bundle, "domain-name")
    assert domain.value == "evil.com"
    assert nt.dst_ref == domain.id
    assert nt.dst_port == 443
