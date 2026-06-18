"""Tests for STIX provenance: TLP marking + authoring Identity (Feature A)."""
import stix2

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle

# STIX 2.1 cyber-observable types that must NOT carry created_by_ref.
_SCO_TYPES = {
    "ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "file",
    "mac-addr", "autonomous-system", "windows-registry-key", "mutex",
    "network-traffic", "user-account", "artifact",
}


def _bundle():
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="uses",
                                  target_value="WellMess", confidence=0.9),
        ],
    )
    ents = [RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4)]
    return build_stix_bundle(ents, llm, "rep", report_text="APT29 used WellMess.")


def test_bundle_has_authoring_identity():
    objs = list(_bundle().objects)
    authors = [o for o in objs if o["type"] == "identity" and o.get("name") == "CTIParsor"]
    assert authors, "no CTIParsor authoring identity in bundle"
    assert authors[0]["identity_class"] == "system"


def test_bundle_has_tlp_marking():
    objs = list(_bundle().objects)
    markings = [o for o in objs if o["type"] == "marking-definition"]
    assert markings, "no TLP marking in bundle"
    # Default STIX_TLP=clear → the standard interoperable TLP:WHITE id.
    assert markings[0]["id"] == stix2.TLP_WHITE.id


def test_sdo_and_sro_carry_created_by_ref_and_marking():
    objs = list(_bundle().objects)
    author = next(o for o in objs if o["type"] == "identity" and o.get("name") == "CTIParsor")
    tlp = next(o for o in objs if o["type"] == "marking-definition")
    sdo_sro = [o for o in objs
               if o["type"] not in _SCO_TYPES
               and o["type"] not in ("identity", "marking-definition")]
    assert sdo_sro, "expected at least one SDO/SRO"
    for o in sdo_sro:
        assert o.get("created_by_ref") == author["id"], f"{o['type']} missing created_by_ref"
        assert tlp["id"] in o.get("object_marking_refs", []), f"{o['type']} missing marking"


def test_scos_are_marked_but_have_no_created_by_ref():
    objs = list(_bundle().objects)
    tlp = next(o for o in objs if o["type"] == "marking-definition")
    scos = [o for o in objs if o["type"] in _SCO_TYPES]
    assert scos, "expected at least one SCO"
    for o in scos:
        assert "created_by_ref" not in o, f"SCO {o['type']} must not carry created_by_ref"
        assert tlp["id"] in o.get("object_marking_refs", []), f"SCO {o['type']} missing marking"


def test_stix_tlp_env_switches_marking(monkeypatch):
    monkeypatch.setenv("STIX_TLP", "red")
    objs = list(_bundle().objects)
    marking = next(o for o in objs if o["type"] == "marking-definition")
    assert marking["id"] == stix2.TLP_RED.id
