"""Tests for STIX provenance: TLP marking + authoring Identity (Feature A)."""
import json

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import (
    OPENCTI_EXTENSION_ID,
    TLP_AMBER_STRICT,
    build_stix_bundle,
    normalise_tlp,
    tlp_default,
)

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


def test_bundle_has_tlp_marking(monkeypatch):
    monkeypatch.delenv("STIX_TLP", raising=False)
    objs = list(_bundle().objects)
    markings = [o for o in objs if o["type"] == "marking-definition"]
    assert len(markings) == 1, "exactly one TLP marking in a bundle"
    # STIX_TLP unset → AMBER, the safe default (ADR-0073); CLEAR is a choice.
    assert markings[0]["id"] == stix2.TLP_AMBER.id


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


# ── ADR-0073: a marking is never guessed ─────────────────────────────────────

def _marking_of(tlp_level=None):
    llm = LLMEnrichmentResult(threat_actors=["APT29"])
    bundle = build_stix_bundle([], llm, "rep", report_text="APT29.", tlp_level=tlp_level)
    objs = list(bundle.objects)
    markings = [o for o in objs if o["type"] == "marking-definition"]
    assert len(markings) == 1
    return markings[0], objs


@pytest.mark.parametrize("spelling,expected_id", [
    ("TLP:AMBER", stix2.TLP_AMBER.id),          # the usual spelling, once a silent CLEAR
    ("tlp:amber", stix2.TLP_AMBER.id),
    ("white", stix2.TLP_WHITE.id),              # TLP 1.0 name
    ("CLEAR", stix2.TLP_WHITE.id),
    ("TLP:CLEAR", stix2.TLP_WHITE.id),
    (" green ", stix2.TLP_GREEN.id),
    ("AMBER+STRICT", TLP_AMBER_STRICT.id),
    ("TLP:Amber+Strict", TLP_AMBER_STRICT.id),
    ("TLP:AMBER + STRICT", TLP_AMBER_STRICT.id),
    ("red", stix2.TLP_RED.id),
])
def test_every_spelling_of_a_level_is_the_same_marking(spelling, expected_id):
    marking, objs = _marking_of(spelling)
    assert marking["id"] == expected_id
    for o in objs:
        if o["type"] == "marking-definition" or (o["type"] == "identity" and o.get("name") == "CTIParsor"):
            continue        # the marking itself, and the authoring identity (bundle-level provenance)
        assert o["object_marking_refs"] == [expected_id], o["type"]


@pytest.mark.parametrize("bad", ["PURPLE", "AMBER-STRICT", "TLP", "TLP:", "amber+", "WHITE+STRICT"])
def test_an_unknown_level_is_refused_not_defaulted(bad):
    with pytest.raises(ValueError, match="unknown TLP level"):
        normalise_tlp(bad)
    with pytest.raises(ValueError):
        _marking_of(bad)


def test_a_bad_default_is_refused_at_startup(monkeypatch):
    """The API's lifespan, the worker's main and the CLI call tlp_default()
    first: a typo in STIX_TLP stops the process, not the first bundle."""
    monkeypatch.setenv("STIX_TLP", "TLP:AMBRE")
    with pytest.raises(ValueError, match="AMBRE"):
        tlp_default()
    with pytest.raises(ValueError):
        _marking_of(None)
    monkeypatch.setenv("STIX_TLP", "TLP:amber+strict")
    assert tlp_default() == "AMBER+STRICT"
    monkeypatch.delenv("STIX_TLP")
    assert tlp_default() == "AMBER"


def test_the_reports_own_level_wins_over_the_default(monkeypatch):
    monkeypatch.setenv("STIX_TLP", "red")
    marking, _ = _marking_of("green")
    assert marking["id"] == stix2.TLP_GREEN.id


def test_amber_strict_is_opencti_s_object():
    """Emitted as OpenCTI exports it: its static id, `definition_type: "TLP"`,
    the name, no `definition`, the platform's extension — so an import lands
    on the platform's own TLP:AMBER+STRICT, and stix2 (which refuses any
    `tlp` marking outside the four spec objects) still round-trips it."""
    marking, objs = _marking_of("AMBER+STRICT")
    assert marking["id"] == "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"
    assert marking["definition_type"] == "TLP"
    assert marking["name"] == "TLP:AMBER+STRICT"
    assert "definition" not in marking
    assert OPENCTI_EXTENSION_ID in marking["extensions"]
    assert marking["extensions"][OPENCTI_EXTENSION_ID]["extension_type"] == "property-extension"
    # Round trip through the library: a consumer re-reading the bundle must not
    # choke on the marking — strictly for the marking alone (the bundle's other
    # objects carry the project's x_ properties and need allow_custom).
    as_json = json.loads(stix2.Bundle(objects=objs, allow_custom=True).serialize())
    parsed = stix2.parse(as_json, allow_custom=True)
    assert any(o["id"] == marking["id"] for o in parsed["objects"])
    strict = stix2.parse(json.loads(TLP_AMBER_STRICT.serialize()))
    assert strict["id"] == marking["id"] and strict["definition_type"] == "TLP"
