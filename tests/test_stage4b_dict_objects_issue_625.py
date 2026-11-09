"""Stage 4b graph completion on STIX objects held as plain dicts (#625).

Bundles deserialised from JSON hold dicts, not stix2 instances (ADR-0061,
#502/#504).  The completion passes must treat both kinds the same: the alias
merge must not crash, and the inference passes must not skip dicts silently.
Each scenario is run once with stix2 objects and once with their JSON dicts,
and the two results must match.
"""
import json
import uuid

import pytest
import stix2

from pipeline.stage4b_graph_completion import InferredEdge, complete_graph
from pipeline.stix_access import field as stix_field


def _sid(kind: str, name: str) -> str:
    """A fixed, valid STIX id, so the stix2 run and the dict run share ids."""
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, name)}"


def _as_dicts(objs: list) -> list:
    return [json.loads(o.serialize()) for o in objs]


def _summary(objs: list) -> list:
    """An order-independent view of the graph that works for dicts and stix2."""
    sdos = sorted(
        (stix_field(o, "type"), stix_field(o, "id"), stix_field(o, "name"),
         tuple(stix_field(o, "aliases") or ()))
        for o in objs if stix_field(o, "type") != "relationship"
    )
    rels = sorted(
        (stix_field(o, "source_ref"), stix_field(o, "relationship_type"),
         stix_field(o, "target_ref"), stix_field(o, "x_evidence_label"),
         stix_field(o, "x_inference_rule"), stix_field(o, "confidence"),
         tuple(stix_field(o, "x_inferred_from") or ()))
        for o in objs if stix_field(o, "type") == "relationship"
    )
    return [sdos, rels]


def _alias_scenario():
    """APT29 / apt-29 duplicate, with an edge on the duplicate and a chain
    onward, so the merge rewires an SRO and feeds transitive inference."""
    a1 = stix2.ThreatActor(id=_sid("threat-actor", "APT29"), name="APT29")
    a2 = stix2.ThreatActor(id=_sid("threat-actor", "apt-29"), name="apt-29",
                           aliases=["Cozy Bear"])
    mw = stix2.Malware(id=_sid("malware", "WellMess"), name="WellMess", is_family=True)
    ap = stix2.AttackPattern(id=_sid("attack-pattern", "Phishing"), name="Phishing")
    return [
        a1, a2, mw, ap,
        stix2.Relationship(a2, "uses", mw, id=_sid("relationship", "a2-mw"), confidence=80),
        stix2.Relationship(mw, "uses", ap, id=_sid("relationship", "mw-ap"), confidence=80),
    ]


def _chain_and_island_scenario():
    """A transitive chain plus a disconnected island for the long-distance step."""
    actor = stix2.IntrusionSet(id=_sid("intrusion-set", "APT-X"), name="APT-X")
    mw = stix2.Malware(id=_sid("malware", "Backdoor-Y"), name="Backdoor-Y", is_family=True)
    ap = stix2.AttackPattern(id=_sid("attack-pattern", "Phishing"), name="Phishing")
    tool = stix2.Tool(id=_sid("tool", "TL"), name="TL")
    island_mw = stix2.Malware(id=_sid("malware", "MW2"), name="MW2", is_family=True)
    island_ap = stix2.AttackPattern(id=_sid("attack-pattern", "AP2"), name="AP2")
    return [
        actor, mw, ap, tool, island_mw, island_ap,
        stix2.Relationship(actor, "uses", mw, id=_sid("relationship", "r1"), confidence=80),
        stix2.Relationship(mw, "uses", ap, id=_sid("relationship", "r2"), confidence=80),
        stix2.Relationship(actor, "uses", tool, id=_sid("relationship", "r3")),
        stix2.Relationship(island_mw, "uses", island_ap, id=_sid("relationship", "r4")),
    ]


def _fake_infer(src, tgt, text):
    # The island's malware is linked to the topic actor, duck-typed for dicts too.
    return InferredEdge(source_id=stix_field(tgt, "id"), verb="uses",
                        target_id=stix_field(src, "id"))


# ── the issue's reproduction ─────────────────────────────────────────────────
def test_alias_merge_accepts_dict_sdos():
    """The issue's example: the merge must neither fail nor leave two objects."""
    sdos = [
        {"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "WannaCry",
         "aliases": ["WannaCrypt"]},
        {"type": "malware", "id": f"malware--{uuid.uuid4()}", "name": "WannaCrypt"},
    ]

    stats = complete_graph(sdos, policy={"completion": {"alias": True}})

    assert not [n for n in stats.notes if "alias merge failed" in n]
    assert stats.notes == []
    assert stats.aliases_merged == 1
    assert len(sdos) == 1
    assert sdos[0]["type"] == "malware"
    assert "WannaCry" in sdos[0]["aliases"]
    assert isinstance(sdos[0], dict)


def test_alias_merge_rewires_a_dict_relationship():
    """The duplicate's SRO (a dict) is rewired onto the canonical dict SDO."""
    objs = _as_dicts(_alias_scenario())

    stats = complete_graph(objs, policy={"completion": {"alias": True, "transitive": False}})

    assert stats.notes == []
    actors = [o for o in objs if o["type"] == "threat-actor"]
    assert len(actors) == 1
    rels = [o for o in objs if o["type"] == "relationship"]
    assert [r["source_ref"] for r in rels if r["relationship_type"] == "uses"][0] == actors[0]["id"]
    # "apt-29" carries the edge, so it is the canonical node; APT29 is absorbed.
    assert actors[0]["name"] == "apt-29"
    assert "APT29" in actors[0]["aliases"] and "Cozy Bear" in actors[0]["aliases"]


# ── dict and stix2 runs must agree ───────────────────────────────────────────
@pytest.mark.parametrize("policy", [
    {"completion": {"alias": True}},
    {"completion": {"alias": True, "transitive": True, "reference": False}},
])
def test_alias_merge_and_transitive_match_stix2_objects(policy):
    stix_objs = _alias_scenario()
    dict_objs = _as_dicts(_alias_scenario())

    stix_stats = complete_graph(stix_objs, policy=policy)
    dict_stats = complete_graph(dict_objs, policy=policy)

    assert stix_stats.notes == dict_stats.notes == []
    assert stix_stats.transitive_added == dict_stats.transitive_added
    assert stix_stats.aliases_merged == dict_stats.aliases_merged == 1
    assert _summary(stix_objs) == _summary(dict_objs)


def test_transitive_and_long_distance_match_stix2_objects():
    """Transitive composition and a long-distance edge to an island, with dict
    SDOs and dict SROs, produce the same graph as the stix2 objects."""
    policy = {"completion": {"long_distance": True, "transitive": True, "alias": False,
                             "reference": False}}
    stix_objs = _chain_and_island_scenario()
    dict_objs = _as_dicts(_chain_and_island_scenario())

    stix_stats = complete_graph(stix_objs, policy=policy, report_text="x",
                                long_distance_infer=_fake_infer)
    dict_stats = complete_graph(dict_objs, policy=policy, report_text="x",
                                long_distance_infer=_fake_infer)

    assert stix_stats.notes == dict_stats.notes == []
    assert stix_stats.transitive_added == dict_stats.transitive_added >= 1
    assert stix_stats.long_distance_added == dict_stats.long_distance_added >= 1
    assert _summary(stix_objs) == _summary(dict_objs)


def test_dict_transitive_adds_the_composed_edge_and_its_premises():
    """Plain dict SDOs and SROs: the composed edge is produced, not skipped."""
    objs = _as_dicts(_chain_and_island_scenario())

    stats = complete_graph(objs, policy={"completion": {"alias": False, "reference": False,
                                                        "long_distance": False}})

    assert stats.transitive_added == 1
    inferred = [o for o in objs if o.get("x_evidence_label") == "inferred"]
    assert len(inferred) == 1
    assert inferred[0]["x_inference_rule"] == "transitive:uses+uses"
    assert inferred[0]["x_inferred_from"] == [_sid("relationship", "r1"),
                                             _sid("relationship", "r2")]


def test_dict_long_distance_connects_the_island():
    objs = _as_dicts(_chain_and_island_scenario())

    stats = complete_graph(objs, policy={"completion": {"long_distance": True,
                                                        "transitive": False,
                                                        "alias": False, "reference": False}},
                           report_text="x", long_distance_infer=_fake_infer)

    assert stats.notes == []
    assert stats.long_distance_added >= 1


def test_dict_reference_grounding_adds_curated_edge():
    """The ATT&CK reference pass also reads dict SDOs (#625)."""
    import pipeline.stage4b_graph_completion as s4b
    if not s4b._attack_pairs():
        pytest.skip("attack_relationships.json not built")

    objs = _as_dicts([
        stix2.ThreatActor(name="APT29"),
        stix2.Malware(name="Mimikatz", is_family=True),
    ])

    stats = complete_graph(objs, policy={"completion": {"transitive": False, "alias": False}})

    assert stats.notes == []
    assert stats.reference_added >= 1
    assert any(o.get("x_inference_rule") == "attack-reference:G0016>S0002" for o in objs)
