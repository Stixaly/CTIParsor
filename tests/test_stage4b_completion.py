"""Tests for Stage 4b — STIX graph completion (ADR-0013).

Covers the deterministic engines (ATT&CK reference grounding, transitive
inference, the alias-merge fallback), the spec-suggested guard, policy control
(off switches + pins winning), and the opt-in long-distance step with a fake
inferer.  No network / no LLM.
"""
import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle
from pipeline.stage4b_graph_completion import (
    InferredEdge,
    _connected_components,
    complete_graph,
)


# ── helpers ───────────────────────────────────────────────────────────────────
def _rels(objs):
    return [o for o in objs if o.get("type") == "relationship"]


def _triples(objs):
    return {
        (o.get("source_ref").split("--")[0],
         o.get("relationship_type"),
         o.get("target_ref").split("--")[0])
        for o in _rels(objs)
    }


def _inferred(objs):
    return [o for o in _rels(objs) if o.get("x_evidence_label") == "inferred"]


# ── Step 2: transitive inference ──────────────────────────────────────────────
def test_transitive_uses_chain_adds_suggested_edge():
    """intrusion-set --uses--> malware --uses--> attack-pattern
    ⟹ intrusion-set --uses--> attack-pattern (suggested, so emitted)."""
    actor = stix2.IntrusionSet(name="APT-X")
    mw = stix2.Malware(name="Backdoor-Y", is_family=True)
    ap = stix2.AttackPattern(name="Phishing")
    r1 = stix2.Relationship(actor, "uses", mw, confidence=80)
    r2 = stix2.Relationship(mw, "uses", ap, confidence=80)
    objs = [actor, mw, ap, r1, r2]

    stats = complete_graph(objs)

    assert stats.transitive_added == 1
    assert ("intrusion-set", "uses", "attack-pattern") in _triples(objs)
    inf = _inferred(objs)
    assert len(inf) == 1
    assert inf[0].get("x_inference_rule") == "transitive:uses+uses"
    assert inf[0].get("x_inferred_from") == [r1.id, r2.id]
    # Confidence is discounted from the weaker premise (min 80 * 0.9 = 72).
    assert inf[0].get("confidence") == 72


def test_transitive_skips_non_suggested_pair():
    """intrusion-set --attributed-to--> threat-actor --attributed-to--> identity
    would compose to intrusion-set --attributed-to--> identity, which is NOT a
    suggested relationship (intrusion-set attributes only to threat-actor), so
    the edge is skipped rather than emitted."""
    iset = stix2.IntrusionSet(name="APT-X")
    actor = stix2.ThreatActor(name="Group-Y")
    ident = stix2.Identity(name="Ministry")
    objs = [iset, actor, ident,
            stix2.Relationship(iset, "attributed-to", actor, confidence=90),
            stix2.Relationship(actor, "attributed-to", ident, confidence=90)]

    stats = complete_graph(objs)

    assert stats.transitive_added == 0
    assert stats.skipped_not_suggested >= 1
    assert not _inferred(objs)


def test_transitive_does_not_duplicate_existing_edge():
    actor = stix2.IntrusionSet(name="A")
    mw = stix2.Malware(name="B", is_family=True)
    ap = stix2.AttackPattern(name="C")
    objs = [actor, mw, ap,
            stix2.Relationship(actor, "uses", mw),
            stix2.Relationship(mw, "uses", ap),
            stix2.Relationship(actor, "uses", ap)]  # already present

    stats = complete_graph(objs)

    assert stats.transitive_added == 0


def test_max_new_edges_cap():
    actor = stix2.IntrusionSet(name="A")
    mw = stix2.Malware(name="B", is_family=True)
    aps = [stix2.AttackPattern(name=f"T{i}") for i in range(5)]
    objs = [actor, mw, *aps, stix2.Relationship(actor, "uses", mw)]
    for ap in aps:
        objs.append(stix2.Relationship(mw, "uses", ap))

    stats = complete_graph(objs, policy={"completion": {"max_new_edges": 2}})

    assert stats.transitive_added == 2
    assert stats.capped is True


# ── Step 1: alias merge ───────────────────────────────────────────────────────
def test_alias_merge_is_off_by_default():
    """aliases.py (ADR-0012) canonicalises MITRE-known aliases at SDO-creation
    time, so this post-hoc fallback must not run unless explicitly enabled."""
    a1 = stix2.ThreatActor(name="APT29")
    a2 = stix2.ThreatActor(name="apt-29")
    objs = [a1, a2]

    stats = complete_graph(objs)

    assert stats.aliases_merged == 0
    assert len([o for o in objs if o.get("type") == "threat-actor"]) == 2


def test_alias_merge_reconnects_and_dedups():
    """Two threat-actor SDOs that are the same actor by normalised name get
    merged; the duplicate's edge is rewired onto the canonical node."""
    a1 = stix2.ThreatActor(name="APT29")
    a2 = stix2.ThreatActor(name="apt-29")   # same normalised name
    mw = stix2.Malware(name="WellMess", is_family=True)
    objs = [a1, a2, mw, stix2.Relationship(a2, "uses", mw)]

    stats = complete_graph(
        objs, policy={"completion": {"alias": True, "transitive": False}}
    )

    actors = [o for o in objs if o.get("type") == "threat-actor"]
    assert len(actors) == 1                       # duplicate removed
    assert stats.aliases_merged == 1
    rels = _rels(objs)
    assert len(rels) == 1
    assert rels[0].get("source_ref") == actors[0].id   # rewired to canonical


def test_alias_merge_never_merges_distinct_iocs():
    """Look-alike CVE vulnerabilities must stay separate (IOC protection)."""
    v1 = stix2.Vulnerability(name="CVE-2023-23397")
    v2 = stix2.Vulnerability(name="CVE-2023-23392")
    objs = [v1, v2]
    complete_graph(objs)
    # Vulnerabilities are not even in the aliasable set, and IOC guard applies.
    assert len([o for o in objs if o.get("type") == "vulnerability"]) == 2


# ── Step 1b: ATT&CK reference grounding ───────────────────────────────────────
def test_reference_grounding_adds_curated_edge():
    """APT29 (G0016) + Mimikatz (S0002) are both in ATT&CK's curated 'uses'
    list — grounding adds the edge with 'reported' evidence and provenance."""
    import pipeline.stage4b_graph_completion as s4b
    if not s4b._attack_pairs():
        pytest.skip("attack_relationships.json not built")

    actor = stix2.ThreatActor(name="APT29")
    mw = stix2.Malware(name="Mimikatz", is_family=True)
    objs = [actor, mw]

    stats = complete_graph(objs, policy={"completion": {"transitive": False,
                                                        "alias": False}})

    assert stats.reference_added >= 1
    refs = [o for o in _rels(objs) if o.get("x_evidence_label") == "reported"]
    assert any(o.get("x_inference_rule") == "attack-reference:G0016>S0002"
               for o in refs)


def test_reference_grounding_can_be_disabled():
    actor = stix2.ThreatActor(name="APT29")
    mw = stix2.Malware(name="Mimikatz", is_family=True)
    objs = [actor, mw]
    stats = complete_graph(objs, policy={"completion": {"reference": False}})
    assert stats.reference_added == 0


def test_reference_grounding_no_edge_for_unknown_names():
    actor = stix2.ThreatActor(name="TotallyUnknownActor12345")
    mw = stix2.Malware(name="NoSuchMalware98765", is_family=True)
    objs = [actor, mw]
    stats = complete_graph(objs)
    assert stats.reference_added == 0


# ── Step 1 (semantic): embedding-based alias matching ─────────────────────────
def test_semantic_alias_merges_on_fake_model(monkeypatch):
    """With a fake embedding model that maps two names to the same vector, the
    semantic pass merges them; unrelated names stay separate."""
    # numpy is not installed in the CI fast-unit-test job (it only pulls the
    # parsing + test deps), and the semantic pass is optional by design.
    np = pytest.importorskip("numpy")

    import pipeline.stage2c_ttp_semantic as s2c

    class FakeModel:
        def encode(self, names):
            # 'APT29' and 'the Dukes' → same vector; others orthogonal.
            vecs = []
            for n in names:
                if n in ("APT29", "the Dukes"):
                    vecs.append([1.0, 0.0])
                else:
                    vecs.append([0.0, 1.0])
            return np.array(vecs)

    monkeypatch.setattr(s2c, "_load_model", lambda: FakeModel())

    a1 = stix2.ThreatActor(name="APT29")
    a2 = stix2.ThreatActor(name="the Dukes")
    a3 = stix2.ThreatActor(name="Lazarus Group")
    objs = [a1, a2, a3]

    stats = complete_graph(
        objs,
        policy={"completion": {"alias": True, "semantic_alias": True,
                               "transitive": False, "reference": False}},
    )

    actors = [o for o in objs if o.get("type") == "threat-actor"]
    assert len(actors) == 2          # APT29 + the Dukes merged; Lazarus separate
    assert stats.aliases_merged == 1


def test_semantic_alias_noop_without_model(monkeypatch):
    import pipeline.stage2c_ttp_semantic as s2c
    monkeypatch.setattr(s2c, "_load_model", lambda: None)

    a1 = stix2.ThreatActor(name="APT29")
    a2 = stix2.ThreatActor(name="the Dukes")
    objs = [a1, a2]
    stats = complete_graph(
        objs,
        policy={"completion": {"alias": True, "semantic_alias": True,
                               "reference": False}},
    )
    assert stats.aliases_merged == 0
    assert any("model unavailable" in n for n in stats.notes)


# ── Policy control: user specifies vs tool decides ────────────────────────────
def test_completion_can_be_disabled():
    actor = stix2.IntrusionSet(name="A")
    mw = stix2.Malware(name="B", is_family=True)
    ap = stix2.AttackPattern(name="C")
    objs = [actor, mw, ap,
            stix2.Relationship(actor, "uses", mw),
            stix2.Relationship(mw, "uses", ap)]

    stats = complete_graph(
        objs, policy={"completion": {"transitive": False, "alias": False}}
    )

    assert stats.transitive_added == 0
    assert not _inferred(objs)


def test_pin_overrides_inferred_verb():
    """A pinned rule for the inferred pair replaces the composed verb."""
    actor = stix2.IntrusionSet(name="A")
    mw = stix2.Malware(name="B", is_family=True)
    ap = stix2.AttackPattern(name="C")
    objs = [actor, mw, ap,
            stix2.Relationship(actor, "uses", mw),
            stix2.Relationship(mw, "uses", ap)]
    policy = {
        "global": "enforce",
        "rules": [{"src": "intrusion-set", "tgt": "attack-pattern",
                   "verb": "targets", "mode": "pin", "enabled": True}],
    }

    complete_graph(objs, policy=policy)

    # intrusion-set --targets--> attack-pattern is NOT suggested, so the pinned
    # verb makes the guard drop the edge rather than emit the un-pinned "uses".
    assert ("intrusion-set", "uses", "attack-pattern") not in _triples(objs)


# ── Step 3: long-distance (opt-in, fake inferer) ──────────────────────────────
def test_connected_components_counts_islands():
    a, b, c = "malware--a", "malware--b", "tool--c"
    # _connected_components only needs objects exposing .get(); use plain dicts
    # so we don't have to mint valid STIX ids just to partition a node set.
    r = {"source_ref": a, "target_ref": b}
    comps = _connected_components({a, b, c}, [r])
    assert len(comps) == 2


def test_long_distance_connects_islands_with_fake_inferer():
    """Two disconnected sub-graphs; the fake inferer links the island's central
    node to the topic node with a suggested verb."""
    # Sub-graph 1 (topic side): intrusion-set with two edges → highest degree.
    actor = stix2.IntrusionSet(name="APT")
    mw = stix2.Malware(name="MW", is_family=True)
    tool = stix2.Tool(name="TL")
    g1 = [actor, mw, tool,
          stix2.Relationship(actor, "uses", mw),
          stix2.Relationship(actor, "uses", tool)]
    # Sub-graph 2 (island): a lone attack-pattern touching one malware.
    ap = stix2.AttackPattern(name="AP")
    mw2 = stix2.Malware(name="MW2", is_family=True)
    g2 = [ap, mw2, stix2.Relationship(mw2, "uses", ap)]
    objs = g1 + g2

    def fake_infer(central, topic, text):
        # Link island's malware --uses--> topic actor's... actor is topic; but
        # actor uses malware is suggested with actor as source.
        return InferredEdge(source_id=topic.id, verb="uses", target_id=central.id)

    stats = complete_graph(
        objs,
        policy={"completion": {"long_distance": True, "transitive": False}},
        report_text="irrelevant",
        long_distance_infer=fake_infer,
    )

    assert stats.long_distance_added >= 1
    assert _inferred(objs)


def test_long_distance_off_by_default():
    actor = stix2.IntrusionSet(name="A")
    mw = stix2.Malware(name="B", is_family=True)
    objs = [actor, mw, stix2.Relationship(actor, "uses", mw)]

    called = {"n": 0}

    def infer(a, b, t):
        called["n"] += 1
        return None

    # long_distance defaults off → inferer never called even if supplied.
    complete_graph(objs, report_text="x", long_distance_infer=infer)
    assert called["n"] == 0


# ── End-to-end through build_stix_bundle ──────────────────────────────────────
def test_build_stix_bundle_runs_completion():
    """A full bundle build should surface an inferred edge from a uses-chain and
    keep producing a valid stix2.Bundle."""
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WellMess"],
        ttps=[TTPExtracted(technique_name="Phishing", mitre_id="T1566")],
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="uses",
                                  target_value="WellMess", confidence=0.9),
            RelationshipExtracted(source_value="WellMess", relationship_type="uses",
                                  target_value="Phishing", confidence=0.9),
        ],
    )
    bundle = build_stix_bundle([RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4)],
                               llm, "rpt")
    assert isinstance(bundle, stix2.Bundle)
    inferred = [o for o in bundle.objects
                if o.get("type") == "relationship"
                and o.get("x_evidence_label") == "inferred"]
    assert any(o.get("x_inference_rule", "").startswith("transitive:") for o in inferred)
