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
    HELD_FOR_REVIEW,
    REJECTED_BY_ANALYST,
    InferredEdge,
    RefusedRelationship,
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


def test_an_indicator_does_not_inherit_its_malwares_techniques():
    """ADR-0068: indicator --indicates--> malware --uses--> attack-pattern
    no longer composes to indicator --indicates--> attack-pattern.  A YARA
    rule for a binary detects the malware, not every technique it uses."""
    mw = stix2.Malware(name="INDUSTROYER.V2", is_family=True)
    ap = stix2.AttackPattern(name="Native API")
    ind = stix2.Indicator(name="Yara rule: R", pattern="rule R { condition: true }",
                          pattern_type="yara", valid_from="2026-10-02T00:00:00Z")
    objs = [mw, ap, ind,
            stix2.Relationship(ind, "indicates", mw, confidence=90),
            stix2.Relationship(mw, "uses", ap, confidence=90)]

    stats = complete_graph(objs)

    assert stats.transitive_added == 0
    assert ("indicator", "indicates", "attack-pattern") not in _triples(objs)


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
    refs = [o for o in _rels(objs) if o.get("x_evidence_label") == "external-reference"]
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


# ── What the report does not state stays out of its Report (audit 8.4.2, 8.4.3) ─

def test_edges_the_report_does_not_state_ship_outside_the_report():
    """MITRE's curated edges and the ones composed from two others ship in the
    bundle but not in the Report's object_refs: OpenCTI files a Report's
    object_refs as contained in that report, and these are not the report's."""
    import pipeline.stage4b_graph_completion as s4b
    from pipeline.bundle_ledger import MappingLedger

    if not s4b._attack_pairs():
        pytest.skip("attack_relationships.json not built")
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["Mimikatz", "WellMess"],
        ttps=[TTPExtracted(technique_name="Phishing", mitre_id="T1566", description="",
                           evidence_text="WellMess was delivered by phishing emails to staff.")],
        relationships=[
            RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="WellMess",
                                  confidence=0.8, evidence_text="APT29 used WellMess."),
            RelationshipExtracted(source_value="WellMess", relationship_type="uses", target_value="Phishing",
                                  confidence=0.8, evidence_text="WellMess was delivered by phishing."),
        ],
    )
    ledger = MappingLedger()
    bundle = build_stix_bundle([], llm, "r", report_text="APT29 used WellMess and Mimikatz.",
                               ledger=ledger)
    [report] = [o for o in bundle.objects if o["type"] == "report"]
    rels = [o for o in bundle.objects if o["type"] == "relationship"]
    reference = [r for r in rels if str(r.get("x_inference_rule", "")).startswith("attack-reference:")]
    transitive = [r for r in rels if str(r.get("x_inference_rule", "")).startswith("transitive:")]
    extracted = [r for r in rels if not r.get("x_inference_rule")]
    assert reference and transitive and extracted
    assert all(r["x_evidence_label"] == "external-reference" for r in reference)
    for r in reference + transitive:
        assert r.id not in report["object_refs"]
        assert ledger.to_dict()["objects"][r.id]["outside_report"] is True
    assert all(r.id in report["object_refs"] for r in extracted)


# ── A rejected relationship stays rejected (ADR-0013, amendment 2026-10-26) ───

def _chain():
    """Zeta Group uses ZetaRAT, ZetaRAT uses ZetaLoader: uses+uses composes
    Zeta Group uses ZetaLoader."""
    a = stix2.IntrusionSet(name="Zeta Group")
    b = stix2.Malware(name="ZetaRAT", is_family=True)
    c = stix2.Malware(name="ZetaLoader", is_family=True)
    ab = stix2.Relationship(a, "uses", b, confidence=80)
    bc = stix2.Relationship(b, "uses", c, confidence=80)
    return a, b, c, ab, bc


def _has_edge(objs, src, verb, tgt) -> bool:
    return any((r.get("source_ref"), r.get("relationship_type"), r.get("target_ref"))
               == (src.id, verb, tgt.id) for r in _rels(objs))


def test_transitive_does_not_add_back_a_rejected_triple():
    """The audit's case: the analyst rejected "Zeta Group uses ZetaLoader", so
    finalize left the row out, and uses+uses composed it back."""
    a, b, c, ab, bc = _chain()
    objs = [a, b, c, ab, bc]

    stats = complete_graph(objs, forbidden={(a.id, "uses", c.id): REJECTED_BY_ANALYST})

    assert stats.transitive_added == 0
    assert not _has_edge(objs, a, "uses", c)
    assert stats.refused == [{
        "source_ref": a.id, "relationship_type": "uses", "target_ref": c.id,
        "rule": "transitive:uses+uses", "reason": REJECTED_BY_ANALYST,
        "inferred_from": [ab.id, bc.id],
    }]


def test_a_held_triple_is_not_inferred_while_it_waits():
    a, b, c, ab, bc = _chain()
    objs = [a, b, c, ab, bc]

    stats = complete_graph(objs, forbidden={(a.id, "uses", c.id): HELD_FOR_REVIEW})

    assert not _has_edge(objs, a, "uses", c)
    assert [r["reason"] for r in stats.refused] == [HELD_FOR_REVIEW]


def test_a_refused_triple_costs_no_budget():
    """The budget is spent on C2 first; the refused C1 that follows is refused,
    not counted against the cap."""
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    c1 = stix2.AttackPattern(name="C1")
    c2 = stix2.AttackPattern(name="C2")
    objs = [a, b, c1, c2, stix2.Relationship(a, "uses", b),
            stix2.Relationship(b, "uses", c2), stix2.Relationship(b, "uses", c1)]

    stats = complete_graph(objs, policy={"completion": {"max_new_edges": 1, "reference": False}},
                           forbidden={(a.id, "uses", c1.id): REJECTED_BY_ANALYST})

    assert stats.transitive_added == 1 and not stats.capped
    assert _has_edge(objs, a, "uses", c2) and not _has_edge(objs, a, "uses", c1)
    assert [r["target_ref"] for r in stats.refused] == [c1.id]


def test_an_undirected_verb_is_refused_both_ways():
    """Rejecting "APT related-to MW2" rules out "MW2 related-to APT", the
    direction the long-distance inferer may answer instead."""
    actor = stix2.IntrusionSet(name="APT")
    mw = stix2.Malware(name="MW", is_family=True)
    mw2 = stix2.Malware(name="MW2", is_family=True)
    ap = stix2.AttackPattern(name="AP")
    objs = [actor, mw, mw2, ap,
            stix2.Relationship(actor, "uses", mw), stix2.Relationship(mw2, "uses", ap)]

    stats = complete_graph(
        objs, policy={"completion": {"long_distance": True, "transitive": False}},
        report_text="irrelevant",
        long_distance_infer=lambda central, topic, text: InferredEdge(mw2.id, "related-to", actor.id),
        forbidden={(actor.id, "related-to", mw2.id): REJECTED_BY_ANALYST},
    )

    assert stats.long_distance_added == 0
    assert not _has_edge(objs, mw2, "related-to", actor)
    assert [(r["source_ref"], r["target_ref"]) for r in stats.refused] == [(mw2.id, actor.id)]


def test_reference_grounding_does_not_add_back_a_rejected_triple():
    """MITRE states APT29 uses Mimikatz; the analyst ruled it out for this
    report, and the tool does not contradict them."""
    import pipeline.stage4b_graph_completion as s4b
    if not s4b._attack_pairs():
        pytest.skip("attack_relationships.json not built")
    actor = stix2.ThreatActor(name="APT29")
    mw = stix2.Malware(name="Mimikatz", is_family=True)
    objs = [actor, mw]

    stats = complete_graph(objs, policy={"completion": {"transitive": False}},
                           forbidden={(actor.id, "uses", mw.id): REJECTED_BY_ANALYST})

    assert stats.reference_added == 0
    assert not _has_edge(objs, actor, "uses", mw)
    assert [(r["rule"], r["reason"]) for r in stats.refused] == [
        ("attack-reference:G0016>S0002", REJECTED_BY_ANALYST)]


def test_long_distance_does_not_add_back_a_rejected_triple():
    actor = stix2.IntrusionSet(name="APT")
    mw = stix2.Malware(name="MW", is_family=True)
    tool = stix2.Tool(name="TL")
    mw2 = stix2.Malware(name="MW2", is_family=True)
    ap = stix2.AttackPattern(name="AP")
    objs = [actor, mw, tool, mw2, ap,
            stix2.Relationship(actor, "uses", mw), stix2.Relationship(actor, "uses", tool),
            stix2.Relationship(mw2, "uses", ap)]

    stats = complete_graph(
        objs, policy={"completion": {"long_distance": True, "transitive": False}},
        report_text="irrelevant",
        long_distance_infer=lambda central, topic, text: InferredEdge(actor.id, "uses", mw2.id),
        forbidden={(actor.id, "uses", mw2.id): REJECTED_BY_ANALYST},
    )

    assert stats.long_distance_added == 0
    assert not _has_edge(objs, actor, "uses", mw2)
    assert [r["rule"] for r in stats.refused] == ["long-distance"]


def test_a_forbidden_triple_follows_an_alias_merge():
    """The row named "apt-29", which the merge absorbs into "APT29": the
    triple Stage 4 resolved it to is moved onto the node that survives."""
    a1 = stix2.ThreatActor(name="APT29")
    a2 = stix2.ThreatActor(name="apt-29")
    mw = stix2.Malware(name="WellMess", is_family=True)
    ap = stix2.AttackPattern(name="Phishing")
    objs = [a1, a2, mw, ap, stix2.Relationship(a1, "uses", mw), stix2.Relationship(mw, "uses", ap)]

    stats = complete_graph(objs, policy={"completion": {"alias": True, "reference": False}},
                           forbidden={(a2.id, "uses", ap.id): REJECTED_BY_ANALYST})

    assert stats.merged_ids == {a2.id: a1.id}
    assert not _has_edge(objs, a1, "uses", ap)
    assert [r["source_ref"] for r in stats.refused] == [a1.id]


def _uses_chain_result() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
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


def test_build_stix_bundle_resolves_a_rejected_row_and_refuses_it_to_completion():
    """The row is resolved as Stage 4 resolves the rows that ship (case,
    verb), and the ledger says what was not added and why."""
    from pipeline.bundle_ledger import MappingLedger

    shipped = MappingLedger()
    build_stix_bundle([], _uses_chain_result(), "rpt", ledger=shipped)
    assert any(o.get("origin") == "completion_transitive" for o in shipped.to_dict()["objects"].values())
    assert "refused" not in shipped.to_dict()

    ledger = MappingLedger()
    bundle = build_stix_bundle(
        [], _uses_chain_result(), "rpt", ledger=ledger,
        refused_relationships=[RefusedRelationship("apt29", " Uses ", "phishing", REJECTED_BY_ANALYST)])

    by_name = {o.get("name"): o.id for o in bundle.objects if o.get("name")}
    assert not [o for o in bundle.objects if o.get("type") == "relationship"
                and str(o.get("x_inference_rule", "")).startswith("transitive:")]
    [refused] = ledger.to_dict()["refused"]
    assert (refused["source_ref"], refused["relationship_type"], refused["target_ref"]) == (
        by_name["APT29"], "uses", by_name["Phishing"])
    assert (refused["rule"], refused["reason"]) == ("transitive:uses+uses", REJECTED_BY_ANALYST)


def test_build_stix_bundle_refuses_a_rejected_row_to_reference_grounding():
    import pipeline.stage4b_graph_completion as s4b
    if not s4b._attack_pairs():
        pytest.skip("attack_relationships.json not built")
    from pipeline.bundle_ledger import MappingLedger

    def _reference_edges(bundle):
        return [o for o in bundle.objects if o.get("type") == "relationship"
                and str(o.get("x_inference_rule", "")).startswith("attack-reference:G0016>S0002")]

    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["Mimikatz"])
    assert _reference_edges(build_stix_bundle([], llm, "rpt"))

    ledger = MappingLedger()
    bundle = build_stix_bundle(
        [], llm, "rpt", ledger=ledger,
        refused_relationships=[RefusedRelationship("APT29", "uses", "Mimikatz", REJECTED_BY_ANALYST)])

    assert not _reference_edges(bundle)
    assert [(r["rule"], r["reason"]) for r in ledger.to_dict()["refused"]] == [
        ("attack-reference:G0016>S0002", REJECTED_BY_ANALYST)]


def test_a_refused_observable_row_is_routed_through_its_indicator():
    """"185.220.101.5 indicates ZetaLoader" ships, when it ships, from the
    address's Indicator; rejected, it forbids that Indicator's edge, which
    indicates+variant-of would compose."""
    from pipeline.bundle_ledger import MappingLedger

    llm = LLMEnrichmentResult(
        malware_families=["ZetaRAT", "ZetaLoader"],
        relationships=[
            RelationshipExtracted(source_value="185.220.101.5", relationship_type="indicates",
                                  target_value="ZetaRAT", confidence=0.9),
            RelationshipExtracted(source_value="ZetaRAT", relationship_type="variant-of",
                                  target_value="ZetaLoader", confidence=0.9),
        ],
    )
    ip = [RawEntity(value="185.220.101.5", entity_type=EntityType.IPV4)]

    def composed(bundle):
        return [o for o in bundle.objects if o.get("type") == "relationship"
                and o.get("x_inference_rule") == "transitive:indicates+variant-of"]

    assert composed(build_stix_bundle(ip, llm, "rpt"))
    ledger = MappingLedger()
    bundle = build_stix_bundle(
        ip, llm, "rpt", ledger=ledger,
        refused_relationships=[RefusedRelationship("185.220.101.5", "indicates", "ZetaLoader",
                                                   REJECTED_BY_ANALYST)])

    assert not composed(bundle)
    by_id = {o.id: o for o in bundle.objects}
    [refused] = ledger.to_dict()["refused"]
    assert by_id[refused["source_ref"]]["type"] == "indicator"
    assert by_id[refused["target_ref"]]["name"] == "ZetaLoader"


def test_a_rejection_outranks_a_hold_on_the_same_triple():
    from pipeline.bundle_ledger import MappingLedger

    ledger = MappingLedger()
    build_stix_bundle([], _uses_chain_result(), "rpt", ledger=ledger, refused_relationships=[
        RefusedRelationship("APT29", "uses", "Phishing", HELD_FOR_REVIEW),
        RefusedRelationship("APT29", "uses", "Phishing", REJECTED_BY_ANALYST),
        RefusedRelationship("APT29", "uses", "Phishing", HELD_FOR_REVIEW),
    ])

    assert [r["reason"] for r in ledger.to_dict()["refused"]] == [REJECTED_BY_ANALYST]


def test_a_refused_row_that_resolves_to_nothing_forbids_nothing():
    """A row whose endpoint is not in the bundle (its entity was rejected too)
    names no triple; completion runs as without it."""
    from pipeline.bundle_ledger import MappingLedger

    ledger = MappingLedger()
    bundle = build_stix_bundle(
        [], _uses_chain_result(), "rpt", ledger=ledger,
        refused_relationships=[RefusedRelationship("APT29", "uses", "NoSuchTool", REJECTED_BY_ANALYST)])

    assert any(str(o.get("x_inference_rule", "")).startswith("transitive:")
               for o in bundle.objects if o.get("type") == "relationship")
    assert "refused" not in ledger.to_dict()
