"""Long-distance completion links SDOs only (issues #417 and #412, ADR-0013).

The source Artifact, the observables and the Indicators are not central nodes
and not endpoints: an edge the model proposes to one of them is refused into the
ledger, and a lone observable never becomes the sub-graph's central node (which
used to get it a direct ``related-to`` edge, bypassing Indicator routing).
No network: the inferer is a fake or a fake LLM.
"""
import json

import stix2

from pipeline.stage4b_graph_completion import InferredEdge, complete_graph
from pipeline.stage4c_long_distance import build_long_distance_inferer

_POLICY = {"completion": {"long_distance": True, "transitive": False}}


def _islands():
    """A topic island (intrusion-set with the highest degree) and a second
    island (one malware with an attack-pattern)."""
    actor = stix2.IntrusionSet(name="APT")
    mw = stix2.Malware(name="MW", is_family=True)
    tool = stix2.Tool(name="TL")
    ap = stix2.AttackPattern(name="AP")
    mw2 = stix2.Malware(name="MW2", is_family=True)
    objs = [actor, mw, tool, mw2, ap,
            stix2.Relationship(actor, "uses", mw),
            stix2.Relationship(actor, "uses", tool),
            stix2.Relationship(mw2, "uses", ap)]
    return actor, mw2, objs


def _long_distance_rels(objs):
    return [o for o in objs if o.get("type") == "relationship"
            and o.get("x_inference_rule") == "long-distance"]


def test_issue_412_isolated_domain_name_gets_no_direct_edge():
    """Repro of #412: a lone domain-name was the central node of its island and
    got a direct related-to edge to the threat actor."""
    actor, _, objs = _islands()
    dom = stix2.DomainName(value="evil.example")
    objs.append(dom)
    asked = []

    def infer(central, topic, text):
        asked.append((central.type, topic.type))
        return InferredEdge(source_id=dom.id, verb="related-to", target_id=actor.id,
                            confidence=0.6, evidence_text="x")

    stats = complete_graph(objs, policy=_POLICY, report_text="x",
                           long_distance_infer=infer)

    assert all("domain-name" not in pair for pair in asked)
    assert stats.long_distance_added == 0
    assert _long_distance_rels(objs) == []


def test_issue_417_artifact_of_the_source_pdf_is_not_a_central_node():
    """The source Artifact is isolated in the graph: it must not be asked about."""
    actor, mw2, objs = _islands()
    pdf = stix2.Artifact(mime_type="application/pdf", payload_bin="JVBERi0=")
    objs.append(pdf)
    asked = []

    def infer(central, topic, text):
        asked.append(central.type)
        return None

    complete_graph(objs, policy=_POLICY, report_text="x", long_distance_infer=infer)

    assert len(asked) == 1 and asked[0] != "artifact"   # the SDO island only
    assert _long_distance_rels(objs) == []


def test_issue_417_sdo_islands_still_connect_with_an_artifact_present():
    """Control: the SDO islands still connect when an Artifact is in the graph."""
    actor, mw2, objs = _islands()
    objs.append(stix2.Artifact(mime_type="application/pdf", payload_bin="JVBERi0="))

    stats = complete_graph(
        objs, policy=_POLICY, report_text="x",
        long_distance_infer=lambda central, topic, text: InferredEdge(
            source_id=topic.id, verb="uses", target_id=central.id,
            confidence=0.6, evidence_text="x"),
    )

    assert stats.long_distance_added == 1
    (edge,) = _long_distance_rels(objs)
    assert edge.source_ref == actor.id   # the topic actor uses the island's node


def test_issue_417_edge_to_a_non_sdo_is_refused_into_the_ledger():
    """An edge the model proposes to a non-SDO object is not added and is kept in
    the refusal ledger under the long-distance rule, once per triple."""
    actor, mw2, objs = _islands()
    dom = stix2.DomainName(value="evil.example")
    objs.append(dom)

    def infer(central, topic, text):
        return InferredEdge(source_id=dom.id, verb="related-to", target_id=topic.id,
                            confidence=0.6, evidence_text="x")

    stats = complete_graph(objs, policy=_POLICY, report_text="x",
                           long_distance_infer=infer)

    assert stats.long_distance_added == 0
    assert _long_distance_rels(objs) == []
    assert [(r["source_ref"], r["relationship_type"], r["rule"], r["reason"])
            for r in stats.refused] == [(dom.id, "related-to", "long-distance", "not_an_sdo")]


def test_issue_417_stage4c_inferer_does_not_ask_the_llm_about_an_observable():
    """The Stage 4c inferer answers None for a non-SDO endpoint without calling
    the LLM, so no quoted edge can reach the graph."""
    actor = stix2.IntrusionSet(name="APT")
    dom = stix2.DomainName(value="evil.example")
    calls = []

    def llm(system, user):
        calls.append(user)
        return json.dumps({"related": True, "source": "a", "verb": "related-to",
                           "quote": "evil.example is used by APT."})

    infer = build_long_distance_inferer(llm)

    assert infer(dom, actor, "evil.example is used by APT.") is None
    assert infer(actor, dom, "evil.example is used by APT.") is None
    assert calls == []
