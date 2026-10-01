"""Tests for Stage 4c — LLM-backed long-distance relation inferer (ADR-0013).

The inferer is exercised with a fake ``llm_fn`` (no network): it must enforce the
same evidence bar as Stage 3d (a quoted supporting sentence is mandatory), honour
the stated direction, reject invalid/unsupported answers, and — through
``complete_graph`` — actually connect two disconnected sub-graphs.
"""
import json

import stix2

from pipeline.stage4b_graph_completion import complete_graph
from pipeline.stage4c_long_distance import (
    build_long_distance_inferer,
    default_long_distance_inferer,
)


def _fake_llm(payload: dict):
    """Return an llm_fn that always answers with the given JSON payload."""
    return lambda system, user: json.dumps(payload)


# ── inferer unit behaviour ────────────────────────────────────────────────────
def test_inferer_returns_edge_with_quote_and_direction():
    actor = stix2.IntrusionSet(name="APT-X")
    mw = stix2.Malware(name="MW", is_family=True)
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "a", "verb": "uses",
                   "quote": "APT-X deployed MW in the campaign."})
    )
    edge = infer(actor, mw, "APT-X deployed MW in the campaign.")
    assert edge is not None
    assert edge.source_id == actor.id and edge.target_id == mw.id
    assert edge.verb == "uses"
    assert edge.evidence_text == "APT-X deployed MW in the campaign."


def test_inferer_direction_b_swaps_endpoints():
    actor = stix2.IntrusionSet(name="APT-X")
    mw = stix2.Malware(name="MW", is_family=True)
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "b", "verb": "authored-by",
                   "quote": "MW was authored by APT-X."})
    )
    # central=mw, topic=actor; source "b" => subject is topic (actor)... but here
    # A is mw and B is actor, so subject "b" = actor is wrong; direction maps to
    # (topic, central). We pass central=mw, topic=actor.
    edge = infer(mw, actor, "MW was authored by APT-X.")
    assert edge.source_id == actor.id and edge.target_id == mw.id


def test_inferer_requires_quote():
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "a", "verb": "uses", "quote": ""})
    )
    assert infer(a, b, "text") is None   # no supporting sentence → no edge


def test_inferer_rejects_unrelated():
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    infer = build_long_distance_inferer(
        _fake_llm({"related": False, "source": None, "verb": None, "quote": None})
    )
    assert infer(a, b, "text") is None


def test_inferer_rejects_invalid_verb():
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "a", "verb": "pwns", "quote": "x uses y"})
    )
    assert infer(a, b, "text") is None


def test_inferer_handles_empty_llm_response():
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    infer = build_long_distance_inferer(lambda s, u: "")
    assert infer(a, b, "text") is None


# ── what report text each question is sent ────────────────────────────────────
def _prompt_seen(a, b, report_text, **kw) -> str:
    seen = []
    infer = build_long_distance_inferer(lambda s, u: seen.append(u) or "", **kw)
    infer(a, b, report_text)
    return seen[0]


def _filler(n: int) -> str:
    return "Unrelated background sentence about the threat landscape. " * (n // 58 + 1)


def test_a_report_within_the_budget_is_sent_whole():
    text = _filler(9_000) + "APT-X deployed MW."
    prompt = _prompt_seen(stix2.IntrusionSet(name="APT-X"), stix2.Malware(name="MW", is_family=True), text)
    assert text in prompt


def test_a_long_report_sends_the_passages_naming_the_entities():
    # Both entities are named only far past the old 6 000-character cut.
    statement = "Later analysis showed that APT-X deployed Mistral against the energy sector."
    text = _filler(40_000) + statement + " " + _filler(40_000)
    prompt = _prompt_seen(stix2.IntrusionSet(name="APT-X"), stix2.Malware(name="Mistral", is_family=True),
                          text, max_chars=3_000)
    assert statement in prompt
    assert len(prompt) < 3_000 + 1_000   # the excerpt plus the question around it


def test_aliases_and_attack_ids_find_passages_too():
    ap = stix2.AttackPattern(name="PowerShell", external_references=[
        {"source_name": "mitre-attack", "external_id": "T1059.001"}])
    actor = stix2.IntrusionSet(name="APT34", aliases=["OilRig"])
    statement = "OilRig relied on T1059.001 for execution."
    text = _filler(30_000) + statement + " " + _filler(30_000)
    assert statement in _prompt_seen(actor, ap, text, max_chars=3_000)


def test_passages_naming_both_entities_come_before_the_rest():
    both = "APT-X deployed Mistral on the servers."
    early = "APT-X was first seen in 2019."   # names A only, but earlier
    text = early + " " + _filler(20_000) + " " + both + " " + _filler(20_000)
    prompt = _prompt_seen(stix2.IntrusionSet(name="APT-X"), stix2.Malware(name="Mistral", is_family=True),
                          text, max_chars=1_000)
    assert both in prompt and early not in prompt


def test_two_letter_names_do_not_pick_passages():
    # "Go" would match inside "good", "ago", "Google" all over the report.
    text = "Opening paragraph. " + _filler(30_000) + " It was a good day ago."
    prompt = _prompt_seen(stix2.Malware(name="Go", is_family=True), stix2.Malware(name="Absent", is_family=True),
                          text, max_chars=2_000)
    assert "Opening paragraph." in prompt and "good day" not in prompt


def test_no_mention_falls_back_to_the_start_of_the_report():
    text = "Opening paragraph. " + _filler(30_000)
    prompt = _prompt_seen(stix2.IntrusionSet(name="Nowhere"), stix2.Malware(name="Absent", is_family=True),
                          text, max_chars=2_000)
    assert "Opening paragraph." in prompt


# ── integration through complete_graph ────────────────────────────────────────
def test_long_distance_connects_islands_and_records_evidence():
    # Sub-graph 1 (topic side): intrusion-set with the highest degree.
    actor = stix2.IntrusionSet(name="APT")
    mw = stix2.Malware(name="MW", is_family=True)
    tool = stix2.Tool(name="TL")
    g1 = [actor, mw, tool,
          stix2.Relationship(actor, "uses", mw),
          stix2.Relationship(actor, "uses", tool)]
    # Sub-graph 2 (island).
    ap = stix2.AttackPattern(name="AP")
    mw2 = stix2.Malware(name="MW2", is_family=True)
    g2 = [ap, mw2, stix2.Relationship(mw2, "uses", ap)]
    objs = g1 + g2

    # Fake inferer: topic (actor) --uses--> island central; always a suggested
    # edge because the actor is an intrusion-set.
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "b", "verb": "uses",
                   "quote": "The group also used it."})
    )

    stats = complete_graph(
        objs,
        policy={"completion": {"long_distance": True, "transitive": False}},
        report_text="The group also used it.",
        long_distance_infer=infer,
    )

    assert stats.long_distance_added >= 1
    inferred = [o for o in objs if o.get("type") == "relationship"
                and o.get("x_evidence_label") == "inferred"]
    assert inferred
    assert any(o.get("x_inference_rule") == "long-distance" for o in inferred)
    assert any(o.get("x_evidence_text") == "The group also used it." for o in inferred)


# ── default_long_distance_inferer gating ──────────────────────────────────────
def test_default_inferer_none_when_policy_disabled():
    assert default_long_distance_inferer(None) is None
    assert default_long_distance_inferer({"completion": {"long_distance": False}}) is None


def test_default_inferer_none_when_provider_not_ready(monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_provider_ready", lambda *a, **k: False)
    got = default_long_distance_inferer({"completion": {"long_distance": True}})
    assert got is None


def test_default_inferer_builds_when_enabled_and_ready(monkeypatch):
    import pipeline.stage3_llm as s3
    monkeypatch.setattr(s3, "_provider_ready", lambda *a, **k: True)
    monkeypatch.setattr(
        s3, "_call_llm",
        lambda system, user, provider=None: json.dumps(
            {"related": True, "source": "a", "verb": "uses", "quote": "a uses b"}
        ),
    )
    infer = default_long_distance_inferer({"completion": {"long_distance": True}})
    assert callable(infer)
    a = stix2.IntrusionSet(name="A")
    b = stix2.Malware(name="B", is_family=True)
    edge = infer(a, b, "a uses b")
    assert edge is not None and edge.verb == "uses"
