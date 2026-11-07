"""Stage 4c reads STIX objects given as dicts (#502), and its reply parser skips
a `<think>` block before the answer (#503).
"""
import json

from pipeline.stage4b_graph_completion import InferredEdge
from pipeline.stage4c_long_distance import _parse, build_long_distance_inferer


def _fake_llm(payload: dict):
    """Return an llm_fn that always answers with the given JSON payload."""
    return lambda system, user: json.dumps(payload)


# ── #502: dict objects ───────────────────────────────────────────────────────

def test_dict_objects_give_an_edge_with_their_ids():
    """(#502) Central and topic given as plain dicts: no AttributeError on `.id`."""
    central = {"id": "malware--1", "type": "malware", "name": "BadMalware"}
    topic = {"id": "threat-actor--2", "type": "threat-actor", "name": "BadActor"}
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "b", "verb": "uses",
                   "quote": "BadActor uses BadMalware."})
    )
    edge = infer(central, topic, "BadActor uses BadMalware.")
    assert isinstance(edge, InferredEdge)
    assert edge.source_id == "threat-actor--2"    # source "b" is the topic
    assert edge.target_id == "malware--1"
    assert edge.verb == "uses"


def test_dict_objects_direction_a_keeps_central_as_source():
    """(#502) Source "a" with dicts: the central object is the subject."""
    central = {"id": "malware--1", "type": "malware", "name": "BadMalware"}
    topic = {"id": "threat-actor--2", "type": "threat-actor", "name": "BadActor"}
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "a", "verb": "uses",
                   "quote": "BadMalware is used by BadActor."})
    )
    edge = infer(central, topic, "BadMalware is used by BadActor.")
    assert edge.source_id == "malware--1"
    assert edge.target_id == "threat-actor--2"


def test_dict_object_without_an_id_gives_no_edge():
    """(#502) An object with no id cannot be an edge end: None, not an edge with a None id."""
    central = {"id": "malware--1", "type": "malware", "name": "BadMalware"}
    topic = {"type": "threat-actor", "name": "BadActor"}
    infer = build_long_distance_inferer(
        _fake_llm({"related": True, "source": "a", "verb": "uses",
                   "quote": "BadMalware is used by BadActor."})
    )
    assert infer(central, topic, "BadMalware is used by BadActor.") is None


# ── #503: <think> blocks before the answer ───────────────────────────────────

def test_parse_skips_the_think_block_and_takes_the_answer():
    """(#503) A draft JSON object inside <think> is not the answer."""
    raw = '<think>Test: {"related": false}</think>{"related": true, "source": "b", "verb": "uses", "quote": "q"}'
    assert _parse(raw) == {"related": True, "source": "b", "verb": "uses", "quote": "q"}


def test_parse_answer_after_a_think_block_with_no_braces_inside():
    """(#503) The usual shape: reasoning, then the JSON answer."""
    raw = '<think>The report names two entities.</think>\n{"related": false, "source": null, "verb": null}'
    assert _parse(raw) == {"related": False, "source": None, "verb": None}


def test_parse_unclosed_think_block_gives_none():
    """(#503) A reply cut inside <think> has no answer: None, not the draft."""
    assert _parse('<think>I should answer with {"related": false}') is None


def test_plain_json_is_unchanged():
    """(#503) A reply with no reasoning block parses as before."""
    assert _parse('Here: {"related": false} done.') == {"related": False}
