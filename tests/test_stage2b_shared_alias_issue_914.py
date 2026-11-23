"""Stage 2b — a name shared by two entities of one type (#914: 'thrip' is
Lotus Blossom G0030 and Thrip G0076) is attributed to one of them by the
context of each mention, on both the Aho-Corasick and the regex path.
"""
from __future__ import annotations

import functools
import logging

import pytest

import pipeline.overrides as ov
from pipeline import stage2b_gazetteer as gaz

pytestmark = pytest.mark.skipif(not gaz.available(), reason="gazetteer.json not built")


@pytest.fixture(params=["aho", "regex"])
def matcher(request, monkeypatch):
    """Run each test on both matching paths.  SKIP_HEAVY_MODELS (CI's first job)
    turns the automaton off: the "aho" run must really use it."""
    monkeypatch.setattr(gaz, "_SKIP_HEAVY", False)
    if request.param == "regex":
        monkeypatch.setattr(gaz, "_AHO_AVAILABLE", False)
    ov.reload()
    return request.param


def _emitted(text: str) -> set[tuple[str, str]]:
    results, _ = gaz.match_gazetteer_traced(text, policy_mode="apply")
    return {(r.value, r.mitre_id) for r in results}


def _rival(canonical: str, mitre_id: str) -> dict:
    return {"name": "nm", "canonical": canonical, "entity_type": "malware", "mitre_id": mitre_id}


ALPHA = _rival("Alpha", "S1")
BETA = _rival("Beta", "S2")


def test_the_shared_names_are_grouped_in_index_order(matcher):
    groups = gaz._shared_groups()
    assert {("corona updates", "malware"), ("concipit1248", "malware"), ("spicyomelette", "malware"),
            ("dnsmessenger", "malware"), ("uac-0056", "threat_actor"), ("thrip", "threat_actor")} <= set(groups)
    assert [e["mitre_id"] for e in groups[("thrip", "threat_actor")]] == ["G0030", "G0076"]


@pytest.mark.parametrize("text, expected", [
    ("The malware Corona Updates (S0425) vs Concipit1248 (S0426): we analyzed Corona Updates and Concipit1248.",
     {("Corona Updates", "S0425"), ("Concipit1248", "S0426")}),
    ("We saw Thrip (G0076) and Lotus Blossom (G0030) and Thrip.",
     {("Thrip", "G0076"), ("Lotus Blossom", "G0030")}),
])
def test_both_entities_of_a_shared_alias_are_emitted(matcher, text, expected):
    assert _emitted(text) == expected


@pytest.mark.parametrize("text, word, mitre_id", [
    ("POWERSOURCE dropped DNSMessenger.", "DNSMessenger", "S0145"),
    ("TEXTMATE, also called DNSMessenger.", "DNSMessenger", "S0146"),
])
def test_a_shared_mention_goes_to_the_entity_its_context_names(matcher, text, word, mitre_id):
    # Attribution is checked on the span: both entities are emitted by their own names.
    keep = gaz._shared_alias_filter(text)
    start = text.index(word)
    group = gaz._shared_groups()[("dnsmessenger", "malware")]
    assert [e["mitre_id"] for e in group if keep(e, start, start + len(word))] == [mitre_id]


def test_an_ambiguous_shared_alias_keeps_the_first_entity_and_logs_once(matcher, caplog):
    group = gaz._shared_groups()[("uac-0056", "threat_actor")]
    assert (group[0]["canonical"], group[0]["mitre_id"]) == ("Ember Bear", "G1003")
    caplog.set_level(logging.INFO, logger=gaz.logger.name)

    # The matcher's choice, before the ordinary-word policy (which is off here).
    results, _ = gaz.match_gazetteer_traced("UAC-0056 was active, and UAC-0056 again.", policy_mode="off")

    assert [(r.value, r.mitre_id) for r in results] == [("Ember Bear", "G1003")]
    notes = [r for r in caplog.records if "shared alias 'uac-0056' left ambiguous" in r.getMessage()]
    assert len(notes) == 1
    assert notes[0].getMessage().endswith(
        "shared alias 'uac-0056' left ambiguous: Ember Bear (G1003) kept, Saint Bear (G1031) possible")


def test_the_policy_still_withholds_an_ambiguous_identity_in_apply_mode():
    # Not a matcher rule: the ordinary-word policy has no identity for this mention.
    results, trace = gaz.match_gazetteer_traced("UAC-0056 was active.", policy_mode="apply")
    assert results == []
    assert [(t["form"], t["reason"]) for t in trace] == [("uac-0056", "ambiguous_identity")]


def test_rule_1_an_id_written_right_after_the_mention_decides():
    text = "Seen: nm (S1), and later S2 elsewhere"
    start = text.index("nm")
    verdict = gaz._context_winner(text, start, start + 2, [ALPHA, BETA])
    assert verdict == {"winner": ALPHA, "rule": 1}


def test_an_id_written_before_the_mention_belongs_to_the_name_it_follows():
    """"Concipit1248 (S0426): we analyzed Corona Updates" -- S0426 is not about the mention."""
    text = "Other (S2): we analyzed nm"
    start = text.index("nm")
    verdict = gaz._context_winner(text, start, start + 2, [ALPHA, BETA])
    assert verdict["rule"] != 1


def test_the_second_corona_updates_mention_stays_with_s0425():
    text = ("The malware Corona Updates (S0425) vs Concipit1248 (S0426): "
            "we analyzed Corona Updates and Concipit1248.")
    second = text.rindex("Corona Updates")
    rivals = gaz._shared_groups()[("corona updates", "malware")]
    verdict = gaz._context_winner(text, second, second + len("Corona Updates"), rivals)
    assert verdict["winner"]["mitre_id"] == "S0425"


def test_rule_2_the_mention_is_the_canonical_name_of_a_rival():
    text = "Beta reported it"
    verdict = gaz._context_winner(text, 0, 4, [ALPHA, BETA])
    assert verdict == {"winner": BETA, "rule": 2}


def test_rule_3_the_id_of_a_rival_is_written_further_away():
    text = "nm reported by " + "x" * 50 + " S2"
    verdict = gaz._context_winner(text, 0, 2, [ALPHA, BETA])
    assert verdict == {"winner": BETA, "rule": 3}


def test_rule_4_the_canonical_name_of_a_rival_is_written_elsewhere():
    text = "nm, also Alpha"
    verdict = gaz._context_winner(text, 0, 2, [ALPHA, BETA])
    assert verdict == {"winner": ALPHA, "rule": 4}


def test_no_rule_decides_and_the_first_rival_is_kept():
    text = "nm alone"
    verdict = gaz._context_winner(text, 0, 2, [ALPHA, BETA])
    assert verdict == {"winner": ALPHA, "rule": None}


def test_a_rule_that_keeps_two_rivals_does_not_decide():
    # Both ids are next to the mention: rule 1 keeps two rivals, so the default applies.
    text = "Ref S1 and S2: nm"
    start = text.index("nm")
    verdict = gaz._context_winner(text, start, start + 2, [ALPHA, BETA])
    assert verdict == {"winner": ALPHA, "rule": None}


@pytest.mark.parametrize("text", [
    "The malware Corona Updates (S0425) vs Concipit1248 (S0426): we analyzed Corona Updates and Concipit1248.",
    "We saw Thrip (G0076) and Lotus Blossom (G0030) and Thrip.",
    "POWERSOURCE dropped DNSMessenger. TEXTMATE, also called DNSMessenger. UAC-0056 was active.",
])
def test_both_paths_give_the_same_result_on_shared_aliases(monkeypatch, text):
    monkeypatch.setattr(gaz, "_SKIP_HEAVY", False)     # else both runs take the regex path
    ov.reload()
    assert gaz._AHO_AVAILABLE, "pyahocorasick is needed to compare the two paths"
    assert gaz._build_automaton() is not None
    aho = gaz.match_gazetteer_traced(text, policy_mode="apply")

    monkeypatch.setattr(gaz, "_AHO_AVAILABLE", False)
    ov.reload()
    regex = gaz.match_gazetteer_traced(text, policy_mode="apply")
    monkeypatch.undo()
    ov.reload()

    def shape(out):
        results, trace = out
        return ([(r.value, r.mitre_id, r.confidence, r.context) for r in results], trace)

    assert shape(aho) == shape(regex)


def test_a_text_without_a_shared_name_is_unchanged(matcher, monkeypatch):
    text = "The Lazarus Group deployed WannaCry against the target."
    with_rule = gaz.match_gazetteer_traced(text, policy_mode="apply")
    # A cache-like stub: the conftest teardown still calls _shared_groups.cache_clear().
    monkeypatch.setattr(gaz, "_shared_groups", functools.lru_cache(maxsize=1)(lambda: {}))
    without_rule = gaz.match_gazetteer_traced(text, policy_mode="apply")
    assert with_rule == without_rule
    assert {r.value for r in with_rule[0]} == {"Lazarus Group", "WannaCry"}


@pytest.mark.parametrize("text, expected", [
    ("Lotus Blossom, also known as Thrip, targeted Asia.", {("Lotus Blossom", "G0030")}),
    ("Lotus Blossom (aka Thrip) targeted Asia.", {("Lotus Blossom", "G0030")}),
    ("More_eggs (also known as SpicyOmelette) was delivered.", {("More_eggs", "S0284")}),
])
def test_an_alias_written_after_its_entity_stays_with_it(matcher, text, expected):
    """Rule 0: the mention is an alias of the rival named just before it."""
    assert _emitted(text) == expected


def test_two_actors_listed_side_by_side_are_not_an_alias_link():
    """"and" is no alias link: Thrip is here the canonical name of G0076 (rule 2)."""
    text = "Lotus Blossom and Thrip were both active."
    start = text.index("Thrip")
    rivals = gaz._shared_groups()[("thrip", "threat_actor")]
    verdict = gaz._context_winner(text, start, start + len("Thrip"), rivals)
    assert (verdict["winner"]["mitre_id"], verdict["rule"]) == ("G0076", 2)


@pytest.mark.parametrize("between", [" (", ", also known as ", " (aka ", " a.k.a. ", " - known as "])
def test_the_alias_links(between):
    assert gaz._ALIAS_LINK.fullmatch(between)


@pytest.mark.parametrize("between", [" and ", " (S0425) vs ", ". Later, ", ", ", " or "])
def test_what_is_not_an_alias_link(between):
    assert not gaz._ALIAS_LINK.fullmatch(between)


def test_an_id_after_a_closing_quote_still_decides():
    text = 'The group "UAC-0056" (G1031) was active.'
    start = text.index("UAC-0056")
    rivals = gaz._shared_groups()[("uac-0056", "threat_actor")]
    verdict = gaz._context_winner(text, start, start + len("UAC-0056"), rivals)
    assert (verdict["winner"]["mitre_id"], verdict["rule"]) == ("G1031", 1)
