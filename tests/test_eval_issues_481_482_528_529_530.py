"""Evaluation scores must not depend on the order of their inputs, and the
in-house negative cases must normalise what the positive paths normalise
(#481, #482, #528, #529, #530).
"""
from __future__ import annotations

import itertools

import pytest

from evaluation import inhouse
from evaluation.metrics import score_entities


def _doc(gold: dict, layers=()) -> inhouse.InhouseDoc:
    return inhouse.InhouseDoc("d", None, gold, frozenset(layers))


# ── #481: one-to-one entity matching must not depend on the order ───────────

def test_entity_matching_is_independent_of_gold_order():
    """Greedy matching gave TP=1 in one gold order and TP=2 in the other (#481)."""
    pred = [("malware", "A"), ("malware", "B")]
    gold = [("malware", "X", {"A", "B"}), ("malware", "Y", {"A"})]
    for order in itertools.permutations(gold):
        c = score_entities(pred, list(order))["malware"]
        assert (c.tp, c.fp, c.fn) == (2, 0, 0), order


def test_entity_matching_maximises_matches_in_any_order():
    """A-Y and B-Z are both exact; a greedy pass that takes A-X leaves B-Z unused (#481)."""
    pred = [("malware", "A"), ("malware", "B")]
    gold = [("malware", "X", {"A", "B"}), ("malware", "Y", {"A"}), ("malware", "Z", {"B"})]
    for p, g in itertools.product(itertools.permutations(pred), itertools.permutations(gold)):
        c = score_entities(list(p), list(g))["malware"]
        assert (c.tp, c.fp, c.fn) == (2, 0, 1), (p, g)


# ── #482: the agreement F1 must not depend on which annotator comes first ───

def test_agreement_f1_is_the_same_whichever_annotator_is_first():
    """b's alias was ignored, so the entity F1 was 1 one way and 0 the other (#482)."""
    a = {"layers": ["entities"], "entities": [
        {"type": "malware", "value": "Alpha", "aliases": ["Bravo"]}]}
    b = {"layers": ["entities"], "entities": [
        {"type": "malware", "value": "Bravo", "aliases": []}]}
    ab = inhouse.agreement(a, b)["entities"]
    ba = inhouse.agreement(b, a)["entities"]
    assert ab["f1"] == ba["f1"] == 1.0
    assert ab["tp"] == ba["tp"] == 1


# ── #528: technique negatives go through the same canonical() as the positives ─

def test_negative_technique_matches_lowercase_prediction_through_canonical():
    """A lowercase predicted sub-technique must still violate its parent negative (#528)."""
    doc = _doc({"layers": ["techniques"], "techniques": [],
                "negatives": [{"kind": "technique", "id": "T1059"}]}, ["techniques"])
    pred = {"ttp_ids": ["t1059.001"], "entities": [], "relations": []}

    s = inhouse.score(doc, pred, canonical=lambda x: x.upper())

    assert s["negatives"]["violations"] == [{"kind": "technique", "id": "T1059"}]


def test_negative_technique_matches_a_revoked_prediction_through_canonical():
    """A revoked id that canonical() maps onto T1059.001 violates the T1059 negative (#528)."""
    revoked = {"T1086": "T1059.001"}

    def canonical(tid: str) -> str:
        tid = tid.upper()
        return revoked.get(tid, tid)

    doc = _doc({"layers": ["techniques"], "techniques": [],
                "negatives": [{"kind": "technique", "id": "T1059"}]}, ["techniques"])
    pred = {"ttp_ids": ["T1086"], "entities": [], "relations": []}

    s = inhouse.score(doc, pred, canonical=canonical)

    assert s["negatives"]["violated"] == 1


# ── #529: relation negatives normalise spaces like score_relations does ─────

@pytest.mark.parametrize("source", ["APT  29", "APT 29"])
def test_negative_relation_matches_prediction_with_spacing_variants(source):
    """`APT 29` in a negative must meet `APT  29` or `APT<nbsp>29` in the prediction (#529)."""
    doc = _doc({"layers": [], "negatives": [
        {"kind": "relation", "triple": ["APT 29", "uses", "Mimikatz"], "why": "generic"}]})
    pred = {"ttp_ids": [], "entities": [],
            "relations": [{"source": source, "type": "uses", "target": "Mimikatz"}]}

    s = inhouse.score(doc, pred, lambda t: t)

    assert s["negatives"]["violated"] == 1


# ── #530: case normalisation of cve, mac_addr and ipv6 IoCs ─────────────────

def test_cve_mac_and_ipv6_values_are_case_normalised():
    """`cve-2024-3400` and `CVE-2024-3400` are the same IoC (#530)."""
    assert inhouse._ioc_norm("cve", "cve-2024-3400") == ("cve", "CVE-2024-3400")
    assert inhouse._ioc_norm("mac_addr", "00:1a:2b:3c:4d:5e") == ("mac_addr", "00:1a:2b:3c:4d:5e")
    assert inhouse._ioc_norm("ipv6", "2001:DB8::1") == ("ipv6", "2001:db8::1")


def test_cve_iocs_in_different_case_are_one_true_positive():
    """Gold `cve-2024-3400` against predicted `CVE-2024-3400` gave 1 FP + 1 FN before (#530)."""
    doc = _doc({"layers": ["iocs"], "iocs": [{"type": "cve", "value": "cve-2024-3400"}]}, ["iocs"])
    pred = {"ttp_ids": [], "entities": [{"type": "cve", "value": "CVE-2024-3400"}], "relations": []}

    c = inhouse.score(doc, pred, lambda t: t)["iocs"]

    assert (c.tp, c.fp, c.fn) == (1, 0, 0)
