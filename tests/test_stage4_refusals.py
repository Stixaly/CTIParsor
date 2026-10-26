"""A rejected or held relationship is not built back by the Stage 4 builders
that have no row of their own: the actor × targeted country / sector product,
policy-pinned edges and IoC associations (ADR-0013, amendment 2026-10-26).
Graph completion's side is in test_stage4b_completion.py.
"""
import json

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult, RelationshipExtracted, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle
from pipeline.stage4b_graph_completion import HELD_FOR_REVIEW, REJECTED_BY_ANALYST, RefusedRelationship


def _build(llm, refused=(), entities=(), **kwargs):
    ledger = MappingLedger()
    bundle = build_stix_bundle(list(entities), llm, "rpt", ledger=ledger,
                               refused_relationships=list(refused), **kwargs)
    return bundle, ledger.to_dict()


def _edges(bundle, **props) -> set[tuple[str, str, str]]:
    names = {o.id: o.get("name") or o.get("value") for o in bundle.objects}
    return {(names.get(o.source_ref), o.relationship_type, names.get(o.target_ref))
            for o in bundle.objects
            if o.get("type") == "relationship" and all(o.get(k) == v for k, v in props.items())}


def _refused(ledger, origin) -> list[dict]:
    return [r for r in ledger.get("refused", []) if r["origin"] == origin]


# ── The actor × targeted country / sector product ───────────────────────────

def _targets(relationships=()) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(threat_actors=["APT29"], targeted_countries=["France", "Germany"],
                               targeted_sectors=["Government"], relationships=list(relationships))


def test_the_targets_product_builds_every_pair_when_nothing_is_refused():
    bundle, ledger = _build(_targets())
    assert {("APT29", "targets", "France"), ("APT29", "targets", "Germany"),
            ("APT29", "targets", "Government")} <= _edges(bundle)
    assert "refused" not in ledger


@pytest.mark.parametrize("ner_found_it", [False, True], ids=["list_only", "ner_entity_too"])
def test_a_rejected_row_is_not_rebuilt_by_the_targets_product(ner_found_it):
    """The loop filtered rejected locations, not rejected rows: a rejected
    "APT29 targets France" came back from the LLM's lists.  France is found
    whether only the targeted-country list names it (no bare-name key) or NER
    found it too."""
    entities = [RawEntity(value="France", entity_type=EntityType.LOCATION)] if ner_found_it else []
    bundle, ledger = _build(
        _targets(), [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)], entities)

    edges = _edges(bundle)
    assert ("APT29", "targets", "France") not in edges
    assert {("APT29", "targets", "Germany"), ("APT29", "targets", "Government")} <= edges
    by_id = {o.id: o for o in bundle.objects}
    [refused] = ledger["refused"]
    assert (by_id[refused["source_ref"]].name, refused["relationship_type"],
            by_id[refused["target_ref"]].name) == ("APT29", "targets", "France")
    assert by_id[refused["target_ref"]].type == "location"
    assert (refused["origin"], refused["reason"], refused["actor"], refused["target"]) == (
        "targeted_location", REJECTED_BY_ANALYST, "APT29", "France")


def test_a_held_row_is_not_built_by_the_targets_product_while_it_waits():
    bundle, ledger = _build(
        _targets(), [RefusedRelationship("apt29", "Targets", "government", HELD_FOR_REVIEW)])

    assert ("APT29", "targets", "Government") not in _edges(bundle)
    assert [(r["reason"], r["target"]) for r in _refused(ledger, "targeted_location")] == [
        (HELD_FOR_REVIEW, "Government")]


def test_the_targets_product_keeps_a_refusal_with_graph_completion_off():
    """`graph_completion=False` (an ablation, ADR-0059) turns Stage 4b off,
    not the analyst's decision."""
    bundle, ledger = _build(
        _targets(), [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)],
        graph_completion=False)

    assert ("APT29", "targets", "France") not in _edges(bundle)
    assert [r["origin"] for r in ledger["refused"]] == ["targeted_location"]


def test_a_refused_country_is_listed_once_however_often_the_list_names_it():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], targeted_countries=["France", "france"])
    _, ledger = _build(llm, [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)])

    assert len(_refused(ledger, "targeted_location")) == 1


@pytest.mark.parametrize("ner_found_it", [False, True], ids=["list_only", "ner_entity_too"])
def test_a_row_that_ships_the_same_triple_keeps_the_edge(ner_found_it):
    """Two rows with one triple, one accepted and one rejected: the accepted
    row says it, so nothing is refused.  With France only in the list the row
    resolves to nothing and the product builds the edge, as before."""
    entities = [RawEntity(value="France", entity_type=EntityType.LOCATION)] if ner_found_it else []
    llm = _targets([RelationshipExtracted(source_value="APT29", relationship_type="targets",
                                          target_value="France", confidence=0.9)])
    bundle, ledger = _build(
        llm, [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)], entities)

    assert ("APT29", "targets", "France") in _edges(bundle)
    assert "refused" not in ledger


def test_the_targets_product_refuses_the_verb_the_policy_gives_the_pair():
    """A pinned `threat-actor located-at location` rewrites the rejected row
    and the product's edge alike; the pin pass would build it too."""
    policy = {"version": 1, "global": "enforce",
              "rules": [{"src": "threat-actor", "verb": "located-at", "tgt": "location",
                         "mode": "pin", "enabled": True}]}
    bundle, ledger = _build(
        _targets(), [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)],
        relationship_policy=policy)

    assert not {e for e in _edges(bundle) if e[0] == "APT29" and e[2] == "France"}
    assert ("APT29", "located-at", "Germany") in _edges(bundle)
    assert sorted((r["origin"], r["relationship_type"]) for r in ledger["refused"]) == [
        ("policy_pin", "located-at"), ("targeted_location", "located-at")]


# ── Policy-pinned edges (ADR-0026 / ADR-0024) ────────────────────────────────

_PIN = {"version": 1, "global": "enforce",
        "rules": [{"src": "malware", "verb": "uses", "tgt": "attack-pattern",
                   "mode": "pin", "enabled": True}]}


def _pinned() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(
        malware_families=["WellMess"],
        ttps=[TTPExtracted(technique_name="Phishing", mitre_id="T1566"),
              TTPExtracted(technique_name="Exploit Public-Facing Application", mitre_id="T1190")])


def _pins(bundle) -> set[tuple[str, str, str]]:
    return _edges(bundle, x_policy_rule="malware uses attack-pattern")


def test_a_rejected_row_is_not_pinned_back():
    shipped, _ = _build(_pinned(), relationship_policy=_PIN)
    assert ("WellMess", "uses", "Phishing") in _pins(shipped)

    bundle, ledger = _build(
        _pinned(), [RefusedRelationship("WellMess", "uses", "Phishing", REJECTED_BY_ANALYST)],
        relationship_policy=_PIN)

    assert _pins(bundle) == _pins(shipped) - {("WellMess", "uses", "Phishing")}
    [refused] = _refused(ledger, "policy_pin")
    by_id = {o.id: o for o in bundle.objects}
    assert (by_id[refused["source_ref"]].name, refused["relationship_type"],
            by_id[refused["target_ref"]].name) == ("WellMess", "uses", "Phishing")
    assert (refused["rule"], refused["reason"]) == ("malware uses attack-pattern", REJECTED_BY_ANALYST)
    # The refusals go to the ledger only: the bundle's synthesis stats keep
    # their shape, the refused pair simply not being a candidate.
    [report] = [o for o in bundle.objects if o.get("type") == "report"]
    pin_stats = report["x_synthesis_stats"]["pin"]
    assert "refused" not in json.dumps(pin_stats)
    assert pin_stats["total_candidates"] == len(_pins(shipped)) - 1


def test_a_held_pair_costs_no_pin_budget():
    """Room for one pinned edge: the held pair does not take it, the next one
    does."""
    bundle, ledger = _build(
        _pinned(), [RefusedRelationship("WellMess", "uses", "Phishing", HELD_FOR_REVIEW)],
        relationship_policy={**_PIN, "max_pinned_edges": 1})

    pins = _pins(bundle)
    assert len(pins) == 1 and ("WellMess", "uses", "Phishing") not in pins
    assert [r["reason"] for r in _refused(ledger, "policy_pin")] == [HELD_FOR_REVIEW]


def test_a_refused_row_forbids_the_verb_it_would_have_shipped_with():
    """The pinned rule rewrites "WellMess related-to Phishing" into "uses":
    that is the edge the analyst refused, so the rule does not build it."""
    bundle, ledger = _build(
        _pinned(), [RefusedRelationship("WellMess", "related-to", "Phishing", REJECTED_BY_ANALYST)],
        relationship_policy=_PIN)

    assert ("WellMess", "uses", "Phishing") not in _pins(bundle)
    assert [r["relationship_type"] for r in _refused(ledger, "policy_pin")] == ["uses"]


def test_an_undirected_verb_is_refused_both_ways_by_a_pinned_rule():
    """Rejecting "Phishing related-to WellMess" rules out the pinned
    "WellMess related-to Phishing", as it does for graph completion."""
    rule = "malware related-to attack-pattern"
    policy = {"version": 1, "global": "enforce",
              "rules": [{"src": "malware", "verb": "related-to", "tgt": "attack-pattern",
                         "mode": "pin", "enabled": True}]}
    shipped, _ = _build(_pinned(), relationship_policy=policy)
    assert ("WellMess", "related-to", "Phishing") in _edges(shipped, x_policy_rule=rule)

    bundle, ledger = _build(
        _pinned(), [RefusedRelationship("Phishing", "related-to", "WellMess", REJECTED_BY_ANALYST)],
        relationship_policy=policy)

    assert ("WellMess", "related-to", "Phishing") not in _edges(bundle, x_policy_rule=rule)
    by_id = {o.id: o for o in bundle.objects}
    assert [(by_id[r["source_ref"]].name, by_id[r["target_ref"]].name)
            for r in _refused(ledger, "policy_pin")] == [("WellMess", "Phishing")]


# ── IoC associations (indicator indicates malware) ───────────────────────────

_IP, _OTHER_IP = "185.220.101.5", "185.220.101.6"
_IOC = f"Malicious IoC: {_IP}"


def _iocs(*links, relationships=()) -> LLMEnrichmentResult:
    """The LLM's JSON links each (IoC, malware) pair; no review row says so."""
    return LLMEnrichmentResult(
        malware_families=["ZetaLoader", "WellMess"],
        ioc_associations=[IoCAssociation(ioc_value=ioc, malware_name=m) for ioc, m in links],
        relationships=list(relationships))


_IPS = [RawEntity(value=_IP, entity_type=EntityType.IPV4),
        RawEntity(value=_OTHER_IP, entity_type=EntityType.IPV4)]


def test_an_ioc_association_builds_its_edge_when_nothing_is_refused():
    bundle, ledger = _build(_iocs((_IP, "ZetaLoader"), (_IP, "WellMess")), entities=_IPS)
    assert {(_IOC, "indicates", "ZetaLoader"), (_IOC, "indicates", "WellMess"),
            (_IOC, "based-on", _IP)} <= _edges(bundle)
    assert "refused" not in ledger


@pytest.mark.parametrize("builds_the_indicator", [True, False], ids=["first_link", "second_link"])
def test_a_rejected_row_is_not_rebuilt_by_an_ioc_association(builds_the_indicator):
    """A rejected "185.220.101.5 indicates ZetaLoader" lands on the IP's
    Indicator (ADR-0041), the edge the association builds: whether that link
    builds the Indicator or finds it built by the IP's other link."""
    links = [(_IP, "ZetaLoader"), (_IP, "WellMess")]
    llm = _iocs(*(links if builds_the_indicator else links[::-1]))
    bundle, ledger = _build(
        llm, [RefusedRelationship(_IP, "indicates", "ZetaLoader", REJECTED_BY_ANALYST)], _IPS)

    edges = _edges(bundle)
    assert (_IOC, "indicates", "ZetaLoader") not in edges
    # The analyst refused the link, not the IoC: its Indicator stays, with
    # its other link and what it is based on.
    assert {(_IOC, "indicates", "WellMess"), (_IOC, "based-on", _IP)} <= edges
    by_id = {o.id: o for o in bundle.objects}
    [refused] = ledger["refused"]
    assert (by_id[refused["source_ref"]].name, refused["relationship_type"],
            by_id[refused["target_ref"]].name) == (_IOC, "indicates", "ZetaLoader")
    assert (refused["origin"], refused["reason"], refused["ioc_value"], refused["malware_name"]) == (
        "ioc_association", REJECTED_BY_ANALYST, _IP, "ZetaLoader")


@pytest.mark.parametrize("builds_the_indicator", [True, False], ids=["first_link", "second_link"])
def test_a_held_row_is_not_built_by_an_ioc_association_while_it_waits(builds_the_indicator):
    links = [(_IP, "ZetaLoader"), (_IP, "WellMess")]
    bundle, ledger = _build(
        _iocs(*(links if builds_the_indicator else links[::-1])),
        [RefusedRelationship(_IP, "Indicates", "zetaloader", HELD_FOR_REVIEW)], _IPS)

    edges = _edges(bundle)
    assert (_IOC, "indicates", "ZetaLoader") not in edges
    assert {(_IOC, "indicates", "WellMess"), (_IOC, "based-on", _IP)} <= edges
    assert [(r["reason"], r["malware_name"]) for r in _refused(ledger, "ioc_association")] == [
        (HELD_FOR_REVIEW, "ZetaLoader")]


def test_a_refused_row_holds_back_only_the_ioc_it_names():
    """Two IPs linked to ZetaLoader, one row refused: the other IP's
    Indicator still indicates ZetaLoader."""
    bundle, ledger = _build(
        _iocs((_IP, "ZetaLoader"), (_OTHER_IP, "ZetaLoader")),
        [RefusedRelationship(_OTHER_IP, "indicates", "ZetaLoader", REJECTED_BY_ANALYST)], _IPS)

    edges = _edges(bundle)
    assert (_IOC, "indicates", "ZetaLoader") in edges
    assert (f"Malicious IoC: {_OTHER_IP}", "indicates", "ZetaLoader") not in edges
    assert [r["ioc_value"] for r in _refused(ledger, "ioc_association")] == [_OTHER_IP]


def test_a_row_that_ships_the_same_triple_keeps_the_association_edge():
    shipping = RelationshipExtracted(source_value=_IP, relationship_type="indicates",
                                     target_value="ZetaLoader", confidence=0.9)
    bundle, ledger = _build(
        _iocs((_IP, "ZetaLoader"), relationships=[shipping]),
        [RefusedRelationship(_IP, "indicates", "ZetaLoader", REJECTED_BY_ANALYST)], _IPS)

    assert (_IOC, "indicates", "ZetaLoader") in _edges(bundle)
    assert "refused" not in ledger


def test_an_ioc_association_refuses_the_verb_the_policy_gives_the_pair():
    """A pinned `indicator related-to malware` rewrites the refused row, once
    routed through the Indicator, and the association's edge alike."""
    policy = {"version": 1, "global": "enforce",
              "rules": [{"src": "indicator", "verb": "related-to", "tgt": "malware",
                         "mode": "pin", "enabled": True}]}
    bundle, ledger = _build(
        _iocs((_IP, "ZetaLoader"), (_IP, "WellMess")),
        [RefusedRelationship(_IP, "indicates", "ZetaLoader", REJECTED_BY_ANALYST)], _IPS,
        relationship_policy=policy)

    assert not {e for e in _edges(bundle) if e[0] == _IOC and e[2] == "ZetaLoader"}
    assert (_IOC, "related-to", "WellMess") in _edges(bundle)
    assert [r["relationship_type"] for r in _refused(ledger, "ioc_association")] == ["related-to"]


def test_an_ioc_association_refuses_an_undirected_verb_the_other_way_round():
    """Under a pinned `indicator related-to malware`, a rejected "ZetaLoader
    related-to 185.220.101.5" (routed: ZetaLoader related-to the Indicator)
    rules out the association's "Indicator related-to ZetaLoader"."""
    policy = {"version": 1, "global": "enforce",
              "rules": [{"src": "indicator", "verb": "related-to", "tgt": "malware",
                         "mode": "pin", "enabled": True}]}
    links = [(_IP, "ZetaLoader"), (_IP, "WellMess")]
    shipped, _ = _build(_iocs(*links), entities=_IPS, relationship_policy=policy)
    assert (_IOC, "related-to", "ZetaLoader") in _edges(shipped)

    bundle, ledger = _build(
        _iocs(*links), [RefusedRelationship("ZetaLoader", "related-to", _IP, REJECTED_BY_ANALYST)],
        _IPS, relationship_policy=policy)

    assert (_IOC, "related-to", "ZetaLoader") not in _edges(bundle)
    assert (_IOC, "related-to", "WellMess") in _edges(bundle)
    by_id = {o.id: o for o in bundle.objects}
    assert [(by_id[r["source_ref"]].name, by_id[r["target_ref"]].name)
            for r in _refused(ledger, "ioc_association")] == [(_IOC, "ZetaLoader")]
