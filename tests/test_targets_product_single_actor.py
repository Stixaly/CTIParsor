"""The actor × targeted country / sector product is built only when the report
names one threat actor, counted after Stage 4b has merged the aliases: with
several, the lists do not say which actor targets what, and the ledger lists
each pair as "ambiguous_actor".  A `targets` row the report states ships
whatever the number of actors."""
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import AMBIGUOUS_ACTOR
from pipeline.stage4b_graph_completion import REJECTED_BY_ANALYST, RefusedRelationship
from tests.test_stage4_refusals import _build, _edges, _refused


def _llm(actors, relationships=()) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(threat_actors=actors, targeted_countries=["France", "Germany"],
                               targeted_sectors=["Government"], relationships=list(relationships))


def _targets_edges(bundle) -> set[tuple[str, str, str]]:
    return {e for e in _edges(bundle) if e[1] == "targets"}


def _actor_count(bundle) -> int:
    return len([o for o in bundle.objects if o.get("type") == "threat-actor"])


def test_two_actors_build_no_product_and_the_ledger_lists_every_pair():
    bundle, ledger = _build(_llm(["APT29", "APT28"]))

    assert _targets_edges(bundle) == set()
    names = {o.get("name") for o in bundle.objects}
    assert {"APT29", "APT28", "France", "Germany", "Government"} <= names
    refused = _refused(ledger, "targeted_location")
    assert len(refused) == 6
    assert {r["reason"] for r in refused} == {AMBIGUOUS_ACTOR}
    assert {(r["actor"], r["target"]) for r in refused} == {
        (a, t) for a in ("APT29", "APT28") for t in ("France", "Germany", "Government")}
    by_id = {o.id: o for o in bundle.objects}
    assert all(by_id[r["source_ref"]].type == "threat-actor" and r["relationship_type"] == "targets"
               for r in refused)


def test_two_names_for_one_actor_object_still_build_the_product():
    """"Cozy Bear" is the name of the APT29 object (as in the apt_report scenario)."""
    bundle, ledger = _build(_llm(["APT29", "Cozy Bear"]))

    assert {("APT29", "targets", "France"), ("APT29", "targets", "Germany"),
            ("APT29", "targets", "Government")} <= _targets_edges(bundle)
    assert "refused" not in ledger


_ALIAS = {"version": 1, "global": "enforce", "rules": [], "completion": {"alias": True}}


def _spellings() -> LLMEnrichmentResult:
    return LLMEnrichmentResult(threat_actors=["Frost Spider", "FrostSpider"],
                               targeted_sectors=["Finance"])


def test_two_spellings_that_stage_4b_merges_build_the_product_once():
    bundle, ledger = _build(_spellings(), relationship_policy=_ALIAS)

    assert _actor_count(bundle) == 1
    [sro] = [o for o in bundle.objects if o.get("type") == "relationship"
             and o.relationship_type == "targets"]
    assert ledger["objects"][sro.id]["origin"] == "targeted_location"
    assert "refused" not in ledger
    assert sro.id in next(o for o in bundle.objects if o.get("type") == "report").object_refs
    assert "**Why:**" in sro.description


def test_two_spellings_stay_ambiguous_when_graph_completion_is_off():
    bundle, ledger = _build(_spellings(), relationship_policy=_ALIAS, graph_completion=False)

    assert _actor_count(bundle) == 2
    assert _targets_edges(bundle) == set()
    assert {(r["actor"], r["reason"]) for r in _refused(ledger, "targeted_location")} == {
        ("Frost Spider", AMBIGUOUS_ACTOR), ("FrostSpider", AMBIGUOUS_ACTOR)}


def test_a_refused_row_still_holds_back_the_merged_product():
    """The rejected row names one spelling; once the spellings are one actor
    the pair is the same triple."""
    bundle, ledger = _build(
        _spellings(), [RefusedRelationship("Frost Spider", "targets", "Finance", REJECTED_BY_ANALYST)],
        relationship_policy=_ALIAS)

    assert _targets_edges(bundle) == set()
    assert {r["reason"] for r in _refused(ledger, "targeted_location")} == {REJECTED_BY_ANALYST}


def test_a_pinned_edge_is_not_listed_as_ambiguous():
    policy = {"version": 1, "global": "enforce",
              "rules": [{"src": "threat-actor", "verb": "targets", "tgt": "identity",
                         "mode": "pin", "enabled": True}]}
    bundle, ledger = _build(_llm(["APT29", "APT28"]), relationship_policy=policy)

    assert _edges(bundle, x_policy_rule="threat-actor targets identity")
    by_id = {o.id: o for o in bundle.objects}
    listed = {(by_id[r["source_ref"]].name, r["relationship_type"], by_id[r["target_ref"]].name)
              for r in _refused(ledger, "targeted_location")}
    assert listed and not listed & _edges(bundle)


def test_an_explicit_row_ships_with_two_actors_and_is_not_listed_as_refused():
    row = RelationshipExtracted(source_value="APT29", relationship_type="targets",
                                target_value="France", confidence=0.9,
                                evidence_text="APT29 targeted France.")
    bundle, ledger = _build(_llm(["APT29", "APT28"], [row]))

    assert _targets_edges(bundle) == {("APT29", "targets", "France")}
    [sro] = [o for o in bundle.objects if o.get("type") == "relationship"
             and o.relationship_type == "targets"]
    assert sro.get("x_evidence_text") == "APT29 targeted France."
    assert ledger["objects"][sro.id]["origin"] == "extracted"
    refused = _refused(ledger, "targeted_location")
    assert len(refused) == 5
    assert ("APT29", "France") not in {(r["actor"], r["target"]) for r in refused}


def test_a_rejected_row_keeps_its_own_reason_with_two_actors():
    bundle, ledger = _build(_llm(["APT29", "APT28"]),
                            [RefusedRelationship("APT29", "targets", "France", REJECTED_BY_ANALYST)])

    assert _targets_edges(bundle) == set()
    pair = [r for r in _refused(ledger, "targeted_location")
            if (r["actor"], r["target"]) == ("APT29", "France")]
    assert [r["reason"] for r in pair] == [REJECTED_BY_ANALYST]
    assert len(_refused(ledger, "targeted_location")) == 6
