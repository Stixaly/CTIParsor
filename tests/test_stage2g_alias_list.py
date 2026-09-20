"""Stage 2g — alias-list extraction tests.

Built from a real production gap (2026-09-20): none of the dictionary/model
stages (gazetteer, CyNER, GLiNER) split an explicit "X (aka Y, Z, W)" /
"X, also known as Y and Z" construct into its individual named aliases —
only Stage 3's LLM was recovering them, and only on chunks it processed
thoroughly. This is the regression test for the fix.
"""
from __future__ import annotations

from models.schemas import EntityType
from pipeline import stage2g_alias_list as sut


def test_real_world_five_way_alias_list_is_fully_split():
    """The exact construct that motivated this stage."""
    text = (
        "Static Tundra (aka Berserk Bear, Ghost Blizzard, Sandworm Team, "
        "Seashell Blizzard) is a Russian state-sponsored group."
    )
    results = sut.extract_alias_list_entities(text)
    values = {r.value for r in results}
    assert values == {
        "Static Tundra", "Berserk Bear", "Ghost Blizzard",
        "Sandworm Team", "Seashell Blizzard",
    }
    assert all(r.entity_type == EntityType.THREAT_ACTOR for r in results)
    assert all(r.source == "alias_list" for r in results)


def test_two_way_parenthetical_alias():
    [a, b] = sut.extract_alias_list_entities("OilRig (aka APT34) has been active since 2014.")
    assert {a.value, b.value} == {"OilRig", "APT34"}


def test_formerly_known_as_variant():
    results = sut.extract_alias_list_entities(
        "Static Tundra (formerly known as Berserk Bear) has rebranded."
    )
    assert {r.value for r in results} == {"Static Tundra", "Berserk Bear"}


def test_inline_also_known_as_without_parentheses():
    results = sut.extract_alias_list_entities(
        "Fighting Ursa, also known as APT28 and Fancy Bear, targeted the ministry."
    )
    values = {r.value for r in results}
    assert {"Fighting Ursa", "APT28", "Fancy Bear"} <= values


def test_no_false_positive_on_unrelated_parenthetical():
    """A parenthetical that isn't an alias marker must not match."""
    assert sut.extract_alias_list_entities(
        "This report references prior findings (see Figure 3) for context."
    ) == []
    assert sut.extract_alias_list_entities(
        "Sandworm (a Russian military unit) has been linked to multiple incidents."
    ) == []


def test_no_construct_at_all_returns_empty():
    assert sut.extract_alias_list_entities("This sentence has no alias construct.") == []


def test_deduplicates_repeated_mentions():
    text = (
        "Static Tundra (aka Berserk Bear) struck first. "
        "Later, Static Tundra (aka Berserk Bear) struck again."
    )
    results = sut.extract_alias_list_entities(text)
    assert len(results) == 2  # not 4 — same two names, deduped by value


def test_confidence_is_below_auto_accept_range():
    """A heuristic regex source should land in review, not auto-promote."""
    [r] = [e for e in sut.extract_alias_list_entities("OilRig (aka APT34) is active.")
           if e.value == "OilRig"]
    assert r.confidence < 0.70


def test_stage_wrapper_is_always_available():
    stage = sut.AliasListStage()
    assert stage.available() is True
    assert stage.name == "alias_list"
