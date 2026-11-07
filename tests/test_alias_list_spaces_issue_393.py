"""Blanks inside a name: alias list (Stage 2g) and CyNER collapse (Stage 2d), issue #393.

"Berserk\xa0Bear (aka Dragonfly)" lost "Berserk": the anchor pattern only read
spaces and tabs, so the name came out as "Bear".  A name wrapped across a line
break is one name too, but a blank line still ends it.  The name is emitted
with single spaces whatever the text put between its words.
"""
from __future__ import annotations

from pipeline import stage2d_cyner, stage2g_alias_list


def _values(text: str) -> set[str]:
    return {r.value for r in stage2g_alias_list.extract_alias_list_entities(text)}


def test_a_no_break_space_joins_the_anchor_words():
    values = _values("Berserk\xa0Bear (aka Dragonfly) attacked energy firms.")
    assert values == {"Berserk Bear", "Dragonfly"}


def test_a_line_break_ends_the_anchor_so_two_names_are_not_joined():
    values = _values("Sandworm\nBerserk Bear (aka Dragonfly) attacked energy firms.")
    assert "Sandworm Berserk Bear" not in values
    assert "Berserk Bear" in values


def test_a_blank_line_still_ends_the_anchor():
    """Control: "\\n\\n" is a paragraph break, so "Berserk" is not part of the name."""
    values = _values("Berserk\n\nBear (aka Dragonfly) attacked energy firms.")
    assert "Berserk Bear" not in values
    assert values == {"Bear", "Dragonfly"}


def test_a_no_break_space_inside_an_alias_is_normalised():
    values = _values("Static Tundra (aka Berserk\xa0Bear, Ghost Blizzard) struck first.")
    assert {"Static Tundra", "Berserk Bear", "Ghost Blizzard"} <= values


def test_an_inline_alias_with_a_no_break_space_keeps_both_words():
    values = _values("Berserk\xa0Bear, also known as Dragonfly, attacked energy firms.")
    assert {"Berserk Bear", "Dragonfly"} <= values


def test_every_emitted_name_has_single_spaces_only():
    results = stage2g_alias_list.extract_alias_list_entities(
        "Berserk\xa0Bear\nTeam (aka Dragonfly\xa0Two, Ghost\nBlizzard) struck first."
    )
    assert results
    assert all(r.value == " ".join(r.value.split()) for r in results)


def test_a_plain_parenthetical_is_unchanged():
    """Control: the construct of the existing tests still gives the same names."""
    assert _values("OilRig (aka APT34) has been active since 2014.") == {"OilRig", "APT34"}


def test_cyner_collapse_sees_a_line_break_as_a_word_break():
    assert stage2d_cyner._collapse_repeated_token("COLDWELL\nCOLDWELL Dropper") == "COLDWELL Dropper"


def test_cyner_collapse_sees_a_no_break_space_as_a_word_break():
    assert stage2d_cyner._collapse_repeated_token("COLDWELL\xa0COLDWELL Dropper") == "COLDWELL Dropper"


def test_cyner_collapse_control_leaves_a_clean_name_untouched():
    assert stage2d_cyner._collapse_repeated_token("BLACKENERGY Dropper") == "BLACKENERGY Dropper"
