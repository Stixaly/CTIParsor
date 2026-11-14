"""Stage 2g — three regressions from the bug triage (issues #766, #769 and #770).

#766: an Oxford comma before "and"/"or" in an inline alias list ("Ghost Blizzard,
and Sandworm") cut the last alias: the comma was taken as the separator and the
next anchor had to start with a capital.

#769: _masked() turned every non-ASCII letter into a lowercase "z", so an
accented capital ("Élite", "Özdemir", "Ångström") could never start a name.
Capitals are now masked as "Z" and the other letters as "z", one character each.

#770: the parenthetical pattern stopped at the first ")", so a nested
parenthesis ("Cozy Bear (NOBELIUM)") ended the alias list early and lost the
aliases after it.  Choice: one level of nesting is read inside the list, and
_clean_alias cuts a name at its first "(" -- the annotation is not part of the
name, and no emitted value keeps an unclosed "(".  The name before the
annotation ("Cozy Bear") is kept; the annotation itself ("NOBELIUM") is not
emitted as a separate alias.
"""
from __future__ import annotations

from pipeline import stage2g_alias_list as sut


def _values(text: str) -> set[str]:
    return {r.value for r in sut.extract_alias_list_entities(text)}


# ── #766: Oxford comma before "and" / "or" ──────────────────────────────────

def test_766_oxford_comma_before_and_keeps_the_last_alias():
    values = _values("Static Tundra, aka Berserk Bear, Ghost Blizzard, and Sandworm.")
    assert values == {"Static Tundra", "Berserk Bear", "Ghost Blizzard", "Sandworm"}


def test_766_oxford_comma_before_or_keeps_the_last_alias():
    values = _values("Static Tundra, aka Berserk Bear, Ghost Blizzard, or Sandworm.")
    assert {"Ghost Blizzard", "Sandworm"} <= values


def test_766_control_without_the_comma_is_unchanged():
    values = _values("Static Tundra, aka Berserk Bear, Ghost Blizzard and Sandworm.")
    assert values == {"Static Tundra", "Berserk Bear", "Ghost Blizzard", "Sandworm"}


# ── #769: accented capitals start a name ───────────────────────────────────

def test_769_accented_capital_anchor_keeps_its_letters():
    values = _values("Élite Bear (aka Sandworm)")
    assert values == {"Élite Bear", "Sandworm"}


def test_769_accented_capitals_in_an_alias_list_are_kept():
    values = _values("Élite Bear (aka Özdemir Group, Sandworm)")
    assert values == {"Élite Bear", "Özdemir Group", "Sandworm"}


def test_769_accented_capital_as_the_first_letter_of_an_anchor():
    assert _values("Ångström (aka Sandworm)") == {"Ångström", "Sandworm"}


def test_769_mask_keeps_one_character_per_character():
    """Offsets stay exact: each capital becomes "Z", each other letter "z"."""
    assert sut._masked("Élite") == "Zlite"
    assert sut._masked("Ångström") == "Zngstrzm"
    text = "Élite Bear (aka Özdemir Group, Sandworm)"
    assert len(sut._masked(text)) == len(text)


def test_769_ascii_marker_and_separator_are_not_masked_away():
    """Control: the words the comment of the module names still read as before."""
    assert _values("Static Tundra (áka Berserk Bear) was seen.") == set()
    assert _values("Static Tundra (aka Berserk Bear, Ánd Ghost Blizzard)") == {
        "Static Tundra", "Berserk Bear", "Ánd Ghost Blizzard",
    }
    assert sut._masked("áka Ánd") == "zka Znd"


# ── #770: nested parentheses ────────────────────────────────────────────────

def test_770_nested_parenthesis_keeps_the_aliases_after_it():
    values = _values("APT29 (aka Cozy Bear (NOBELIUM), Midnight Blizzard)")
    assert {"APT29", "Cozy Bear", "Midnight Blizzard"} <= values


def test_770_no_emitted_name_has_an_unclosed_parenthesis():
    for text in (
        "APT29 (aka Cozy Bear (NOBELIUM), Midnight Blizzard)",
        "APT29 (aka Cozy Bear (NOBELIUM, Midnight Blizzard)",
        "APT29 (aka Cozy Bear (NOBELIUM)) struck first.",
    ):
        assert all(v.count("(") == v.count(")") for v in _values(text)), text


def test_770_control_a_plain_parenthesis_is_unchanged():
    assert _values("APT29 (aka Cozy Bear, Midnight Blizzard) struck first.") == {
        "APT29", "Cozy Bear", "Midnight Blizzard",
    }
