"""Stage 3b refuses the neighbouring identifier (audit B 8.1.4).

The fuzzy window used to accept UNC4763 and UNC4737 for UNC4736, BlackBasta
for BlackCat and APT2 for APT28: a hallucination one character away from a
real name passed as that name.  Names with a digit, names under 8 characters
and single-token names are now matched exactly on word boundaries; fuzzy
matching stays for multi-word names OCR split or hyphenated.
"""
from __future__ import annotations

import pytest

from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage3b_validate import _name_in_text, validate_llm_result

TEXT = ("The operators relied on Cobalt Strike beacons and Mimikatz. We track this "
        "cluster as UNC4736. The BlackCat affiliate also used AnyDesk. APT28 was not "
        "involved; Storm-0558 and TA505 were. LummaC2 logs were sold.")


@pytest.mark.parametrize("name", [
    "UNC4736", "BlackCat", "AnyDesk", "APT28", "Storm-0558", "TA505", "LummaC2",
    "Cobalt Strike", "Mimikatz",
])
def test_names_in_the_text_are_kept(name):
    assert _name_in_text(name, TEXT)


@pytest.mark.parametrize("name", [
    "UNC4763", "UNC4737", "UNC473",          # neighbouring cluster numbers
    "BlackBasta",                            # another ransomware, ratio 80 against BlackCat
    "APT2", "APT29", "APT280",               # a prefix, a sibling, an extension
    "Storm-0559", "TA506", "LummaC",
    "FIN7", "FIN6",                          # absent, and never fuzzy
    "AnyConnect", "Cobalt Group", "Lazarus",
])
def test_neighbouring_identifiers_are_refused(name):
    assert not _name_in_text(name, TEXT)


@pytest.mark.parametrize("text", [
    "The loader dropped Cobalt- Strike on the host.",     # hyphenated at a line break
    "The loader dropped CobaltStrike on the host.",       # joined
    "The loader dropped Cobalt  Strike on the host.",     # double space
])
def test_a_multi_word_name_split_by_ocr_is_still_found(text):
    assert _name_in_text("Cobalt Strike", text)


def test_a_fuzzy_window_with_digits_is_not_a_match():
    """`Mustang Panda` must not be read into `Mustang Pand4` — digits must agree."""
    assert not _name_in_text("Mustang Panda", "Related to Mustang Pand4 tooling.")


def test_word_boundaries_apply_to_long_names_too():
    assert not _name_in_text("WellMess", "WellMessenger is a chat app.")
    assert _name_in_text("WellMess", "APT29's WellMess implant.")


def test_the_filter_drops_the_neighbour_and_its_relationships():
    from pipeline.stage3_llm import RelationshipExtracted
    r = LLMEnrichmentResult(
        threat_actors=["UNC4736", "UNC4763"],
        malware_families=["BlackBasta"],
        tools=["Cobalt Strike", "AnyDesk"],
        relationships=[
            RelationshipExtracted(source_value="UNC4763", relationship_type="uses",
                                  target_value="Cobalt Strike", confidence=0.9),
            RelationshipExtracted(source_value="UNC4736", relationship_type="uses",
                                  target_value="AnyDesk", confidence=0.9),
        ],
    )
    out = validate_llm_result(r, TEXT)
    assert out.threat_actors == ["UNC4736"]
    assert out.malware_families == []
    assert out.tools == ["Cobalt Strike", "AnyDesk"]
    assert [(x.source_value, x.target_value) for x in out.relationships] == [("UNC4736", "AnyDesk")]
