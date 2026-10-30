# tests/test_object_mentions.py
import pytest

from pipeline.object_mentions import find_mentions, mention_description


def test_name_matches_regardless_of_case():
    text = "EMOTET was used. emotet came back."
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["EMOTET was used.", "emotet came back."]}

def test_name_must_be_a_whole_word():
    text = "Emotets grew. xEmotet ran. Emotet, the loader, ran. The (Emotet) family."
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["Emotet, the loader, ran.", "The (Emotet) family."]}

def test_alias_is_a_name_too():
    text = "Geodo spreads banking trojans."
    assert find_mentions(text, {"m1": ["Emotet", "Geodo"]}) == {"m1": ["Geodo spreads banking trojans."]}

def test_limit_keeps_the_first_sentences_in_document_order():
    text = "Emotet one. Emotet two. Emotet three. Emotet four."
    assert find_mentions(text, {"m1": ["Emotet"]}, limit=2) == {"m1": ["Emotet one.", "Emotet two."]}
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["Emotet one.", "Emotet two.", "Emotet three."]}

def test_repeated_sentence_is_shown_once():
    text = "Emotet spreads\nfast. Emotet spreads fast. Emotet drops files."
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["Emotet spreads fast.", "Emotet drops files."]}

def test_name_shorter_than_three_characters_is_ignored():
    text = "The US and C2 servers were tracked."
    assert find_mentions(text, {"m1": ["US", " C2 "]}) == {}

def test_name_is_stripped_before_matching():
    assert find_mentions("Emotet ran.", {"m1": [" Emotet "]}) == {"m1": ["Emotet ran."]}

def test_long_sentence_is_cut_with_an_ellipsis():
    text = "Emotet " + "a" * 500 + "."
    assert find_mentions(text, {"m1": ["Emotet"]}, max_chars=20) == {"m1": ["Emotet " + "a" * 13 + "…"]}

def test_cut_leaves_no_space_before_the_ellipsis():
    assert find_mentions("Emotet spreads fast.", {"m1": ["Emotet"]}, max_chars=7) == {"m1": ["Emotet…"]}

def test_sentence_within_max_chars_is_unchanged():
    assert find_mentions("Emotet ran.", {"m1": ["Emotet"]}, max_chars=11) == {"m1": ["Emotet ran."]}

def test_pdf_line_breaks_are_merged():
    text = "The Emotet\nloader is\nspread by mail. Other text."
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["The Emotet loader is spread by mail."]}

def test_name_broken_across_lines_still_matches():
    text = "The Lazarus\nGroup ran it. Lazarus   Group again."
    expected = {"a1": ["The Lazarus Group ran it.", "Lazarus Group again."]}
    assert find_mentions(text, {"a1": ["Lazarus Group"]}) == expected

def test_object_without_a_mention_is_absent():
    assert find_mentions("Emotet ran.", {"m1": ["Emotet"], "m2": ["Trickbot"]}) == {"m1": ["Emotet ran."]}

def test_two_objects_can_share_a_sentence():
    text = "Emotet was delivered by TA542."
    assert find_mentions(text, {"m1": ["Emotet"], "m2": ["TA542"]}) == {"m1": [text], "m2": [text]}

def test_boundary_holds_when_lowercasing_changes_the_length():
    # "İ" lower-cases to two characters: the boundary is read from the same copy the search ran on.
    text = "İ Emotets grew. İ Emotet, ok."
    assert find_mentions(text, {"m1": ["Emotet"]}) == {"m1": ["İ Emotet, ok."]}


def test_a_cased_name_counts_only_with_an_initial_capital():
    # "silence" is an ordinary word: only the capitalised uses name the actor
    text = "The group went into silence. Silence used a loader. SILENCE struck again. silence fell."
    assert find_mentions(text, {"m1": ["Silence"]}, cased={"silence"}) == {
        "m1": ["Silence used a loader.", "SILENCE struck again."]}


@pytest.mark.parametrize("cased", [{"silence"}, {"Silence"}])
def test_cased_names_are_compared_lower_cased(cased):
    text = "The group went into silence. Silence used a loader."
    assert find_mentions(text, {"m1": ["Silence"]}, cased=cased) == {"m1": ["Silence used a loader."]}


def test_a_name_outside_cased_matches_whatever_its_case():
    text = "The group went into silence. emotet ran. EMOTET again."
    assert find_mentions(text, {"m1": ["Silence", "Emotet"]}, cased={"silence"}) == {
        "m1": ["emotet ran.", "EMOTET again."]}


def test_the_capital_check_reads_past_a_character_whose_lower_case_is_longer():
    # "İ" lower-cases to two characters: the capital of "Silence" is read at its own offset.
    text = "İ went into silence. İ Silence used a loader."
    assert find_mentions(text, {"m1": ["Silence"]}, cased={"silence"}) == {"m1": ["İ Silence used a loader."]}


def test_description_names_the_report_and_quotes_each_sentence():
    assert mention_description("APT report", ["Emotet ran.", "It drops files."]) == (
        "Mentioned in *APT report*:\n\n> Emotet ran.\n\n> It drops files."
    )

def test_description_without_a_report_name():
    assert mention_description("  ", ["Emotet ran."]) == "Mentioned in the report:\n\n> Emotet ran."

def test_report_name_is_escaped():
    assert mention_description("APT*report", ["Emotet ran."]) == "Mentioned in *APT\\*report*:\n\n> Emotet ran."

def test_sentence_starting_with_a_hash_is_not_a_heading():
    assert mention_description("APT report", ["# Emotet ran."]) == "Mentioned in *APT report*:\n\n> \\# Emotet ran."

def test_no_sentence_gives_no_description():
    assert mention_description("APT report", []) is None
