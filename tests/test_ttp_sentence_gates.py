"""
Sentence-gate and instrumentation tests — ADR-0023 Phase 2.

Stage 2c discards sentences at two points before any embedding is computed,
and on PDF-extracted text its splitter used to emit line-wrap fragments
instead of sentences.  These tests lock the unwrapping rule, the two
measurement escape hatches, and the counter contract.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.stage2c_ttp_semantic import (
    _MAX_CANDIDATES,
    _has_ttp_keyword,
    _select_candidates,
    _split_candidate_sentences,
    _unwrap_hard_linebreaks,
    sentence_gate_stats,
)


def test_unwrap_joins_hard_wrapped_lines():
    """Single newline hard wrap should be joined into one line."""
    text = (
        "At the time of writing, WithSecure has not identified definitive links\n"
        "between GREYVIBE and any previously tracked threat group."
    )
    result = _unwrap_hard_linebreaks(text)
    assert "definitive links between GREYVIBE" in result, (
        "Hard-wrapped lines must be joined into a continuous phrase"
    )
    assert "\n" not in result, (
        "A single newline inside a paragraph is a hard wrap, not a boundary"
    )


def test_unwrap_joins_doubled_hard_wraps():
    """Doubled newlines from PDF extraction must also be joined."""
    text = (
        "Based on significant overlaps observed across both development and "
        "operational phases\n\n"
        "of the associated campaigns, WithSecure associates the activities "
        "with a threat group\n\n"
        "tracked as GREYVIBE."
    )
    result = _unwrap_hard_linebreaks(text)
    assert "operational phases of the associated campaigns" in result, (
        "Doubled newline is a hard wrap in PDF-extracted text, not a "
        "paragraph break"
    )
    assert "threat group tracked as GREYVIBE." in result, (
        "Doubled newline is a hard wrap in PDF-extracted text, not a "
        "paragraph break"
    )
    assert "\n" not in result, (
        "Doubled newline is a hard wrap in PDF-extracted text, not a "
        "paragraph break"
    )


def test_unwrap_keeps_sentence_boundary():
    """A newline after sentence-ending punctuation must be preserved."""
    text = (
        "Ukraine-related entities since at least August 2025.\n\n"
        "The next sentence starts here."
    )
    result = _unwrap_hard_linebreaks(text)
    assert result.count("\n") == 1, (
        "A newline after a period is a true sentence boundary and must "
        "remain, regardless of run length"
    )


def test_unwrap_keeps_list_items_separate():
    """List items (bullet or numbered) must not be joined to the previous line."""
    bullet_text = (
        "The actor used the following tools\n\n"
        "- Cobalt Strike\n\n"
        "- Mimikatz"
    )
    bullet_result = _unwrap_hard_linebreaks(bullet_text)
    assert bullet_result.count("\n") == 2, (
        "Bullet list items must remain on separate lines"
    )

    numbered_text = (
        "steps taken\n\n"
        "1. First step\n\n"
        "2. Second step"
    )
    numbered_result = _unwrap_hard_linebreaks(numbered_text)
    assert numbered_result.count("\n") == 2, (
        "Numbered list items must remain on separate lines"
    )


def test_unwrap_handles_trailing_hyphen():
    """A line ending with a hyphen should still be joined if not a sentence end."""
    text = (
        "GREYVIBE_ A Russia-nexus group leveraging\n\n"
        "AI across state-aligned operations -\n\n"
        "WithSecure"
    )
    result = _unwrap_hard_linebreaks(text)
    assert (
        "leveraging AI across state-aligned operations - WithSecure" in result
    ), (
        "Trailing hyphen is not a sentence terminator; lines must be joined"
    )
    assert "\n" not in result, (
        "All hard wraps in this paragraph must be resolved to a single line"
    )


def test_unwrap_guards_non_string():
    """Non-string inputs must return an empty string."""
    assert _unwrap_hard_linebreaks(None) == "", (
        "None input must be handled gracefully and return empty string"
    )
    assert _unwrap_hard_linebreaks(42) == "", (
        "Non-string input must be handled gracefully and return empty string"
    )

def test_split_candidate_sentences_no_longer_fragments_wrapped_text(monkeypatch):
    # Construct a paragraph of 4 lines forming ONE sentence ending with a period
    wrapped_text = (
        "This is a very long sentence that is split across multiple lines \n"
        "for testing purposes and it continues here with more text \n"
        "and even more text to ensure it is long enough \n"
        "to pass the length filter."
    )

    # Default: unwrap enabled
    segments = _split_candidate_sentences(wrapped_text)
    assert len(segments) == 1

    # Disable unwrap
    monkeypatch.setenv("TTP_UNWRAP_LINES", "0")
    segments_disabled = _split_candidate_sentences(wrapped_text)
    assert len(segments_disabled) == 4


def test_split_candidate_sentences_guards_non_string():
    assert _split_candidate_sentences(None) == []
    assert _split_candidate_sentences(42) == []


def test_keyword_gate_off_keeps_everything(monkeypatch):
    sentence = "The weather in Paris was pleasant throughout the quarter."

    # Default: gate on, no TTP keywords
    assert _has_ttp_keyword(sentence) is False

    # Gate off
    monkeypatch.setenv("TTP_KEYWORD_GATE", "off")
    assert _has_ttp_keyword(sentence) is True

    # Test other off values
    monkeypatch.setenv("TTP_KEYWORD_GATE", "0")
    assert _has_ttp_keyword(sentence) is True

    monkeypatch.setenv("TTP_KEYWORD_GATE", "false")
    assert _has_ttp_keyword(sentence) is True

    monkeypatch.setenv("TTP_KEYWORD_GATE", "no")
    assert _has_ttp_keyword(sentence) is True

    # Test on values
    monkeypatch.setenv("TTP_KEYWORD_GATE", "on")
    assert _has_ttp_keyword(sentence) is False

    # Test absent value (default on)
    monkeypatch.delenv("TTP_KEYWORD_GATE", raising=False)
    assert _has_ttp_keyword(sentence) is False


def test_keyword_gate_guards_non_string():
    assert _has_ttp_keyword(None) is False
    assert _has_ttp_keyword(42) is False


def test_sentence_gate_stats_accounting_is_closed():
    # Create a text with some TTP keywords and some without
    # Assuming _TTP_KEYWORDS contains common terms like "exploited", "malware"
    text = (
        "The actor exploited a vulnerability in the system. "
        "The weather was nice. "
        "They deployed malware to the target. "
        "The meeting was scheduled for Monday. "
        "The exploit was successful."
    )

    stats = sentence_gate_stats(text)

    assert stats["dropped_by_keyword"] == stats["sentences_total"] - stats["kept_by_keyword"]
    assert stats["dropped_by_cap"] == stats["kept_by_keyword"] - stats["scored"]
    assert stats["scored"] <= stats["kept_by_keyword"] <= stats["sentences_total"]

    # Check all keys present
    expected_keys = {
        "sentences_total",
        "kept_by_keyword",
        "scored",
        "dropped_by_keyword",
        "dropped_by_cap",
    }
    assert set(stats.keys()) == expected_keys


def test_sentence_gate_stats_reflects_gate_toggle(monkeypatch):
    text = (
        "The actor exploited a vulnerability in the system. "
        "The weather was nice. "
        "They deployed malware to the target. "
        "The meeting was scheduled for Monday. "
        "The exploit was successful."
    )

    # Default: gate on
    stats_on = sentence_gate_stats(text)

    # Gate off
    monkeypatch.setenv("TTP_KEYWORD_GATE", "off")
    stats_off = sentence_gate_stats(text)

    assert stats_off["kept_by_keyword"] > stats_on["kept_by_keyword"]
    assert stats_off["kept_by_keyword"] == stats_off["sentences_total"]


def test_candidate_cap_binds_only_above_the_cap():
    # Create 250 sentences with "exploited"
    sentences = [f"The actor exploited vulnerability number {i} in the system." for i in range(250)]
    text = " ".join(sentences)

    stats = sentence_gate_stats(text)

    assert stats["scored"] <= _MAX_CANDIDATES
    if stats["kept_by_keyword"] > _MAX_CANDIDATES:
        assert stats["dropped_by_cap"] > 0


def test_select_candidates_matches_stats():
    text1 = (
        "The actor exploited a vulnerability in the system. "
        "The weather was nice. "
        "They deployed malware to the target."
    )

    text2 = (
        "The actor exploited a vulnerability in the system. "
        "The weather was nice. "
        "They deployed malware to the target. "
        "The meeting was scheduled for Monday."
    )

    for text in [text1, text2]:
        candidates = _select_candidates(text)
        stats = sentence_gate_stats(text)
        assert len(candidates) == stats["scored"]
