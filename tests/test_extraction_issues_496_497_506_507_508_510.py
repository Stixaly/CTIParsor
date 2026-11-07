"""Extraction fixes of the 2026-11-07 audit batch (#496, #497, #506, #507, #508, #510).

Each test cites the issue it pins.  They run on the code as it is after the fix;
the failure each one showed before the fix is recorded in the lot report.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.base import resolve_type_conflicts
from pipeline.evidence_span import sentence_bounds
from pipeline.named_entities import with_named_entities
from pipeline.stage2_extraction import _extract_network_iocs, refang
from pipeline.stage3_llm import LLMEnrichmentResult


def _urls(text):
    return {e.value for e in _extract_network_iocs(text) if e.entity_type == EntityType.URL}


def _domains(text):
    return {e.value for e in _extract_network_iocs(text) if e.entity_type == EntityType.DOMAIN}


# ── #496: an FTP URL keeps its path after refang ─────────────────────────────

def test_ftp_url_keeps_its_path_after_refang():
    """(#496) fxxp:// refangs to ftp://, and the URL is extracted whole, not just its host."""
    normalized = refang("fxxp://files.evil.com/payload.exe")
    assert normalized == "ftp://files.evil.com/payload.exe"
    assert "ftp://files.evil.com/payload.exe" in _urls(normalized)


def test_ftp_host_is_not_a_separate_domain_once_its_url_is_extracted():
    """(#496) The FTP host is suppressed as a domain, like the HTTP host already is."""
    assert "files.evil.com" not in _domains("ftp://files.evil.com/payload.exe")


def test_http_url_is_still_extracted_whole():
    """(#496) The HTTP control case is unchanged."""
    assert "http://files.evil.com/payload.exe" in _urls("http://files.evil.com/payload.exe")


# ── #497: punctuation inside quotes belongs to the URL ───────────────────────

@pytest.mark.parametrize("text, url", [
    ('"https://example.com/path;"', "https://example.com/path;"),
    ('"https://example.com/path?key=value,"', "https://example.com/path?key=value,"),
    ('"https://example.com/a."', "https://example.com/a."),
    ('"https://example.com/path"', "https://example.com/path"),
])
def test_quoted_url_keeps_its_trailing_punctuation(text, url):
    """(#497) The closing quote says where the URL ends: a ';' or ',' in it is part of the URL."""
    assert url in _urls(text)


def test_quoted_url_in_parentheses_still_loses_the_unmatched_paren():
    """(#497) "(" ")" balance still applies inside quotes."""
    assert "https://example.com/a" in _urls('"(https://example.com/a)"')


@pytest.mark.parametrize("text, url", [
    ("see https://example.com/path; now", "https://example.com/path"),
    ("visit https://example.com/path, then", "https://example.com/path"),
    ("(https://example.com/a) in parens", "https://example.com/a"),
])
def test_prose_punctuation_is_still_stripped(text, url):
    """(#497) Punctuation after an unquoted URL is prose and is still removed."""
    assert url in _urls(text)
    assert not any(u.endswith((";", ",", ")")) for u in _urls(text))


# ── #506: sentence_bounds offsets index the original text ────────────────────

def _slices(text):
    return [text[s:e] for s, e in sentence_bounds(text)]


def test_triple_newline_gives_offsets_without_the_leading_newline():
    """(#506) `\\n\\n\\n` leaves no newline at the head of the next sentence."""
    text = "Heading\n\n\nSentence two."
    bounds = sentence_bounds(text)
    assert [text[s:e] for s, e in bounds] == ["Heading", "Sentence two."]


def test_whitespace_only_line_separates_paragraphs():
    """(#506) A blank line holding spaces is a paragraph break, not a sentence's inner text."""
    text = "Heading\n  \nSentence two."
    assert _slices(text) == ["Heading", "Sentence two."]


def test_whitespace_only_line_with_tabs_and_carriage_returns():
    """(#506) Tabs and CRs in the blank line count as blank too."""
    text = "Heading\n\t \r\nSentence two."
    assert _slices(text) == ["Heading", "Sentence two."]


def test_leading_blank_lines_are_not_part_of_the_first_sentence():
    """(#506) Whitespace before a paragraph is skipped, so the offsets start on text."""
    text = "  \n\nFirst para\n\n\n  Second para"
    assert _slices(text) == ["First para", "Second para"]


@pytest.mark.parametrize("text", [
    "Heading\n\n\nSentence two.",
    "Heading\n  \nSentence two.",
    "A sentence. Another one!\n\n\nLast line?  \n \nEnd.",
])
def test_every_span_is_exactly_its_sentence(text):
    """(#506) text[start:end] is a stripped sentence of the original text, never shifted."""
    for start, end in sentence_bounds(text):
        piece = text[start:end]
        assert piece == piece.strip()
        assert piece


# ── #507: outer whitespace does not hide a type conflict ─────────────────────

def test_type_conflict_is_resolved_across_outer_spaces():
    """(#507) "PsExec " (cyner, malware) and "PsExec" (gazetteer, tool) are one value."""
    entities = [
        RawEntity(value="PsExec", entity_type=EntityType.TOOL, source="gazetteer"),
        RawEntity(value="PsExec ", entity_type=EntityType.MALWARE, source="cyner"),
    ]
    result = resolve_type_conflicts(entities)
    assert [e.entity_type for e in result] == [EntityType.TOOL]


def test_merge_into_dedups_across_outer_spaces():
    """(#507) merge_into treats "PsExec " and "PsExec" of one type as the same entity."""
    from pipeline.base import BaseExtractionStage

    existing = [RawEntity(value="PsExec", entity_type=EntityType.TOOL, source="gazetteer")]
    new = [RawEntity(value="PsExec ", entity_type=EntityType.TOOL, source="cyner")]
    assert len(BaseExtractionStage.merge_into(existing, new)) == 1


def test_type_conflict_keeps_case_distinct_handling():
    """(#507) Only whitespace is stripped; the case folding is unchanged."""
    entities = [
        RawEntity(value="PsExec", entity_type=EntityType.TOOL, source="gazetteer"),
        RawEntity(value="psexec", entity_type=EntityType.MALWARE, source="cyner"),
    ]
    assert [e.entity_type for e in resolve_type_conflicts(entities)] == [EntityType.TOOL]


# ── #508: overrides canonical is stripped on the term fallback ───────────────

class _Rows(list):
    def fetchall(self):
        return list(self)


class _Conn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _sql):
        return _Rows(self._rows)


def test_promoted_canonical_falls_back_to_the_stripped_term(monkeypatch):
    """(#508) With no display, canonical is the term without its outer spaces."""
    import api.db as db
    from pipeline import overrides

    rows = [{"term": "  BadTool  ", "entity_type": "tool", "action": "promote", "display": None}]
    monkeypatch.setattr(db, "get_conn", lambda: _Conn(rows))
    monkeypatch.setattr(overrides, "overrides_enabled", lambda: True)
    overrides._load_active.cache_clear()
    try:
        entries = overrides.promoted_entries()
    finally:
        overrides._load_active.cache_clear()
    assert [e["canonical"] for e in entries] == ["BadTool"]
    assert [e["name"] for e in entries] == ["badtool"]


# ── #510: a NULL source in the job store does not crash the sort ─────────────

def test_a_null_source_next_to_a_named_source_does_not_crash():
    """(#510) ("malware", name, None) and ("malware", name, "llm") used to raise TypeError."""
    llm = LLMEnrichmentResult(threat_actors=["APT29"])
    out = with_named_entities(llm, [("malware", "APT29", "llm"), ("malware", "APT29", None)])
    assert out.outranked == ()


def test_a_null_source_is_the_lowest_priority_source():
    """(#510) A None source ranks after every named source: the tool wins over the malware."""
    out = with_named_entities(LLMEnrichmentResult(), [
        ("malware", "Widget", None),
        ("tool", "Widget", "gazetteer"),
    ])
    assert len(out.outranked) == 1
    lost = out.outranked[0]
    assert (lost.entity_type, lost.sources, lost.kept_types) == ("malware", ("",), ("tool",))
    assert lost.kept_sources == ("gazetteer",)


def test_non_null_source_order_is_unchanged():
    """(#510) Sources that are strings sort as before: the outranked sources list is the same."""
    out = with_named_entities(LLMEnrichmentResult(), [
        ("malware", "Widget", "spacy"),
        ("malware", "Widget", "cyner"),
        ("tool", "Widget", "gazetteer"),
    ])
    lost = [o for o in out.outranked if o.entity_type == "malware"][0]
    assert lost.sources == ("cyner", "spacy")
