"""Merging chunks must keep the better-evidenced duplicate, not the last one."""
from __future__ import annotations

from pipeline.stage3_llm import (
    LLMEnrichmentResult,
    RelationshipExtracted,
    TTPExtracted,
    _evidence_rank,
    _merge_results,
    _prefer,
)

QUOTE = "the actor sent a spearphishing email with a macro attachment"


def _ttp(evidence: str | None, mitre_id: str = "T1566.001") -> LLMEnrichmentResult:
    """One chunk result carrying a single TTP with the given evidence."""
    return LLMEnrichmentResult(ttps=[TTPExtracted(
        technique_name="Spearphishing Attachment",
        mitre_id=mitre_id, evidence_text=evidence)])


def test_quote_survives_an_unquoted_later_chunk():
    """The measured case: citation was lost to a later unquoted chunk."""
    merged = _merge_results([_ttp(QUOTE), _ttp(None)])
    assert merged.ttps[0].evidence_text == QUOTE


def test_merge_is_order_independent_for_ttps():
    """Merging should not depend on the order of chunks."""
    a = _merge_results([_ttp(QUOTE), _ttp(None)])
    b = _merge_results([_ttp(None), _ttp(QUOTE)])
    assert a.ttps[0].evidence_text == b.ttps[0].evidence_text == QUOTE


def test_longer_quote_wins_over_shorter():
    """A full clause should beat a single word."""
    long_q = "the loader downloaded a second stage from the C2 over HTTPS"
    merged = _merge_results([_ttp(long_q, "T1105"), _ttp("downloaded", "T1105")])
    assert merged.ttps[0].evidence_text == long_q


def test_relationship_quote_and_confidence_survive():
    """Relationships should keep both the quote and the higher confidence."""
    r1 = LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="APT29", relationship_type="uses", target_value="WellMess",
        confidence=0.9, evidence_text=QUOTE)])
    r2 = LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="APT29", relationship_type="uses", target_value="WellMess",
        confidence=0.5)])
    merged = _merge_results([r1, r2])
    assert len(merged.relationships) == 1
    assert merged.relationships[0].evidence_text == QUOTE
    assert merged.relationships[0].confidence == 0.9


def test_higher_confidence_wins_when_evidence_is_equal():
    """When evidence is equal, higher confidence should win."""
    r1 = LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="A", relationship_type="uses", target_value="B",
        confidence=0.4)])
    r2 = LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="A", relationship_type="uses", target_value="B",
        confidence=0.8)])
    merged = _merge_results([r1, r2])
    assert merged.relationships[0].confidence == 0.8


def test_incumbent_kept_on_a_full_tie():
    """On a full tie, the incumbent (first seen) should be kept."""
    t1 = TTPExtracted(technique_name="First Name", mitre_id="T1059", evidence_text=QUOTE)
    t2 = TTPExtracted(technique_name="Second Name", mitre_id="T1059", evidence_text=QUOTE)
    # Fallback: verify _prefer directly if normalize_ttps interferes
    assert _prefer(t1, t2) is t1


def test_evidence_rank_scores_absent_and_blank_the_same():
    """Absent, empty, and whitespace evidence should all score (0, 0)."""
    assert _evidence_rank(TTPExtracted(technique_name="x")) == (0, 0)
    assert _evidence_rank(TTPExtracted(technique_name="x", evidence_text="")) == (0, 0)
    assert _evidence_rank(TTPExtracted(technique_name="x", evidence_text="   ")) == (0, 0)
    assert _evidence_rank(TTPExtracted(technique_name="x", evidence_text="abc")) == (1, 3)


def test_prefer_returns_candidate_when_incumbent_is_none():
    """If there is no incumbent, the candidate should be returned."""
    t = TTPExtracted(technique_name="x")
    assert _prefer(None, t) is t


def test_deduplication_still_collapses_duplicates():
    """Deduplication should still collapse identical duplicates."""
    merged = _merge_results([_ttp(QUOTE), _ttp(QUOTE)])
    assert len(merged.ttps) == 1


def test_name_only_ttp_still_absorbed_by_an_id_bearing_one():
    """Name-only TTPs should still be absorbed by id-bearing ones."""
    r1 = LLMEnrichmentResult(ttps=[TTPExtracted(
        technique_name="Spearphishing Attachment", mitre_id=None)])
    r2 = LLMEnrichmentResult(ttps=[TTPExtracted(
        technique_name="Spearphishing Attachment", mitre_id="T1566.001")])
    merged = _merge_results([r1, r2])
    assert len(merged.ttps) == 1
    assert merged.ttps[0].mitre_id == "T1566.001"
