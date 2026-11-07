"""Issue #398 — what Stage 3d leaves on a relationship it verifies.

A relationship whose quote the verifier finds in the text is stated by the
source: a `gap` claim that gets such a quote becomes `reported`, the grade
Stage 3f's select mode gives a technique it finds quoted.  The quote kept as
evidence is cut at a word boundary, never in the middle of a word.
"""
import json

import pytest

import pipeline.stage3d_verify as v
from models.schemas import EvidenceLabel
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted

TEXT = "APT29 uses SUNBURST to move laterally inside the victim network."


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.setattr(v, "_VERIFY_MIN_RELS", 1)
    monkeypatch.setattr(v, "_VERIFY_BATCH", 40)


def _rel(label: EvidenceLabel) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(relationships=[RelationshipExtracted(
        source_value="APT29", relationship_type="uses", target_value="SUNBURST",
        evidence_text="", evidence_label=label)])


def _answer(quote: str | None):
    """An llm_fn that verifies claim 1 with `quote` (None: refuted)."""
    def llm_fn(system: str, user: str) -> str:
        return json.dumps([{"n": 1, "verified": quote is not None, "quote": quote}])
    return llm_fn


def test_a_gap_claim_backed_by_a_quote_becomes_reported():  # issue_398
    out = v.verify_relationships(TEXT, _rel(EvidenceLabel.GAP), _answer(TEXT), enabled=True)
    assert len(out.relationships) == 1
    assert out.relationships[0].evidence_label == EvidenceLabel.REPORTED
    assert out.relationships[0].evidence_text == TEXT


@pytest.mark.parametrize("label", [EvidenceLabel.OBSERVED, EvidenceLabel.REPORTED,
                                   EvidenceLabel.ASSESSED, EvidenceLabel.INFERRED])
def test_a_verified_claim_keeps_any_other_label(label):  # issue_398, control
    out = v.verify_relationships(TEXT, _rel(label), _answer(TEXT), enabled=True)
    assert out.relationships[0].evidence_label == label


def test_a_gap_claim_held_for_review_keeps_gap():  # issue_398, control
    quote = "APT29 deployed SUNBURST last spring."
    out = v.verify_relationships(TEXT, _rel(EvidenceLabel.GAP), _answer(quote), enabled=True)
    assert out.relationships == []
    assert out.rel_review[0].evidence_label == EvidenceLabel.GAP


def test_a_long_quote_is_cut_at_a_word_boundary():  # issue_398
    quote = " ".join(f"word{i}" for i in range(200)) + "."
    out = v.verify_relationships(quote, _rel(EvidenceLabel.REPORTED), _answer(quote), enabled=True)
    kept = out.relationships[0].evidence_text
    assert kept.endswith("…")
    assert len(kept) <= 500
    body = kept[:-1]
    assert quote.startswith(body)
    assert quote[len(body)] == " "   # the cut falls between two words
