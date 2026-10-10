"""Stage 3d — what the relationship verifier is shown, and how it answers.

A claim is only checkable against text the verifier sees.  The text used to be
cut at 3 500 characters, which removed every document-level claim supported
further down the report and hid the tail of long reports' chunks.

What the verifier could not decide is held for an analyst (ADR-0082), never
kept as if verified: until 2026-10 a failed call, an unreadable answer, a
silent answer or a missing verdict all left the claim in the bundle.
"""
import json
import re

import pytest

import pipeline.stage3d_verify as v
from pipeline.llm_parse import fit_text
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, _merge_results

_CLAIM = re.compile(r'^(\d+)\. "([^"]+)" uses "([^"]+)"$', re.MULTILINE)


def _rels(n: int) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(relationships=[
        RelationshipExtracted(source_value=f"Actor{i}", relationship_type="uses",
                              target_value=f"Malware{i}")
        for i in range(n)
    ])


def _text(n: int) -> str:
    """A report stating every claim of `_rels(n)`."""
    return " ".join(f"Actor{i} uses Malware{i} in the wild." for i in range(n))


def _recorder(verdict=lambda n: True, answer=None):
    """An llm_fn that records its prompts and marks claim n by `verdict(n)`,
    quoting the sentence `_text` states it in."""
    calls: list[tuple[str, str]] = []

    def llm_fn(system: str, user: str) -> str:
        calls.append((system, user))
        if answer is not None:
            return answer
        return json.dumps([{"n": int(n), "verified": verdict(int(n)),
                            "quote": f"{src} uses {tgt} in the wild." if verdict(int(n)) else None}
                           for n, src, tgt in _CLAIM.findall(user)])
    return llm_fn, calls


def _reasons(out) -> dict[str, str]:
    return {h.source_value: h.reason for h in out.rel_review}


@pytest.fixture(autouse=True)
def _defaults(monkeypatch):
    monkeypatch.setattr(v, "_VERIFY_MIN_RELS", 1)
    monkeypatch.setattr(v, "_VERIFY_BATCH", 40)


def test_the_whole_text_reaches_the_verifier():
    text = "A" * 10_000 + " The support sits here, past 3 500 characters."
    llm_fn, calls = _recorder()
    v.verify_relationships(text, _rels(1), llm_fn, enabled=True)
    assert text in calls[0][1]


def test_past_the_limit_the_text_is_cut_and_the_claims_kept():
    text = "B" * 50_000
    llm_fn, calls = _recorder()
    v.verify_relationships(text, _rels(3), llm_fn, enabled=True, max_prompt_chars=5_000)
    prompt = calls[0][1]
    assert len(prompt) == 5_000
    assert '3. "Actor2" uses "Malware2"' in prompt
    assert "Return a JSON array" in prompt


def test_claims_are_verified_in_batches(monkeypatch):
    monkeypatch.setattr(v, "_VERIFY_BATCH", 2)
    llm_fn, calls = _recorder(verdict=lambda n: n != 1)
    out = v.verify_relationships(_text(5), _rels(5), llm_fn, enabled=True)
    assert len(calls) == 3
    # Numbering restarts per batch; claim 1 of each batch was refuted.
    assert [r.source_value for r in out.relationships] == ["Actor1", "Actor3"]
    assert out.relationships[0].evidence_text == "Actor1 uses Malware1 in the wild."
    assert out.rel_review == []


def test_a_failed_batch_holds_only_its_own_claims(monkeypatch):
    monkeypatch.setattr(v, "_VERIFY_BATCH", 2)
    answers = iter(["", json.dumps([{"n": 1, "verified": False}, {"n": 2, "verified": False}])])
    out = v.verify_relationships(_text(4), _rels(4), lambda s, u: next(answers), enabled=True)
    assert out.relationships == []
    assert _reasons(out) == {"Actor0": "verification call failed", "Actor1": "verification call failed"}


def test_an_unparseable_answer_holds_every_claim():
    llm_fn, _ = _recorder(answer="no json here")
    out = v.verify_relationships(_text(2), _rels(2), llm_fn, enabled=True)
    assert out.relationships == []
    assert set(_reasons(out).values()) == {"verification answer unparseable"}


def test_a_claim_the_answer_leaves_out_is_held():
    answer = json.dumps([{"n": 1, "verified": True, "quote": "Actor0 uses Malware0 in the wild."}])
    out = v.verify_relationships(_text(2), _rels(2), lambda s, u: answer, enabled=True)
    assert [r.source_value for r in out.relationships] == ["Actor0"]
    assert _reasons(out) == {"Actor1": "verification answer silent on this claim"}


@pytest.mark.parametrize("verdict, ships", [
    (True, True), ("true", True), ("False", False), (None, None), ("maybe", None), (1, None),
])
def test_only_a_true_or_false_verdict_decides(verdict, ships):
    item = {"n": 1, "quote": "Actor0 uses Malware0 in the wild."}
    if verdict is not None:
        item["verified"] = verdict
    out = v.verify_relationships(_text(1), _rels(1), lambda s, u: json.dumps([item]), enabled=True)
    if ships is None:      # `verified` omitted used to count as true
        assert out.relationships == []
        assert _reasons(out) == {"Actor0": "verification gave no true/false verdict"}
    else:
        assert len(out.relationships) == int(ships) and out.rel_review == []


def test_a_verified_claim_needs_a_quote_from_the_text():
    for quote, reason in ((None, "verified without a quote"),
                          ("  ", "verified without a quote"),
                          ("Actor0 deployed Malware0 last spring.", "quote not found in the text")):
        answer = json.dumps([{"n": 1, "verified": True, "quote": quote}])
        out = v.verify_relationships(_text(1), _rels(1), lambda s, u, a=answer: a, enabled=True)
        assert out.relationships == []
        assert _reasons(out) == {"Actor0": reason}
    # The unfound quote stays with the held claim, for the analyst to judge.
    assert out.rel_review[0].evidence_text == "Actor0 deployed Malware0 last spring."


def test_a_held_claim_keeps_what_extraction_gave_it():
    rel = RelationshipExtracted(source_value="APT29", relationship_type="uses", target_value="SUNBURST",
                                confidence=0.7, evidence_text="APT29 used SUNBURST.",
                                evidence_label="assessed")
    out = v.verify_relationships("APT29 used SUNBURST.", LLMEnrichmentResult(relationships=[rel]),
                                 lambda s, u: "", enabled=True)
    held = out.rel_review[0]
    assert (held.confidence, held.evidence_text, held.evidence_label.value) == (
        0.7, "APT29 used SUNBURST.", "assessed")


def test_a_claim_held_in_one_chunk_and_verified_in_another_ships_once():
    llm_fn, _ = _recorder()
    verified = v.verify_relationships(_text(2), _rels(2), llm_fn, enabled=True)
    held = v.verify_relationships(_text(3), _rels(3), lambda s, u: "", enabled=True)
    again = v.verify_relationships(_text(3), _rels(3), lambda s, u: "", enabled=True)
    merged = _merge_results([verified, held, again])
    assert sorted(r.source_value for r in merged.relationships) == ["Actor0", "Actor1"]
    assert [h.source_value for h in merged.rel_review] == ["Actor2"]


def test_the_document_mode_accepts_a_reference_sentence_but_not_a_chain():
    llm_fn, calls = _recorder()
    v.verify_relationships("text", _rels(1), llm_fn, enabled=True, document=True)
    system = calls[0][0]
    assert system.startswith(v._VERIFY_SYSTEM_DOCUMENT)
    assert "TWO sentences" in system and "A chain through a third entity is NOT support" in system


def test_the_chunk_mode_keeps_the_single_sentence_rule():
    llm_fn, calls = _recorder()
    v.verify_relationships("text", _rels(1), llm_fn, enabled=True)
    assert calls[0][0].startswith(v._VERIFY_SYSTEM)


def test_a_two_sentence_quote_survives_in_document_mode():
    first = "The group, tracked as APT29, is Russian. " * 12
    text = first + "Unrelated filler in between. The group deployed SUNBURST."
    quote = first + "[...] The group deployed SUNBURST."
    llm_fn, _ = _recorder(answer=json.dumps([{"n": 1, "verified": True, "quote": quote}]))
    out = v.verify_relationships(text, _rels(1), llm_fn, enabled=True, document=True)
    assert out.relationships[0].evidence_text == quote.strip()
    out = v.verify_relationships(text, _rels(1), llm_fn, enabled=True)
    assert len(out.relationships[0].evidence_text) == 500


def test_a_two_sentence_quote_needs_both_sentences_in_the_text():
    quote = "The group, tracked as APT29, is Russian. [...] The group deployed SUNBURST."
    llm_fn, _ = _recorder(answer=json.dumps([{"n": 1, "verified": True, "quote": quote}]))
    out = v.verify_relationships("The group deployed SUNBURST.", _rels(1), llm_fn, enabled=True,
                                 document=True)
    assert _reasons(out) == {"Actor0": "quote not found in the text"}


def test_fit_text_leaves_a_prompt_that_fits_untouched():
    assert fit_text("[{text}] {claims}", "abc", 100, claims="c") == "[abc] c"
    assert fit_text("[{text}] {claims}", "abc", None, claims="c") == "[abc] c"
    assert fit_text("[{text}] {claims}", "abcdef", 8, claims="c") == "[abcd] c"
