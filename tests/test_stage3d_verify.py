"""Stage 3d — what the relationship verifier is shown, and how it answers.

A claim is only checkable against text the verifier sees.  The text used to be
cut at 3 500 characters, which removed every document-level claim supported
further down the report and hid the tail of long reports' chunks.
"""
import json

import pytest

import pipeline.stage3d_verify as v
from pipeline.llm_parse import fit_text
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted


def _rels(n: int) -> LLMEnrichmentResult:
    return LLMEnrichmentResult(relationships=[
        RelationshipExtracted(source_value=f"Actor{i}", relationship_type="uses",
                              target_value=f"Malware{i}")
        for i in range(n)
    ])


def _recorder(verdict=lambda n: True, answer=None):
    """An llm_fn that records its prompts and marks claim n by `verdict(n)`."""
    calls: list[tuple[str, str]] = []

    def llm_fn(system: str, user: str) -> str:
        calls.append((system, user))
        if answer is not None:
            return answer
        count = user.count('" uses "')
        return json.dumps([{"n": n, "verified": verdict(n), "quote": f"quote {n}" if verdict(n) else None}
                           for n in range(1, count + 1)])
    return llm_fn, calls


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
    out = v.verify_relationships("text", _rels(5), llm_fn, enabled=True)
    assert len(calls) == 3
    # Numbering restarts per batch; claim 1 of each batch was refuted.
    assert [r.source_value for r in out.relationships] == ["Actor1", "Actor3"]
    assert out.relationships[0].evidence_text == "quote 2"


def test_a_failed_batch_keeps_only_its_own_claims(monkeypatch):
    monkeypatch.setattr(v, "_VERIFY_BATCH", 2)
    answers = iter(["", json.dumps([{"n": 1, "verified": False}, {"n": 2, "verified": False}])])
    out = v.verify_relationships("text", _rels(4), lambda s, u: next(answers), enabled=True)
    assert [r.source_value for r in out.relationships] == ["Actor0", "Actor1"]


def test_an_unparseable_answer_keeps_every_claim():
    llm_fn, _ = _recorder(answer="no json here")
    out = v.verify_relationships("text", _rels(2), llm_fn, enabled=True)
    assert len(out.relationships) == 2


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
    quote = "The group, tracked as APT29, is Russian. " * 12 + "[...] The group deployed SUNBURST."
    llm_fn, _ = _recorder(answer=json.dumps([{"n": 1, "verified": True, "quote": quote}]))
    out = v.verify_relationships("text", _rels(1), llm_fn, enabled=True, document=True)
    assert out.relationships[0].evidence_text == quote.strip()
    out = v.verify_relationships("text", _rels(1), llm_fn, enabled=True)
    assert len(out.relationships[0].evidence_text) == 500


def test_fit_text_leaves_a_prompt_that_fits_untouched():
    assert fit_text("[{text}] {claims}", "abc", 100, claims="c") == "[abc] c"
    assert fit_text("[{text}] {claims}", "abc", None, claims="c") == "[abc] c"
    assert fit_text("[{text}] {claims}", "abcdef", 8, claims="c") == "[abcd] c"
