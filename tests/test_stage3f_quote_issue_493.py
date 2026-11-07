"""Issue #493: a Stage 3f verdict counts only when its quote is in the text.

A claim the checker marks verified is kept only when the quote it gives is a
sentence of the source (`stated_in`, the check Stage 3d already makes).  An
invented quote, or an empty one, does not verify the claim, and an invented
quote is never copied into the technique's description.  Every LLM call is a
fake; no model is needed.
"""
from __future__ import annotations

import json

import pipeline.stage3f_ttp_verify as v
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted

TEXT = "The attacker sent a phishing email."


def _answer(verified, quote):
    """A checker answer for claim 1 only."""
    return lambda system, user: json.dumps([{"n": 1, "verified": verified, "quote": quote}])


def _result():
    return LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="Phishing", mitre_id="T1566.001")])


def test_an_invented_quote_does_not_verify_the_claim_issue_493():
    out = v.verify_ttps(TEXT, _result(), _answer(True, "The attackers launched malicious rocket ships."),
                        enabled=True)
    assert out.ttps == []


def test_an_empty_quote_does_not_verify_the_claim_issue_493():
    out = v.verify_ttps(TEXT, _result(), _answer(True, ""), enabled=True)
    assert out.ttps == []


def test_a_quote_from_the_text_fills_the_empty_description_issue_493():
    out = v.verify_ttps(TEXT, _result(), _answer(True, "The attacker sent a phishing email."), enabled=True)
    assert [t.description for t in out.ttps] == ["The attacker sent a phishing email."]


def test_a_quote_from_the_text_with_other_case_and_spacing_still_verifies_issue_493():
    out = v.verify_ttps(TEXT, _result(), _answer(True, "THE  ATTACKER sent a phishing email."), enabled=True)
    assert [t.mitre_id for t in out.ttps] == ["T1566.001"]
