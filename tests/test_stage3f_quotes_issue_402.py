"""Issue #402: three defects of Stage 3f select mode.

A quote copied with an invisible character (a zero-width space) is the same
words as the report: `_norm` drops what the prompt drops.  The spotlighting
marker lines around the report count in the prompt limit, so the report is
not cut for them.  An LLM proposal with an empty passage keeps the Stage 2c
passage of the same technique.

Every LLM call is a fake; no API key or model is needed.
"""
from __future__ import annotations

import json

from pipeline import stage3f_ttp_select as sel
from pipeline.llm_parse import fit_report
from pipeline.ttp_retrieval import TtpCandidate

ZWSP = "​"
TEXT = ("The actor used spear" + ZWSP + "phishing emails and PowerShell scripts "
        "to run the second-stage loader.")


def _cands(*ids):
    return [TtpCandidate(attack_id=i, name=f"name {i}", sources=["dense"], passage="p") for i in ids]


def _answer(quote, attack_id="T1566.001"):
    return lambda system, user: json.dumps({"selected": [{"attack_id": attack_id, "evidence_quote": quote,
                                                          "reason": "phishing"}]})


# ── Quotes and invisible characters ──────────────────────────────────────────

def test_a_quote_without_the_zero_width_space_is_found_in_the_report_issue_402():
    out = sel.select_ttps(TEXT, _cands("T1566.001"), _answer("The actor used spearphishing emails and PowerShell"))
    assert [t.mitre_id for t in out.selected] == ["T1566.001"]
    assert out.review == []


def test_a_quote_with_the_zero_width_space_is_found_issue_402():
    out = sel.select_ttps(TEXT, _cands("T1566.001"), _answer("The actor used spear" + ZWSP + "phishing emails"))
    assert [t.mitre_id for t in out.selected] == ["T1566.001"]
    assert out.review == []


def test_norm_drops_the_invisible_characters_the_prompt_drops_issue_402():
    assert sel._norm("spear​phishing﻿‮ x") == "spearphishing x"
    # Control: a no-break space is a word separator, not an invisible character.
    assert sel._norm("spear\xa0phishing") == "spear phishing"


def test_a_quote_with_a_different_word_still_goes_to_review_issue_402():
    out = sel.select_ttps(TEXT, _cands("T1566.001"), _answer("The actor used spearphishing emails and Mimikatz"))
    assert out.selected == []
    assert [r.attack_id for r in out.review] == ["T1566.001"]


# ── Prompt budget and spotlighting markers ───────────────────────────────────

def test_the_spotlighting_markers_count_in_the_prompt_limit_issue_402():
    report = "abc " * 2000
    cands = [TtpCandidate(attack_id=f"T10{i:02d}", name=f"Technique {i}", passage="x" * 200, sources=["dense"])
             for i in range(8)]
    # Eight candidates overflow the limit by 20 characters, fewer than the
    # marker lines add: the lowest ranked one goes, and the report is not cut.
    limit = len(fit_report(sel._SELECT_USER_TEMPLATE, report, None,
                           candidates=sel.format_candidates(cands))[0]) - 20
    seen = {}

    def fn(system, user):
        seen["user"] = user
        return '{"selected": []}'
    sel.select_ttps(report, cands, fn, max_prompt_chars=limit)
    assert report in seen["user"]
    assert len(seen["user"]) <= limit
    assert "T1007" not in seen["user"] and "T1006" in seen["user"]


def test_a_candidate_that_no_longer_fits_beside_the_markers_is_not_offered_issue_402():
    report = "abc " * 2000
    cands = [TtpCandidate(attack_id=f"T10{i:02d}", name=f"Technique {i}", passage="x" * 200, sources=["dense"])
             for i in range(8)]
    # The room for seven candidates, markers included: the eighth (the lowest
    # ranked) is not offered, and the report is not cut.
    limit = len(fit_report(sel._SELECT_USER_TEMPLATE, report, None,
                           candidates=sel.format_candidates(cands[:7]))[0])
    offered = sel._fit_candidates(report, cands, limit)
    assert [c.attack_id for c in offered] == [c.attack_id for c in cands[:7]]


# ── Passage of the chunk's candidates ────────────────────────────────────────

def test_an_llm_proposal_without_passage_keeps_the_2c_passage_issue_402():
    ret = [TtpCandidate(attack_id="T1059", name="Cmd", passage="PowerShell was used to run payloads",
                        sources=["dense"])]
    llm = [TtpCandidate(attack_id="T1059", name="Cmd", passage="", sources=["llm"])]
    [out] = sel.chunk_candidates(ret, llm)
    assert out.passage == "PowerShell was used to run payloads"
    assert out.sources == ["dense", "llm"]


def test_an_llm_passage_is_kept_over_the_2c_one_issue_402():
    ret = [TtpCandidate(attack_id="T1059", name="Cmd", passage="PowerShell was used", sources=["dense"])]
    llm = [TtpCandidate(attack_id="T1059", name="Cmd", passage="ran PowerShell", sources=["llm"])]
    [out] = sel.chunk_candidates(ret, llm)
    assert out.passage == "ran PowerShell"
