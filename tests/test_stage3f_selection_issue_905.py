"""Issue #905: an empty `selected` list before the real answer is an abstention
that the answer after it overrides, as a bare `[]` already is (#378); and
`salvage_selection` reads the object that holds `selected` even when a closed
sub-object sits before the key.

Every LLM call is a fake; no API key or model is needed.
"""
from __future__ import annotations

import json

from pipeline import stage3f_ttp_select as sel
from pipeline.ttp_retrieval import TtpCandidate

TEXT = ("The actor sent emails with malicious Word attachments to finance staff. "
        "Once opened, the macro ran PowerShell to download a second-stage loader.")

CHOICE = {"attack_id": "T1059.001", "evidence_quote": "the macro ran PowerShell to download",
          "reason": "PowerShell run by the macro"}


def _cands(*ids):
    return [TtpCandidate(attack_id=i, name=f"name {i}", sources=["dense"], passage="p") for i in ids]


def test_an_empty_selected_before_the_real_answer_is_not_the_answer_issue_905():
    raw = '{"selected": []}\n' + json.dumps({"selected": [CHOICE]})
    assert sel.parse_selection(raw) == [CHOICE]
    out = sel.select_ttps(TEXT, _cands("T1059.001", "T1566.001"), lambda s, u: raw)
    assert out.status == sel.OK
    assert [t.mitre_id for t in out.selected] == ["T1059.001"]
    assert out.review == []


def test_salvage_reads_the_answer_past_a_closed_sub_object_issue_905():
    # The nearest `{` before the key is the closed {"k": 1}, which decodes whole:
    # the answer is the object that holds the key, still open at the cut.
    raw = ('{"meta": {"k": 1}, "selected": [' + json.dumps(CHOICE)
           + ', {"attack_id": "T1566.001", "reason": "cut')
    assert sel.salvage_selection(raw) == [CHOICE]
    out = sel.select_ttps(TEXT, _cands("T1059.001", "T1566.001"), lambda s, u: raw)
    assert out.status == sel.TRUNCATED
    assert [t.mitre_id for t in out.selected] == ["T1059.001"]
