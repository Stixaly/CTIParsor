"""Issue #378: a bare `[]` in the preamble of a selection answer is not an
abstention when the real answer follows it.

`parse_selection` reads the first complete `[` or `{` value.  The `[]` of
"(or [] if none)" was an empty list of dicts, so `all()` accepted it and the
answer read as an abstention: the real selection after it was never read.
An answer that is only `[]` stays an abstention.

Every LLM call is a fake; no API key or model is needed.
"""
from __future__ import annotations

import json

import pytest

from pipeline import stage3f_ttp_select as sel
from pipeline.ttp_retrieval import TtpCandidate

TEXT = ("The actor sent emails with malicious Word attachments to finance staff. "
        "Once opened, the macro ran PowerShell to download a second-stage loader.")

SELECTION = {"selected": [{"attack_id": "T1059.001", "evidence_quote": "the macro ran PowerShell to download",
                           "reason": "PowerShell run by the macro"}]}


def _cands(*ids):
    return [TtpCandidate(attack_id=i, name=f"name {i}", sources=["dense"], passage="p") for i in ids]


def test_an_empty_list_in_the_preamble_does_not_hide_the_selection_issue_378():
    raw = 'Here is the result (or [] if none):\n' + json.dumps(SELECTION)
    assert sel.parse_selection(raw) == SELECTION["selected"]


def test_the_selection_after_a_preamble_empty_list_reaches_the_bundle_issue_378():
    raw = 'Here is the result (or [] if none):\n' + json.dumps(SELECTION)
    out = sel.select_ttps(TEXT, _cands("T1059.001", "T1566.001"), lambda s, u: raw)
    assert out.status == sel.OK
    assert [t.mitre_id for t in out.selected] == ["T1059.001"]
    assert out.review == []


def test_a_bare_list_after_a_preamble_empty_list_is_read_issue_378():
    raw = 'Nothing else applies, so [] is not the answer. [{"attack_id": "T1059.001"}]'
    assert sel.parse_selection(raw) == [{"attack_id": "T1059.001"}]


@pytest.mark.parametrize("raw", [
    "[]",
    '```json\n[]\n```',
    '{"selected": []}',
    'Sure, none ([] here).\n{"selected": []}',
    '[] [] [] {"selected": []}',
])
def test_an_answer_of_only_empty_choices_is_still_an_abstention_issue_378(raw):
    assert sel.parse_selection(raw) == []
    out = sel.select_ttps(TEXT, _cands("T1059.001"), lambda s, u: raw)
    assert out.status == sel.OK and out.selected == [] and out.review == []
