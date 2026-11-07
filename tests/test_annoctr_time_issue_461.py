"""evaluation/annoctr_time.score — a one-character repair that is left at a year
candidate (#461).  The gold span "n early March" does not read; its repair
"early March" reads as year_from_context, with 2016-03 as the candidate.  That
candidate, and the reason, count as they do for an unread gold span.  The
`is_relative` test stays on the gold span text, as it always did."""
from __future__ import annotations

from evaluation import annoctr_time as at

_DCT = "2016-06-17"


def _doc(text, span, value="2016-03"):
    s = text.index(span)
    return at.TimeDoc("d", "dev", _DCT, text, [at.Timex(span, value, "DATE", s, s + len(span))])


def test_a_repair_left_at_a_year_candidate_is_counted_issue_461():
    # "n early March" is unparsed; "early March" (one character narrower) reads
    # as year_from_context with 2016-03, the gold value.
    doc = _doc("They struck n early March again.", "n early March")
    gold = at.score([doc], repair_spans=False)
    repaired = at.score([doc], repair_spans=True)

    assert gold.reasons == {"unparsed": 1} and gold.year_candidates == 0
    assert repaired.read == 0 and repaired.total == 1
    assert repaired.reasons == {"year_from_context": 1}
    assert (repaired.year_candidates, repaired.year_candidates_right) == (1, 1)


def test_the_gold_span_candidate_is_kept_when_it_has_one_issue_461():
    """Control: the gold span already gives the year candidate; nothing changes."""
    doc = _doc("They struck early March again.", "early March")
    for repair in (False, True):
        sc = at.score([doc], repair_spans=repair)
        assert sc.reasons == {"year_from_context": 1}
        assert (sc.year_candidates, sc.year_candidates_right) == (1, 1)


def test_every_expression_is_read_or_has_one_reason_issue_461():
    doc = _doc("They struck n early March again.", "n early March")
    sc = at.score([doc], repair_spans=True)
    assert sc.read + sum(sc.reasons.values()) == sc.total
