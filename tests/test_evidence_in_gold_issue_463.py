"""Issue #463: `in_gold` must say whether a technique is in the gold set, located
mention or not.  The ratios still range over located gold mentions only."""
import csv

import pytest

from evaluation import evidence

TEXT = ("Intro paragraph about the campaign and its victims. "
        "The loader downloads the second stage payload from a remote server. "
        "Nothing else of note happened during the intrusion that week.")
DOWNLOADS = "The loader downloads the second stage payload from a remote server."
NOTHING = "Nothing else of note happened during the intrusion that week."


def _rows(gold_techs=None):
    s = TEXT.index("downloads the second")
    # T1105 has a located gold mention; T1566 is gold but none of its mentions
    # could be placed; T1027 is not in the gold set at all.
    spans = {"T1105": [(s, s + 40)]}
    ttps = [
        {"mitre_id": "T1105", "evidence_text": DOWNLOADS},
        {"mitre_id": "T1566", "evidence_text": NOTHING},
        {"mitre_id": "T1027", "evidence_text": NOTHING},
    ]
    kwargs = {} if gold_techs is None else {"gold_techs": gold_techs}
    return evidence.check("d", TEXT, ttps, spans, lambda t: t or None, **kwargs)


def test_an_unlocated_gold_technique_is_in_gold_but_not_located_in_gold():
    located_gold, unlocated_gold, not_gold = _rows({"T1105", "T1566"})
    assert (located_gold.correct, located_gold.gold_located) == (True, True)
    assert (unlocated_gold.correct, unlocated_gold.gold_located) == (True, False)
    assert (not_gold.correct, not_gold.gold_located) == (False, False)
    assert unlocated_gold.located is not None
    assert unlocated_gold.on_passage is None and unlocated_gold.near_passage is None


def test_without_gold_techs_the_gold_set_is_the_located_spans():
    # The default keeps the earlier call: an unlocated gold technique is not known.
    located_gold, unlocated_gold, _ = _rows()
    assert located_gold.correct is True and located_gold.on_passage is True
    assert unlocated_gold.correct is False and unlocated_gold.gold_located is False


def test_ratios_do_not_count_the_unlocated_gold_technique_issue_463():
    summary = evidence.summarise(_rows({"T1105", "T1566"}))
    # Only the located gold technique is in the denominator, as before the change.
    assert summary["ttps_with_quote"] == 3
    assert summary["correct_and_located"] == 1
    assert summary["on_annotated_passage"] == 1.0
    assert summary["near_annotated_passage"] == 1.0
    assert summary == evidence.summarise(_rows())


def test_the_csv_carries_in_gold_and_gold_located_issue_463(tmp_path, monkeypatch):
    import pipeline.mitre_db

    monkeypatch.setattr(pipeline.mitre_db, "lookup_by_id", lambda tid: {"name": tid.lower()})
    path = tmp_path / "support-sample.csv"
    n = evidence.support_sample(_rows({"T1105", "T1566"}), {"d": TEXT}, path, n=10)
    assert n == 3
    with path.open(encoding="utf-8", newline="") as f:
        by_tech = {r["technique"]: r for r in csv.DictReader(f)}
    assert (by_tech["T1105"]["in_gold"], by_tech["T1105"]["gold_located"]) == ("True", "True")
    assert (by_tech["T1566"]["in_gold"], by_tech["T1566"]["gold_located"]) == ("True", "False")
    assert (by_tech["T1027"]["in_gold"], by_tech["T1027"]["gold_located"]) == ("False", "False")
    assert by_tech["T1566"]["supports_use (yes/no/unsure)"] == ""


@pytest.mark.parametrize("gold_techs", [None, {"T1105"}])
def test_located_gold_technique_is_unchanged_issue_463(gold_techs):
    # The control: a technique with a located mention gets the same passage flags
    # whether or not the caller passes the gold set.
    [row, *_] = _rows(gold_techs)
    assert row.correct is True and row.gold_located is True
    assert row.on_passage is True and row.near_passage is True
