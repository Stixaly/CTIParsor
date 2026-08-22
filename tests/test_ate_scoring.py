"""
Regression tests for the ATE scorer — ADR-0023 Phase 1.

These lock the two defects the pre-ADR-0023 scorer had:
  1. Fractional parent/sub-technique credit leaked mass out of the
     accounting: a prediction could contribute 0.5 to TP and 0 to FP, so
     predicting T1059.001 and T1059.002 against a gold T1059 scored
     precision 1.00 and recall 1.00.
  2. Corpus-level micro-averaging let long, technique-dense samples
     dominate the score.

Every test here must FAIL against the old scorer.  scripts/verify_ate_scorer.py
proves that by re-implementing the old behaviour and re-running these
assertions against it.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.eval_pipeline import (
    ATESample,
    _clean_ids,
    _score_ate_sample,
    _score_one_granularity,
    _truncate_to_parent,
    run_ate_benchmark,
)


def test_truncate_to_parent():
    """_truncate_to_parent correctly extracts parent technique IDs."""
    assert _truncate_to_parent("T1059.001") == "T1059", \
        "T1059.001 should truncate to T1059"
    assert _truncate_to_parent("T1059") == "T1059", \
        "T1059 (no sub-technique) should remain T1059"
    assert _truncate_to_parent("t1059.001") == "T1059", \
        "lowercase t1059.001 should normalize and truncate to T1059"
    assert _truncate_to_parent(" T1566.002 ") == "T1566", \
        "padded ' T1566.002 ' should strip and truncate to T1566"
    assert _truncate_to_parent("T1027.010") == "T1027", \
        "T1027.010 should truncate to T1027"


def test_clean_ids_guards_non_string_input():
    """_clean_ids filters out non-string and empty elements."""
    result = _clean_ids(["T1059", 42, None, "", "  ", "t1566.001"])
    assert result == {"T1059", "T1566.001"}, \
        f"_clean_ids should filter non-strings and empties, got {result}"


def test_no_partial_credit_parent_predicted_sub_is_gold():
    """Predicting parent when sub-technique is gold: no partial credit."""
    tech_res, sub_res = _score_ate_sample({"T1059"}, {"T1059.001"})

    # Sub-technique level: mismatch -> 0.0 everywhere
    assert sub_res[0] == 0.0, \
        f"sub-technique precision should be 0.0, got {sub_res[0]}"
    assert sub_res[1] == 0.0, \
        f"sub-technique recall should be 0.0, got {sub_res[1]}"
    assert sub_res[2] == 0.0, \
        f"sub-technique F1 should be 0.0, got {sub_res[2]}"
    assert sub_res[3] == 0, f"sub-technique TP should be 0, got {sub_res[3]}"
    assert sub_res[4] == 1, f"sub-technique FP should be 1, got {sub_res[4]}"
    assert sub_res[5] == 1, f"sub-technique FN should be 1, got {sub_res[5]}"

    # Technique level: match -> 1.0 everywhere
    assert tech_res[0] == 1.0, \
        f"technique precision should be 1.0, got {tech_res[0]}"
    assert tech_res[1] == 1.0, \
        f"technique recall should be 1.0, got {tech_res[1]}"
    assert tech_res[2] == 1.0, \
        f"technique F1 should be 1.0, got {tech_res[2]}"
    assert tech_res[3] == 1, f"technique TP should be 1, got {tech_res[3]}"
    assert tech_res[4] == 0, f"technique FP should be 0, got {tech_res[4]}"
    assert tech_res[5] == 0, f"technique FN should be 0, got {tech_res[5]}"


def test_no_partial_credit_sub_predicted_parent_is_gold():
    """Predicting sub-technique when parent is gold: no partial credit."""
    tech_res, sub_res = _score_ate_sample({"T1059.001"}, {"T1059"})

    # Sub-technique level: mismatch -> 0.0 everywhere
    assert sub_res[0] == 0.0, \
        f"sub-technique precision should be 0.0, got {sub_res[0]}"
    assert sub_res[1] == 0.0, \
        f"sub-technique recall should be 0.0, got {sub_res[1]}"
    assert sub_res[2] == 0.0, \
        f"sub-technique F1 should be 0.0, got {sub_res[2]}"
    assert sub_res[3] == 0, f"sub-technique TP should be 0, got {sub_res[3]}"
    assert sub_res[4] == 1, f"sub-technique FP should be 1, got {sub_res[4]}"
    assert sub_res[5] == 1, f"sub-technique FN should be 1, got {sub_res[5]}"

    # Technique level: match -> 1.0 everywhere
    assert tech_res[0] == 1.0, \
        f"technique precision should be 1.0, got {tech_res[0]}"
    assert tech_res[1] == 1.0, \
        f"technique recall should be 1.0, got {tech_res[1]}"
    assert tech_res[2] == 1.0, \
        f"technique F1 should be 1.0, got {tech_res[2]}"
    assert tech_res[3] == 1, f"technique TP should be 1, got {tech_res[3]}"
    assert tech_res[4] == 0, f"technique FP should be 0, got {tech_res[4]}"
    assert tech_res[5] == 0, f"technique FN should be 0, got {tech_res[5]}"


def test_two_subs_one_parent_gold_is_not_perfect():
    """
    Central test: predicting two sub-techniques against one parent gold.
    Pre-ADR-0023 scorer returned 1.00/1.00 here; new scorer must not.
    """
    tech_res, sub_res = _score_ate_sample({"T1059.001", "T1059.002"}, {"T1059"})

    # Sub-technique level: both predictions are FP, gold is FN
    assert sub_res[3] == 0, f"sub-technique TP should be 0, got {sub_res[3]}"
    assert sub_res[4] == 2, f"sub-technique FP should be 2, got {sub_res[4]}"
    assert sub_res[5] == 1, f"sub-technique FN should be 1, got {sub_res[5]}"
    assert sub_res[0] == 0.0, \
        f"sub-technique precision should be 0.0, got {sub_res[0]}"
    assert sub_res[1] == 0.0, \
        f"sub-technique recall should be 0.0, got {sub_res[1]}"

    # Technique level: both collapse to T1059, so TP=1, FP=0, FN=0
    assert tech_res[3] == 1, f"technique TP should be 1, got {tech_res[3]}"
    assert tech_res[4] == 0, f"technique FP should be 0, got {tech_res[4]}"
    assert tech_res[5] == 0, f"technique FN should be 0, got {tech_res[5]}"
    assert tech_res[0] == 1.0, \
        f"technique precision should be 1.0, got {tech_res[0]}"
    assert tech_res[1] == 1.0, \
        f"technique recall should be 1.0, got {tech_res[1]}"

    # Explicit assertion that sub-technique precision is NOT 1.0
    assert sub_res[0] < 1.0, \
        "pre-ADR-0023 scorer returned 1.00 here"


def test_accounting_is_closed():
    """
    For every (pred, gold) pair, verify that tp + fp == len(pred) and
    tp + fn == len(gold) at BOTH granularities. This is the invariant that
    the partial-credit leak violated.
    """
    cases = [
        ({"T1059"}, {"T1059.001"}),
        ({"T1059.001", "T1059.002"}, {"T1059"}),
        ({"T1566.001"}, {"T1566.001"}),
        ({"T1486"}, {"T1566.001"}),
        (set(), {"T1059"}),
        ({"T1059"}, set()),
    ]

    for pred, gold in cases:
        tech_res, sub_res = _score_ate_sample(pred, gold)

        # Sub-technique granularity
        sub_pred_clean = _clean_ids(pred)
        sub_gold_clean = _clean_ids(gold)
        assert sub_res[3] + sub_res[4] == len(sub_pred_clean), \
            f"sub-technique: tp({sub_res[3]}) + fp({sub_res[4]}) != len(pred)({len(sub_pred_clean)})"
        assert sub_res[3] + sub_res[5] == len(sub_gold_clean), \
            f"sub-technique: tp({sub_res[3]}) + fn({sub_res[5]}) != len(gold)({len(sub_gold_clean)})"

        # Technique granularity
        tech_pred_clean = {_truncate_to_parent(t) for t in sub_pred_clean}
        tech_gold_clean = {_truncate_to_parent(t) for t in sub_gold_clean}
        assert tech_res[3] + tech_res[4] == len(tech_pred_clean), \
            f"technique: tp({tech_res[3]}) + fp({tech_res[4]}) != len(pred)({len(tech_pred_clean)})"
        assert tech_res[3] + tech_res[5] == len(tech_gold_clean), \
            f"technique: tp({tech_res[3]}) + fn({tech_res[5]}) != len(gold)({len(tech_gold_clean)})"


def test_exact_match_is_perfect():
    """Exact match at both granularities should score 1.0 everywhere."""
    tech_res, sub_res = _score_ate_sample({"T1566.001"}, {"T1566.001"})

    assert sub_res[0] == 1.0, f"sub-technique precision should be 1.0, got {sub_res[0]}"
    assert sub_res[1] == 1.0, f"sub-technique recall should be 1.0, got {sub_res[1]}"
    assert sub_res[2] == 1.0, f"sub-technique F1 should be 1.0, got {sub_res[2]}"

    assert tech_res[0] == 1.0, f"technique precision should be 1.0, got {tech_res[0]}"
    assert tech_res[1] == 1.0, f"technique recall should be 1.0, got {tech_res[1]}"
    assert tech_res[2] == 1.0, f"technique F1 should be 1.0, got {tech_res[2]}"


def test_pure_false_positive_scores_zero():
    """Pure false positive should score 0.0 at both granularities."""
    tech_res, sub_res = _score_ate_sample({"T1486"}, {"T1566.001"})

    assert sub_res[0] == 0.0, f"sub-technique precision should be 0.0, got {sub_res[0]}"
    assert sub_res[1] == 0.0, f"sub-technique recall should be 0.0, got {sub_res[1]}"
    assert sub_res[2] == 0.0, f"sub-technique F1 should be 0.0, got {sub_res[2]}"

    assert tech_res[0] == 0.0, f"technique precision should be 0.0, got {tech_res[0]}"
    assert tech_res[1] == 0.0, f"technique recall should be 0.0, got {tech_res[1]}"
    assert tech_res[2] == 0.0, f"technique F1 should be 0.0, got {tech_res[2]}"


def test_empty_prediction_on_empty_gold_is_correct_rejection():
    """Empty prediction on empty gold is a correct rejection: 1.0 everywhere."""
    result = _score_one_granularity(set(), set())
    assert result[0] == 1.0, f"precision should be 1.0, got {result[0]}"
    assert result[1] == 1.0, f"recall should be 1.0, got {result[1]}"
    assert result[2] == 1.0, f"F1 should be 1.0, got {result[2]}"
    assert result[3] == 0, f"TP should be 0, got {result[3]}"
    assert result[4] == 0, f"FP should be 0, got {result[4]}"
    assert result[5] == 0, f"FN should be 0, got {result[5]}"


def test_prediction_on_empty_gold_costs_precision():
    """Prediction on empty gold must cost precision: 0.0 everywhere."""
    result = _score_one_granularity({"T1059"}, set())
    assert result[0] == 0.0, f"precision should be 0.0, got {result[0]}"
    assert result[2] == 0.0, f"F1 should be 0.0, got {result[2]}"
    assert result[4] == 1, f"FP should be 1, got {result[4]}"


def test_macro_average_is_not_micro_average(monkeypatch):
    """
    Macro-averaged F1 is the mean of per-sample F1 scores, not the
    micro-averaged F1 computed from corpus-level TP/FP/FN.
    """
    import tests.eval_pipeline as ep

    fake = {"A": {"T1059"}, "B": set()}
    monkeypatch.setitem(ep._ATE_STAGE_FNS, "fake",
                        lambda text: fake.get(text, set()))

    samples = [
        ATESample(text="A", expected_ids={"T1059"}, description="A"),
        ATESample(text="B",
                  expected_ids={f"T{1000+i}" for i in range(10)},
                  description="B"),
    ]
    score = run_ate_benchmark(samples, stage="fake")

    # Sample A: F1 = 1.0, Sample B: F1 = 0.0 -> macro F1 = 0.5
    assert abs(score.subtechnique.f1 - 0.5) < 1e-9, \
        f"macro-averaged F1 should be 0.5, got {score.subtechnique.f1}"


def test_label_count_diagnostic(monkeypatch):
    """
    mean_labels_predicted and mean_labels_gold should reflect per-sample
    label counts, not corpus totals.
    """
    import tests.eval_pipeline as ep

    fake = {"A": {"T1059"}, "B": set()}
    monkeypatch.setitem(ep._ATE_STAGE_FNS, "fake",
                        lambda text: fake.get(text, set()))

    samples = [
        ATESample(text="A", expected_ids={"T1059"}, description="A"),
        ATESample(text="B",
                  expected_ids={f"T{1000+i}" for i in range(10)},
                  description="B"),
    ]
    score = run_ate_benchmark(samples, stage="fake")

    # Sample A: 1 predicted, 1 gold. Sample B: 0 predicted, 10 gold.
    # Mean predicted = (1+0)/2 = 0.5, Mean gold = (1+10)/2 = 5.5
    assert abs(score.subtechnique.mean_labels_predicted - 0.5) < 1e-9, \
        f"mean_labels_predicted should be 0.5, got {score.subtechnique.mean_labels_predicted}"
    assert abs(score.subtechnique.mean_labels_gold - 5.5) < 1e-9, \
        f"mean_labels_gold should be 5.5, got {score.subtechnique.mean_labels_gold}"


def test_negative_samples_are_counted(monkeypatch):
    """
    Negative samples (empty gold) must be counted in the macro average.
    A perfect sample + a polluted negative sample -> precision = 0.5.
    """
    import tests.eval_pipeline as ep

    fake = {"good": {"T1059"}, "bad": {"T1486"}}
    monkeypatch.setitem(ep._ATE_STAGE_FNS, "fake",
                        lambda text: fake.get(text, set()))

    samples = [
        ATESample(text="good", expected_ids={"T1059"}, description="good"),
        ATESample(text="bad", expected_ids=set(), description="bad"),
    ]
    score = run_ate_benchmark(samples, stage="fake")

    # Sample "good": precision = 1.0, Sample "bad": precision = 0.0
    # Macro precision = (1.0 + 0.0) / 2 = 0.5
    assert abs(score.subtechnique.precision - 0.5) < 1e-9, \
        f"macro precision should be 0.5, got {score.subtechnique.precision}"
