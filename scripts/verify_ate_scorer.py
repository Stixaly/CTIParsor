#!/usr/bin/env python3
"""
Mutation harness for the ATE scorer — ADR-0023 Phase 1, step 8bis.

A regression test written after the fact can pass for the wrong reason.  This
script re-implements the PRE-ADR-0023 scorer verbatim and replays every
scoring case the new tests assert on.  Each case must produce a DIFFERENT
result under the old scorer; a case that agrees is a case the tests do not
actually lock.

Usage:
  python scripts/verify_ate_scorer.py

Exit code 0 when every case diverges as expected, 1 otherwise.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from tests.eval_pipeline import _score_ate_sample


# Verbatim copy of the pre-ADR-0023 scorer.  Do not fix anything here:
# this function exists to reproduce the defect, not to run in production.
def _old_score_ate_sample(
    predicted_ids: set[str],
    expected_ids:  set[str],
    parent_credit: float = 0.5,
) -> tuple[float, float, float]:
    """
    Score one ATE sample.  Returns (tp, fp, fn).

    parent_credit:
      If 0.5 — predicting the parent T-ID (e.g. T1059) when the ground truth is
      a sub-technique (T1059.001) gives partial credit (0.5).  This is fair
      because Stage 2c may match at technique level while the report means a
      specific sub-technique.
      If 0.0 — strict exact match only (no partial credit for parents).
    """
    pred = {t.strip().upper() for t in predicted_ids}
    gold = {t.strip().upper() for t in expected_ids}

    tp: float = 0.0
    matched_gold: set[str] = set()

    for pt in pred:
        if pt in gold:
            tp += 1.0
            matched_gold.add(pt)
        elif parent_credit > 0:
            # Check if predicted is the parent of any gold sub-technique
            for gt in gold:
                if gt in matched_gold:
                    continue
                if "." in gt and gt.rsplit(".", 1)[0] == pt:
                    tp += parent_credit
                    matched_gold.add(gt)
                    break
                # Or if gold is the parent of a predicted sub-technique
                if "." in pt and pt.rsplit(".", 1)[0] == gt:
                    tp += parent_credit
                    matched_gold.add(gt)
                    break

    fp = len(pred)  - sum(
        1 for p in pred if p in gold or any(
            ("." in g and g.rsplit(".", 1)[0] == p) or
            ("." in p and p.rsplit(".", 1)[0] == g)
            for g in gold
        )
    )
    fn = len(gold - matched_gold)

    return max(0.0, tp), max(0.0, float(fp)), max(0.0, float(fn))


CASES: list[tuple[str, set[str], set[str]]] = [
    ("parent predicted, sub is gold",        {"T1059"},                    {"T1059.001"}),
    ("sub predicted, parent is gold",        {"T1059.001"},                {"T1059"}),
    ("two subs predicted, one parent gold",  {"T1059.001", "T1059.002"},   {"T1059"}),
    ("exact match",                          {"T1566.001"},                {"T1566.001"}),
    ("pure false positive",                  {"T1486"},                    {"T1566.001"}),
    ("empty prediction, gold present",       set(),                        {"T1059"}),
    ("prediction on empty gold",             {"T1059"},                    set()),
]

# Cases where the old and new scorers legitimately agree.  The pre-ADR-0023
# defect lived only in the parent/sub-technique partial-credit path, so exact
# matches, pure false positives and the empty-set cases must NOT diverge —
# asserting that is how we check the rewrite did not move behaviour it should
# have left alone.
CONTROL_CASES = {
    "exact match",
    "pure false positive",
    "empty prediction, gold present",
    "prediction on empty gold",
}


def main() -> None:
    all_ok = True
    n_cases = len(CASES)
    n_ok = 0

    print(f"{'case':<40} {'old P':>7} {'old R':>7}  |  {'new P':>7} {'new R':>7}  | verdict")
    print("-" * 100)

    for case_name, pred, gold in CASES:
        # Old scorer
        old_tp, old_fp, old_fn = _old_score_ate_sample(pred, gold)
        old_prec = old_tp / (old_tp + old_fp) if (old_tp + old_fp) > 0 else 0.0
        old_rec = old_tp / (old_tp + old_fn) if (old_tp + old_fn) > 0 else 0.0

        # New scorer (sub-technique granularity)
        tech_res, sub_res = _score_ate_sample(pred, gold)
        new_prec = sub_res[0]
        new_rec = sub_res[1]

        # Determine if the case diverges
        diverges = (abs(old_prec - new_prec) > 1e-9) or (abs(old_rec - new_rec) > 1e-9)

        # Control cases should NOT diverge; non-control cases SHOULD diverge
        if case_name in CONTROL_CASES:
            ok = not diverges
        else:
            ok = diverges

        verdict = "DIVERGES" if diverges else "same (not locked)"
        if not ok:
            verdict += " [UNEXPECTED]"
            all_ok = False
        else:
            n_ok += 1

        print(f"{case_name:<40} {old_prec:>7.3f} {old_rec:>7.3f}  |  "
              f"{new_prec:>7.3f} {new_rec:>7.3f}  | {verdict}")

    print("-" * 100)
    print(f"{n_ok}/{n_cases} per-sample cases behaved as expected")

    if not _check_aggregation():
        all_ok = False

    sys.exit(0 if all_ok else 1)


def _check_aggregation() -> bool:
    """
    Per-sample scoring cannot expose the second defect: the old harness summed
    TP/FP/FN across the whole corpus, so one long technique-dense sample could
    dominate.  Replay a two-sample corpus through the real run_ate_benchmark and
    compare its macro average against the old micro formula.
    """
    import tests.eval_pipeline as ep

    fake = {"perfect": {"T1059"}, "missed": set()}
    ep._ATE_STAGE_FNS["__verify_fake"] = lambda text: fake.get(text, set())
    samples = [
        ep.ATESample(text="perfect", expected_ids={"T1059"}, description="perfect"),
        ep.ATESample(text="missed",
                     expected_ids={f"T{1000 + i}" for i in range(10)},
                     description="missed"),
    ]
    try:
        macro_f1 = ep.run_ate_benchmark(samples, stage="__verify_fake").subtechnique.f1
    finally:
        ep._ATE_STAGE_FNS.pop("__verify_fake", None)

    tp = fp = fn = 0.0
    for sample in samples:
        s_tp, s_fp, s_fn = _old_score_ate_sample(fake[sample.text], sample.expected_ids)
        tp, fp, fn = tp + s_tp, fp + s_fp, fn + s_fn
    micro_p = tp / (tp + fp) if (tp + fp) else 0.0
    micro_r = tp / (tp + fn) if (tp + fn) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0

    diverges = abs(micro_f1 - macro_f1) > 1e-9
    print()
    print("aggregation: 2-sample corpus (one perfect, one with 10 missed labels)")
    print(f"  old micro-averaged F1 : {micro_f1:.4f}")
    print(f"  new macro-averaged F1 : {macro_f1:.4f}")
    print(f"  verdict               : {'DIVERGES' if diverges else 'same (not locked) [UNEXPECTED]'}")
    return diverges


if __name__ == "__main__":
    main()
