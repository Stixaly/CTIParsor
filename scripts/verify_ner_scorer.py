#!/usr/bin/env python3
"""
Mutation harness for the NER scorer — companion to tests/test_ner_scoring.py.

A regression test written after the fact can pass for the wrong reason.  This
script re-implements the PREVIOUS scorer verbatim and replays every case the
new tests assert on.  Each case must score DIFFERENTLY under the old scorer; a
case that agrees is a case the tests do not actually lock.

Usage:
  python scripts/verify_ner_scorer.py

Exit code 0 when every case diverges as expected, 1 otherwise.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.schemas import EntityType, RawEntity  # noqa: E402
from tests.eval_pipeline import _match_score, score_sample  # noqa: E402


# Verbatim copy of the previous score_sample.  Do not fix anything here:
# this function exists to reproduce the defect, not to run in production.
def _old_score_sample(predicted, expected, partial_credit=True):
    gold = list(expected)
    pred = list(predicted)

    tp: float = 0.0
    matched_gold: set[int] = set()

    for pe in pred:
        best_score = 0.0
        best_gold_idx = -1
        for gi, (gv, gt) in enumerate(gold):
            if gi in matched_gold:
                continue
            s = _match_score(pe.value, pe.entity_type, gv, gt)
            if s > best_score:
                best_score = s
                best_gold_idx = gi

        if best_gold_idx >= 0 and best_score > 0:
            if partial_credit:
                tp += best_score
            else:
                tp += 1.0 if best_score == 1.0 else 0.0
            matched_gold.add(best_gold_idx)

    fp = len(pred) - len(matched_gold)
    fn = len(gold) - len(matched_gold)

    return max(0.0, tp), max(0.0, float(fp)), max(0.0, float(fn))


# Verbatim copy of the previous per-type loop in score_dataset (one sample).
def _old_per_type(predicted, expected, partial_credit=True):
    scores: dict[str, list[float]] = {}
    for pe in predicted:
        scores.setdefault(pe.entity_type.value, [0.0, 0.0, 0.0])
    for _, et in expected:
        scores.setdefault(et.value, [0.0, 0.0, 0.0])
    for pe in predicted:
        key = pe.entity_type.value
        type_gold = [(v, t) for v, t in expected if t == pe.entity_type]
        best = max((_match_score(pe.value, pe.entity_type, gv, gt) for gv, gt in type_gold),
                   default=0.0)
        if best > 0:
            scores[key][0] += best if partial_credit else (1.0 if best == 1.0 else 0.0)
        else:
            scores[key][1] += 1.0
    for gv, gt in expected:
        key = gt.value
        type_pred = [pe for pe in predicted if pe.entity_type == gt]
        best = max((_match_score(pe.value, pe.entity_type, gv, gt) for pe in type_pred),
                   default=0.0)
        if best == 0:
            scores[key][2] += 1.0
    return {k: tuple(v) for k, v in scores.items()}


def _p(*values, t=EntityType.MALWARE):
    return [RawEntity(value=v, entity_type=t) for v in values]


M = EntityType.MALWARE

# (label, predicted, expected, partial_credit)
CASES = [
    ("partial match is FP + FN (strict)", _p("Cobalt"), [("Cobalt Strike", M)], False),
    ("partial match counted whole (lenient)", _p("Cobalt"), [("Cobalt Strike", M)], True),
    ("exact beats an earlier partial", _p("Cobalt", "Cobalt Strike"), [("Cobalt Strike", M)], False),
]


def main() -> int:
    failures = 0
    for label, pred, gold, lenient in CASES:
        new = score_sample(pred, gold, partial_credit=lenient)
        # The old default was partial_credit=True; the new default is strict.
        old = _old_score_sample(pred, gold, partial_credit=True)
        ok = new != old
        failures += not ok
        print(f"{'ok  ' if ok else 'SAME'}  {label:<40} new={new}  old={old}")

    # The per-type table: two predictions for one gold both scored TP.
    pred, gold = _p("WellMess", "wellmess"), [("WellMess", M)]
    old_type = _old_per_type(pred, gold)["malware"]
    new_type = score_sample(pred, gold)
    ok = old_type != new_type
    failures += not ok
    print(f"{'ok  ' if ok else 'SAME'}  {'per-type: one gold matched twice':<40} "
          f"new={new_type}  old={old_type}")

    print("\nevery case diverges" if not failures else f"\n{failures} case(s) do not diverge")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
