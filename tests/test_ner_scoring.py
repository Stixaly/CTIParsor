"""
Regression tests for the NER scorer (tests/eval_pipeline.py).

These lock the defects the previous scorer had:
  1. A partial match ("Cobalt" for gold "Cobalt Strike") added 0.5 to TP and
     nothing to FP or FN, so the sample scored P = R = F1 = 1.0: half of the
     prediction left the accounting.
  2. Predictions were matched greedily in input order, so a partial match
     could take the gold entity an exact prediction needed.
  3. The per-type table matched each prediction against every gold entity of
     its type with max(), so two predictions could both count as true
     positives for one gold entity.

scripts/verify_ner_scorer.py re-implements the previous scorer and checks that
every case here scores differently under it.
"""
import random
import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.schemas import EntityType, RawEntity  # noqa: E402
from tests.eval_pipeline import NERSample, score_dataset, score_sample  # noqa: E402

M, IP = EntityType.MALWARE, EntityType.IPV4


def _p(*values, t=M) -> list[RawEntity]:
    return [RawEntity(value=v, entity_type=t) for v in values]


def test_a_partial_match_is_a_false_positive_and_a_false_negative():
    assert score_sample(_p("Cobalt"), [("Cobalt Strike", M)]) == (0.0, 1.0, 1.0)


def test_lenient_scoring_counts_a_partial_match_whole():
    assert score_sample(_p("Cobalt"), [("Cobalt Strike", M)], partial_credit=True) == (1.0, 0.0, 0.0)


def test_an_exact_match_is_never_lost_to_an_earlier_partial_one():
    # Old scorer: "Cobalt" took the gold first (0.5), "Cobalt Strike" became a FP.
    assert score_sample(_p("Cobalt", "Cobalt Strike"), [("Cobalt Strike", M)]) == (1.0, 1.0, 0.0)


def test_one_gold_entity_is_matched_once():
    assert score_sample(_p("WellMess", "wellmess"), [("WellMess", M)]) == (1.0, 1.0, 0.0)


def test_the_right_value_under_the_wrong_type_does_not_match():
    assert score_sample(_p("1.2.3.4", t=EntityType.DOMAIN), [("1.2.3.4", IP)]) == (0.0, 1.0, 1.0)


def test_every_prediction_and_every_gold_entity_is_counted_once():
    rng = random.Random(7)
    vocab = ["Cobalt", "Cobalt Strike", "Strike", "WellMess", "WellMail", "Mess"]
    for _ in range(300):
        pred = _p(*rng.sample(vocab, rng.randint(0, 5)))
        gold = [(v, M) for v in rng.sample(vocab, rng.randint(0, 5))]
        for lenient in (False, True):
            tp, fp, fn = score_sample(pred, gold, partial_credit=lenient)
            assert tp + fp == len(pred) and tp + fn == len(gold), (pred, gold, lenient)


def test_per_type_counts_add_up_to_the_overall_and_to_the_inputs():
    samples = [
        NERSample(text="a", expected=[("Cobalt Strike", M), ("1.2.3.4", IP)]),
        NERSample(text="b", expected=[("WellMess", M)]),
    ]
    predictions = {
        "a": _p("Cobalt", "Cobalt Strike") + _p("1.2.3.4", t=IP),
        "b": _p("WellMess", "WellMess"),
    }
    scores = score_dataset(samples, stage_fn=lambda text: predictions[text])

    malware, ipv4, overall = scores["malware"], scores["ipv4"], scores["overall"]
    assert (malware.tp, malware.fp, malware.fn) == (2.0, 2.0, 0.0)
    assert (ipv4.tp, ipv4.fp, ipv4.fn) == (1.0, 0.0, 0.0)
    assert (overall.tp, overall.fp, overall.fn) == (3.0, 2.0, 0.0)
    assert overall.tp + overall.fp == 5 and overall.tp + overall.fn == 3


def test_partial_pairs_are_reported_per_type():
    samples = [NERSample(text="a", expected=[("Cobalt Strike", M)])]
    scores = score_dataset(samples, stage_fn=lambda _t: _p("Cobalt"))
    assert scores["malware"].partial == 1 and scores["overall"].partial == 1
    assert scores["overall"].precision == 0.0
    lenient = score_dataset(samples, stage_fn=lambda _t: _p("Cobalt"), partial_credit=True)
    assert lenient["overall"].precision == 1.0 and lenient["overall"].partial == 1
