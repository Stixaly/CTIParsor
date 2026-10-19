"""
The decision rule of the NER measurement (ADR-0089) in
scripts/measure_ner_precision.py: `gates` and `decision`, and the checks that
decide which documents and which runs it may read (`read_record`,
`rerun_reason`, `left_out_docs`, `config_problems`, `run_problems`).

`gates` reads what `compare` writes (and, for M5, what `replay` writes) and
says whether each criterion holds.  The inputs are built by hand in the shape
`summarize()` returns, with only the numbers a gate reads.

Differences are rounded to 4 decimals before they are compared, as
`Counts.as_dict` rounds the values: 0.55 -> 0.60 is +5.0 points, not
0.0499999.
"""
from __future__ import annotations

import pytest

from scripts.measure_ner_precision import (
    config_problems,
    decision,
    gates,
    left_out_docs,
    read_record,
    rerun_reason,
    run_problems,
)


def _counts(precision: float, recall: float, f1: float) -> dict:
    return {"tp": 50, "fp": 50, "fn": 50, "precision": precision, "recall": recall, "f1": f1}


def _type(precision=(0.5, 0.5), recall=(0.5, 0.5), f1=(0.5, 0.5), lost=0, gained=0, interval_low=None) -> dict:
    """One type's row of `summarize()`: each metric is (base, variant)."""
    row = {
        "base": _counts(precision[0], recall[0], f1[0]),
        "variant": _counts(precision[1], recall[1], f1[1]),
        "lost_tp": [[f"doc{i}", f"lost{i}"] for i in range(lost)],
        "gained_tp": [[f"doc{i}", f"gained{i}"] for i in range(gained)],
        "removed": [], "added": [],
    }
    if interval_low is not None:
        row["bootstrap"] = {"precision": {"observed_diff": precision[1] - precision[0],
                                          "ci95": [interval_low, interval_low + 0.08]}}
    return row


# +10 points of precision, F1 up, nothing lost, an interval above zero.
_PASSING_MALWARE = {"precision": (0.5, 0.6), "f1": (0.5, 0.55), "interval_low": 0.02}


def _cmp(left_out: int = 0, problems=(), split: str = "test", **types: dict) -> dict:
    """A `compare` report of 34 test documents in which every gate passes,
    except for what is given."""
    rows = {"malware": _PASSING_MALWARE, **types}
    return {"a": "base", "b": "candidate", "split": split, "expected": 34, "documents": 34 - left_out,
            "left_out": {f"doc{i}": "base: not scored" for i in range(left_out)},
            "config_problems": list(problems),
            "types": {t: _type(**rows.get(t, {})) for t in ("threat_actor", "malware", "location", "tool", "identity")}}


def _train(malware: int = 0, threat_actor: int = 0, tp: int = 100, **header) -> dict:
    """The train `replay` report for the variant "malware" against adr0088:
    the gold entities lost per type, out of `tp` true positives."""
    def row(lost: int) -> dict:
        return {"base": {"tp": tp}, "lost_tp": [["doc", f"gold{i}"] for i in range(lost)]}
    return {"split": "train", "expect": "off", "base": "adr0088", **header,
            "variants": {"malware": {"malware": row(malware), "threat_actor": row(threat_actor)}}}


def _passed(rows, gate: str, etype: str | None = None):
    """The verdict of the one row of this gate (and type)."""
    found = [passed for g, t, passed, _ in rows if g == gate and etype in (None, t)]
    assert len(found) == 1, f"{gate} {etype}: {len(found)} rows"
    return found[0]


def test_every_gate_passes_on_a_clean_measurement():
    rows = gates(_cmp(), _train())
    assert [(g, t) for g, t, _, _ in rows] == [
        ("M0", "configuration"), ("M0", "documents"), ("M1", "malware"), ("M2", "malware"), ("M3", "malware"),
        ("M4a", "threat_actor"), ("M4b", "location"), ("M4b", "tool"), ("M4b", "identity"),
        ("M5", "malware (train)"), ("M5", "threat_actor (train)")]
    assert all(passed is True for _, _, passed, _ in rows)
    assert decision(rows) == "adopt"


@pytest.mark.parametrize("left_out, passed", [(2, True), (3, False)])
def test_m0_two_documents_may_be_left_out_but_not_three(left_out, passed):
    rows = gates(_cmp(left_out=left_out), _train())
    assert _passed(rows, "M0", "documents") is passed


@pytest.mark.parametrize("cmp", [_cmp(problems=["commit: 'a' against 'b'"]), _cmp(split="dev")])
def test_m0_the_runs_must_differ_by_the_switch_alone_on_test(cmp):
    assert _passed(gates(cmp, _train()), "M0", "configuration") is False


@pytest.mark.parametrize("variant, passed", [(0.55, True), (0.549, False)])
def test_m1_malware_precision_must_gain_five_points(variant, passed):
    rows = gates(_cmp(malware={"precision": (0.5, variant), "f1": (0.5, 0.55), "interval_low": 0.02}), _train())
    assert _passed(rows, "M1") is passed


def test_a_boundary_difference_is_not_lost_to_float_arithmetic():
    """0.60 - 0.55 is 0.04999999999999993 and 0.49 - 0.50 is -0.010000000000000009
    in floats: +5.0 and -1.0 points, which pass."""
    rows = gates(_cmp(malware={"precision": (0.55, 0.60), "f1": (0.5, 0.55), "interval_low": 0.02},
                      threat_actor={"precision": (0.50, 0.49)}, location={"recall": (0.50, 0.49)}), _train())
    assert _passed(rows, "M1") is True
    assert _passed(rows, "M4a") is True
    assert _passed(rows, "M4b", "location") is True


def test_m1_the_interval_must_stay_above_zero():
    rows = gates(_cmp(malware={**_PASSING_MALWARE, "interval_low": 0.0}), _train())
    assert _passed(rows, "M1") is False


def test_m1_fails_when_malware_did_not_move():
    """No bootstrap is computed when nothing moved."""
    rows = gates(_cmp(malware={}), _train())
    assert _passed(rows, "M1") is False


@pytest.mark.parametrize("lost, gained, passed", [(1, 0, True), (2, 1, True), (2, 0, False)])
def test_m2_malware_may_lose_one_gold_entity_net(lost, gained, passed):
    rows = gates(_cmp(malware={**_PASSING_MALWARE, "lost": lost, "gained": gained}), _train())
    assert _passed(rows, "M2") is passed


@pytest.mark.parametrize("variant, passed", [(0.5, True), (0.499, False)])
def test_m3_malware_f1_must_not_go_down(variant, passed):
    rows = gates(_cmp(malware={**_PASSING_MALWARE, "f1": (0.5, variant)}), _train())
    assert _passed(rows, "M3") is passed


@pytest.mark.parametrize("variant, passed", [(0.56, True), (0.559, False)])
def test_m4a_threat_actor_precision_may_drop_one_point(variant, passed):
    rows = gates(_cmp(threat_actor={"precision": (0.57, variant)}), _train())
    assert _passed(rows, "M4a") is passed


@pytest.mark.parametrize("lost, gained, passed", [(1, 0, True), (2, 1, True), (2, 0, False)])
def test_m4a_threat_actors_may_lose_one_gold_entity_net(lost, gained, passed):
    rows = gates(_cmp(threat_actor={"lost": lost, "gained": gained}), _train())
    assert _passed(rows, "M4a") is passed


@pytest.mark.parametrize("actor", [{"lost": 2}, {"f1": (0.5, 0.499)}])
def test_m4a_threat_actors_may_not_lose_two_gold_entities_or_f1(actor):
    rows = gates(_cmp(threat_actor=actor), _train())
    assert _passed(rows, "M4a") is False


@pytest.mark.parametrize("etype", ["location", "tool", "identity"])
@pytest.mark.parametrize("metric", ["precision", "recall"])
@pytest.mark.parametrize("variant, passed", [(0.56, True), (0.559, False)])
def test_m4b_the_other_types_may_drop_one_point(etype, metric, variant, passed):
    rows = gates(_cmp(**{etype: {metric: (0.57, variant)}}), _train())
    assert _passed(rows, "M4b", etype) is passed


@pytest.mark.parametrize("train", [None, _train(split="dev"), _train(base="off"), _train(expect="adr0088")])
def test_m5_without_the_train_replay_the_criteria_name_the_row_is_missing_not_failed(train):
    rows = gates(_cmp(), train)
    assert _passed(rows, "M5") is None
    assert all(passed is True for g, _, passed, _ in rows if g != "M5")
    assert decision(rows) == "incomplete"


@pytest.mark.parametrize("etype", ["malware", "threat_actor"])
@pytest.mark.parametrize("lost, passed", [(2, True), (3, False)])
def test_m5_the_train_split_may_lose_two_percent_of_its_true_positives(etype, lost, passed):
    rows = gates(_cmp(), _train(**{etype: lost}))
    assert _passed(rows, "M5", f"{etype} (train)") is passed


# ── decision ────────────────────────────────────────────────────────────────

def test_a_failed_criterion_is_not_adopted():
    assert decision(gates(_cmp(malware={**_PASSING_MALWARE, "lost": 2}), _train())) == "do not adopt"


def test_a_failed_criterion_is_not_adopted_even_with_m5_missing():
    assert decision(gates(_cmp(malware={**_PASSING_MALWARE, "lost": 2}), None)) == "do not adopt"


@pytest.mark.parametrize("cmp", [_cmp(left_out=3), _cmp(problems=["x"])])
def test_m0_failing_makes_the_measurement_void_whatever_the_other_rows_say(cmp):
    """Void, not "do not adopt": these runs decide nothing."""
    assert decision(gates(cmp, _train())) == "void"
    assert decision(gates({**cmp, "types": _cmp(malware={})["types"]}, _train())) == "void"


# ── which documents: run again or left out ──────────────────────────────────

def _record(**stage3) -> dict:
    return {"doc_id": "d", "stages": [{"stage": "2", "counts": {"entities": 3}},
                                      {"stage": "3", "counts": {"provider_failures": 0, **stage3}},
                                      {"stage": "3d", "counts": {"failed": 0, "unparsed": 0}}]}


def test_an_unreadable_record_is_an_error_record(tmp_path):
    """A run cut off while writing a record leaves half a JSON file."""
    path = tmp_path / "doc7.json"
    path.write_text('{"doc_id": "doc7", "enti', encoding="utf-8")
    rec = read_record(path)
    assert rec["doc_id"] == "doc7"
    assert rerun_reason(rec).startswith("error: unreadable record")


def test_an_error_record_is_run_again():
    assert rerun_reason({"doc_id": "d", "error": "StageRequired: no usable answer"}).startswith("error: ")


def test_a_request_that_got_no_answer_is_run_again():
    assert rerun_reason(_record(provider_failures=2)) == "Stage 3: 2 request(s) got no answer"


def _raw(cyner_calls: int = 1, spacy_calls: int = 3, chunks: int = 3) -> dict:
    return {**_record(), "raw": {"chunks": ["c"] * chunks, "spacy_calls": [[]] * spacy_calls,
                                 "cyner_calls": [[[]]] * cyner_calls}}


@pytest.mark.parametrize("rec, reason", [
    (_raw(cyner_calls=0), "Stage 2d: CyNER recorded no prediction call"),
    (_raw(spacy_calls=2), "Stage 2: spaCy read 2 of 3 chunks"),
])
def test_a_ner_pass_that_did_not_run_is_run_again(rec, reason):
    """Stage 2d logs a CyNER inference error and goes on with no names: the
    stage report still says it ran."""
    assert rerun_reason(rec) == reason


@pytest.mark.parametrize("rec", [
    _record(), _raw(), _record(extraction_invalid=2, extraction_empty=1),
    {**_record(), "stages": _record()["stages"][:2] + [{"stage": "3d", "counts": {"failed": 1, "unparsed": 1}}]},
])
def test_what_the_model_answered_is_kept(rec):
    """An answer that does not parse, or an empty one, is the model's answer:
    temperature 0 and a fixed seed give it again."""
    assert rerun_reason(rec) is None


# ── which runs: the switch, and nothing else ────────────────────────────────

def _meta(lead: bool, **kw) -> dict:
    env = {"NER_PRECISION_FILTERS": "true", "NER_PRECISION_MALWARE": str(lead).lower(),
           "VLLM_MODEL": "Inferact/Qwen3.8-27B-NVFP4", "LLM_TEMPERATURE": "0", "LLM_SEED": "13"}
    return {"commit": "c" * 40, "clean": True, "split": "test", "disable": None, "allow_degraded": False,
            "limit": None, "filters": True, "malware_lead": lead, "env": env, **kw}


def test_two_runs_that_differ_by_the_switch_alone_have_no_problem():
    assert config_problems(_meta(False), _meta(True), "base", "cand") == []


@pytest.mark.parametrize("base, cand", [
    (_meta(False), _meta(True, commit="d" * 40)),
    (_meta(False, clean=None), _meta(True)),
    (_meta(True), _meta(True)),                                   # the baseline ran with the lead on
    (_meta(False), _meta(False)),
    (_meta(False, filters=False), _meta(True)),
    (_meta(False), {**_meta(True), "env": {**_meta(True)["env"], "VLLM_MODEL": "Qwen3.8-27B-NVFP4"}}),
    (_meta(False), _meta(True, limit=3)),
])
def test_any_other_difference_between_the_runs_is_a_problem(base, cand):
    assert config_problems(base, cand, "base", "cand")


def test_a_run_without_its_meta_is_a_problem():
    assert config_problems(None, _meta(True), "base", "cand") == ["no ner-meta.json for base"]


# ── which documents are left out ────────────────────────────────────────────

def test_a_document_missing_from_both_runs_is_left_out():
    """The case a symmetric difference of the two runs' documents misses: a
    document neither run scored."""
    left = left_out_docs(["d1", "d2", "d3"], {"base": {"d1"}, "cand": {"d1"}}, {"base": {}, "cand": {}})
    assert left == {"d2": "base: not scored; cand: not scored", "d3": "base: not scored; cand: not scored"}


def test_a_document_is_left_out_with_each_run_s_reason():
    left = left_out_docs(["d1", "d2"], {"base": {"d1", "d2"}, "cand": {"d1"}},
                         {"base": {}, "cand": {"d2": "Stage 3: 1 request(s) got no answer"}})
    assert left == {"d2": "cand: Stage 3: 1 request(s) got no answer"}


def test_documents_scored_in_both_runs_are_not_left_out():
    assert left_out_docs(["d1"], {"base": {"d1"}, "cand": {"d1"}}, {"base": {}, "cand": {}}) == {}


# ── run.json: the options and the manifest ──────────────────────────────────

def _run(**kw) -> dict:
    return {"name": "x", "started": "2026-10-18T20:00:00", "split": "test", "disabled": ["1f", "4", "5"],
            "required": ["3"], "consensus": False, "document_relations": False, "ttp_mode": "select",
            "manifest": {"llm": {"model": "m", "prompt_fingerprint": "abc"}, "packages": {"spacy": "3.8"}}, **kw}


def test_two_run_records_that_differ_by_name_and_time_have_no_problem():
    assert run_problems(_run(), _run(name="y", started="2026-10-18T23:30:00")) == []


@pytest.mark.parametrize("other, problem", [
    (_run(ttp_mode="verify"), "run.json ttp_mode: 'select' against 'verify'"),
    (_run(disabled=["1f", "4", "5", "3d"]), "run.json disabled: ['1f', '4', '5'] against ['1f', '4', '5', '3d']"),
    (_run(manifest={**_run()["manifest"], "packages": {"spacy": "3.9"}}), "run.json manifest.packages differs"),
])
def test_a_run_record_that_drifted_is_a_problem(other, problem):
    assert run_problems(_run(), other) == [problem]
