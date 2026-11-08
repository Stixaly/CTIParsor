"""scripts/measure_default_provider.py (ADR-0094 item 11): the refusals, the
dry run, the spread, the summary and the cost estimate. No subprocess runs:
the runner is replaced, and no LLM is called."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from scripts import measure_default_provider as measure

GOOD_ENV = {"ANTHROPIC_API_KEY": "test-key-not-real", "LLM_TEMPERATURE": "0"}


@pytest.fixture
def eval_dir(tmp_path, monkeypatch):
    path = tmp_path / "eval"
    monkeypatch.setattr(measure, "EVAL", path)
    monkeypatch.setattr(measure, "git_head", lambda: "0" * 40)
    return path


def _problems(environ: dict, dotenv: dict | None = None) -> list[str]:
    return measure.check(environ, dotenv or {})[1]


# ── defaults kept equal to the code ──────────────────────────────────────────

def test_defaults_match_stage3_source():
    source = (measure.REPO / "pipeline" / "stage3_llm.py").read_text(encoding="utf-8")
    assert f'os.environ.get("LLM_PROVIDER", "{measure.DEFAULT_PROVIDER}")' in source
    model = re.search(r'_DEFAULT_ANTHROPIC_MODEL = "([^"]+)"', source).group(1)
    assert model == measure.DEFAULT_MODEL


# ── refusals ─────────────────────────────────────────────────────────────────

def test_good_configuration_is_accepted(eval_dir):
    settings, problems = measure.check(dict(GOOD_ENV), {})
    assert problems == []
    assert settings == {"provider": "anthropic", "temperature": "0",
                        "vision_provider": "auto", "model": measure.DEFAULT_MODEL}


def test_missing_api_key_is_refused(eval_dir):
    problems = _problems({"LLM_TEMPERATURE": "0"})
    assert any("ANTHROPIC_API_KEY" in p for p in problems)


def test_api_key_read_from_dotenv_is_enough(eval_dir):
    assert _problems({"LLM_TEMPERATURE": "0"}, {"ANTHROPIC_API_KEY": "k"}) == []


@pytest.mark.parametrize("environ, dotenv", [
    ({}, {"LLM_PROVIDER": "vllm"}),          # .env says another provider
    ({"LLM_PROVIDER": "gemini"}, {}),        # the environment says another one
    ({"LLM_PROVIDER": ""}, {}),              # empty is not the default
])
def test_other_provider_is_refused(eval_dir, environ, dotenv):
    problems = _problems({**GOOD_ENV, **environ}, dotenv)
    assert any("LLM_PROVIDER" in p for p in problems)


def test_unset_provider_means_the_default_and_is_accepted(eval_dir):
    assert _problems(dict(GOOD_ENV), {}) == []


def test_environment_overrides_dotenv(eval_dir):
    # python -m evaluation does not override a variable already set: the
    # environment's value is the one that counts.
    problems = _problems({**GOOD_ENV, "LLM_PROVIDER": "anthropic"}, {"LLM_PROVIDER": "vllm"})
    assert problems == []


@pytest.mark.parametrize("value", [None, "", "0.2", "1", "zero"])
def test_temperature_other_than_zero_is_refused(eval_dir, value):
    environ = {"ANTHROPIC_API_KEY": "k"}
    if value is not None:
        environ["LLM_TEMPERATURE"] = value
    problems = _problems(environ)
    assert any("LLM_TEMPERATURE" in p for p in problems)


@pytest.mark.parametrize("value", ["0", "0.0"])
def test_temperature_zero_is_accepted(eval_dir, value):
    assert _problems({"ANTHROPIC_API_KEY": "k", "LLM_TEMPERATURE": value}) == []


def test_vision_none_is_refused(eval_dir):
    problems = _problems({**GOOD_ENV, "VISION_PROVIDER": "none"})
    assert any("VISION_PROVIDER=none" in p for p in problems)


@pytest.mark.parametrize("value", ["lmstudio", "gemini", "ollama"])
def test_vision_on_another_provider_is_refused(eval_dir, value):
    problems = _problems({**GOOD_ENV, "VISION_PROVIDER": value})
    assert any("VISION_PROVIDER" in p for p in problems)


@pytest.mark.parametrize("value", ["", "auto", "anthropic"])
def test_vision_default_or_anthropic_is_accepted(eval_dir, value):
    assert _problems({**GOOD_ENV, "VISION_PROVIDER": value}) == []


def test_other_model_is_refused(eval_dir):
    problems = _problems({**GOOD_ENV, "ANTHROPIC_MODEL": "claude-haiku-4-5"})
    assert any("ANTHROPIC_MODEL" in p for p in problems)


def test_existing_run_name_is_refused(eval_dir):
    (eval_dir / "runs" / "default-provider-annoctr-2").mkdir(parents=True)
    problems = _problems(dict(GOOD_ENV))
    assert any("default-provider-annoctr-2" in p and "already exists" in p for p in problems)


def test_existing_inhouse_run_name_is_refused(eval_dir):
    (eval_dir / "inhouse-runs" / "default-provider-inhouse-1").mkdir(parents=True)
    assert any("default-provider-inhouse-1" in p for p in _problems(dict(GOOD_ENV)))


def test_refusal_exits_before_any_step(eval_dir, capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no step may start")
    monkeypatch.setattr(measure, "subprocess", SimpleNamespace(run=boom))
    code = measure.main([], environ={"LLM_TEMPERATURE": "0"}, dotenv={})
    assert code == 1
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_read_dotenv_handles_comments_export_quotes(tmp_path):
    env = tmp_path / ".env"
    env.write_text("# a comment\nexport LLM_PROVIDER=anthropic\n"
                   "ANTHROPIC_API_KEY=\"quoted-value\"\n"
                   "LLM_TEMPERATURE=0 # inline comment\n\n", encoding="utf-8")
    assert measure.read_dotenv(env) == {"LLM_PROVIDER": "anthropic",
                                        "ANTHROPIC_API_KEY": "quoted-value",
                                        "LLM_TEMPERATURE": "0"}
    assert measure.read_dotenv(tmp_path / "missing") == {}


# ── dry run ──────────────────────────────────────────────────────────────────

def test_dry_run_prints_the_expected_commands(eval_dir, capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a dry run runs nothing")
    monkeypatch.setattr(measure, "subprocess", SimpleNamespace(run=boom))
    assert measure.main(["--dry-run"], environ=dict(GOOD_ENV), dotenv={}) == 0
    out = capsys.readouterr().out
    assert "run --split test --name default-provider-annoctr-1" in out
    assert "run --split test --name default-provider-annoctr-2" in out
    assert "inhouse-run --name default-provider-inhouse-1" in out
    assert "inhouse-score --name default-provider-inhouse-2 --from bundle" in out
    assert "compare --a default-provider-annoctr-1 --b default-provider-annoctr-2 --task ttp" in out
    assert "inhouse-compare" in out
    assert not (eval_dir / "runs").exists()


def test_plan_runs_two_annoctr_and_two_inhouse_runs():
    labels = [label for label, _, _ in measure.plan("python")]
    assert sum(label.startswith("run ") for label in labels) == 2
    assert sum(label.startswith("inhouse-run ") for label in labels) == 2


# ── the measurement: a fake runner writes the files a real run would ─────────

def _fake_runner(eval_dir, calls, fail_on=None):
    micro = {
        "default-provider-annoctr-1": {"precision": 0.5, "recall": 0.4, "f1": 0.44},
        "default-provider-annoctr-2": {"precision": 0.52, "recall": 0.4, "f1": 0.45},
    }

    def runner(argv, cwd, env, check, capture_output, text):
        command = argv[3]
        calls.append(argv)
        assert env["LLM_PROVIDER"] == "anthropic" and env["LLM_TEMPERATURE"] == "0"
        if command == fail_on:
            return SimpleNamespace(returncode=3, stdout="")
        name = argv[argv.index("--name") + 1] if "--name" in argv else None
        if command == "score":
            target = eval_dir / "runs" / name / "score.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"documents_scored": 2, "documents_failed": [],
                                          "ttp": {"technique_micro": micro[name]},
                                          "seconds_per_document": 3.5, "llm": {"model": "m"}}))
        if command == "inhouse-score":
            target = eval_dir / "inhouse-runs" / name / "score-bundle.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            value = 0.6 if name.endswith("1") else 0.65
            target.write_text(json.dumps({"documents": 8, "micro": {
                "techniques": {"precision": 0.5, "recall": 0.5, "f1": value}}}))
        if command == "inhouse-compare":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"micro": {}}))
        return SimpleNamespace(returncode=0, stdout="")
    return runner


def test_measurement_writes_summary_with_spreads(eval_dir, monkeypatch):
    calls = []
    settings = measure.check(dict(GOOD_ENV), {})[0]
    code = measure.measure(measure.plan("python"), settings, dict(GOOD_ENV),
                           runner=_fake_runner(eval_dir, calls))
    assert code == 0
    assert len(calls) == len(measure.plan("python"))
    summaries = list(eval_dir.glob("default-provider-*.json"))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert summary["commit"] == "0" * 40
    assert summary["provider"] == "anthropic" and summary["llm_temperature"] == 0
    assert summary["billed"] is True
    f1 = summary["annoctr_test"]["spread_technique_micro"]["f1"]
    assert f1 == {"run_1": 0.44, "run_2": 0.45, "difference": 0.01}
    layer = summary["inhouse"]["spread_micro"]["techniques"]["f1"]
    assert layer["difference"] == pytest.approx(0.05)
    assert summary["inhouse"]["compare"] == {"micro": {}}


def test_failed_step_stops_and_writes_no_summary(eval_dir):
    calls = []
    settings = measure.check(dict(GOOD_ENV), {})[0]
    code = measure.measure(measure.plan("python"), settings, dict(GOOD_ENV),
                           runner=_fake_runner(eval_dir, calls, fail_on="score"))
    assert code == 3
    assert [c[3] for c in calls] == ["run", "score"]
    assert not list(eval_dir.glob("default-provider-*.json"))


def test_spread_of_two_equal_runs_is_zero():
    values = {"precision": 0.5, "recall": 0.25, "f1": 0.3333}
    assert all(v["difference"] == 0 for v in measure.spread(values, dict(values)).values())


def test_spread_with_a_missing_value_is_none():
    out = measure.spread({"f1": 0.4}, {"f1": None})
    assert out["f1"]["difference"] is None


# ── estimate ─────────────────────────────────────────────────────────────────

def _write_run(eval_dir, name, docs):
    for doc_id, record in docs.items():
        target = eval_dir / "runs" / name / "docs" / f"{doc_id}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(record), encoding="utf-8")


RECORD = {
    "doc_id": "d1",
    "stages": [
        {"stage": "1", "status": "ran", "reason": "", "seconds": 0.1, "counts": {"chars": 4000, "chunks": 2}},
        {"stage": "3", "status": "ran", "reason": "", "seconds": 9.0,
         "counts": {"llm_calls": 4, "provider_calls": 5}},
        {"stage": "3d", "status": "ran", "reason": "", "seconds": 1.0,
         "counts": {"ok": 1, "unparsed": 0, "failed": 0}},
        {"stage": "3f", "status": "ran", "reason": "", "seconds": 2.0,
         "counts": {"ok": 2, "unparsed": 0, "failed": 1, "truncated": 0}},
    ],
}


def test_estimate_counts_requests_and_estimates_tokens(eval_dir):
    _write_run(eval_dir, "default-provider-annoctr-1", {"d1": RECORD})
    result = measure.estimate("default-provider-annoctr-1", None)
    doc = result["runs"][0]["documents"][0]
    assert doc["chars"] == 4000
    assert doc["llm_calls"] == {"3": 5, "3d": 1, "3f": 3}
    assert doc["llm_requests"] == 9
    assert doc["input_tokens_estimated"] == 1000
    assert doc["output_tokens_estimated"] is None


def test_estimate_prices_are_arguments(eval_dir):
    _write_run(eval_dir, "default-provider-annoctr-1", {"d1": RECORD})
    runs = measure.estimate("default-provider-annoctr-1", 100)["runs"]
    total = measure.price_total(runs, 3.0, 15.0)
    assert total["input_tokens_estimated"] == 1000
    assert total["output_tokens_estimated"] == 900
    assert total["cost_usd"] == 0.0165
    no_out = measure.price_total(measure.estimate("default-provider-annoctr-1", None)["runs"], 3.0, None)
    assert no_out["cost_usd"] == 0.003 and no_out["output_tokens_estimated"] is None


def test_estimate_of_an_unknown_run_fails(eval_dir, capsys):
    assert measure.main(["--estimate", "nope"]) == 1
    assert "no run named" in capsys.readouterr().err


def test_estimate_through_main_prints_the_total(eval_dir, capsys):
    _write_run(eval_dir, "default-provider-inhouse-1", {"d1": RECORD})
    assert measure.main(["--estimate", "default-provider-inhouse-1", "--price-in", "3"]) == 0
    out = capsys.readouterr().out
    assert "input_tokens_estimated: 1000" in out
    assert "output tokens are not recorded" in out
