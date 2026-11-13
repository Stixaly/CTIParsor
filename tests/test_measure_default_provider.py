"""scripts/measure_default_provider.py (ADR-0094 item 11, amended by ADR-0100):
the refusals, the dry run, the spread, the summary and the cost estimate. The
measurement is of the qualified configuration (vLLM serving
Inferact/Qwen3.8-27B-NVFP4) by default; `--provider anthropic` keeps the
billed option. No subprocess runs: the runner is replaced, and no LLM is called."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from scripts import measure_default_provider as measure

ANTHROPIC_ENV = {"ANTHROPIC_API_KEY": "test-key-not-real", "LLM_TEMPERATURE": "0"}
# A documentation address (TEST-NET-1), not the maintainer's server.
QUALIFIED_ENV = {
    "LLM_PROVIDER": "vllm",
    "VLLM_BASE_URL": "http://192.0.2.10:8000",
    "VLLM_MODEL": "Inferact/Qwen3.8-27B-NVFP4",
    "VLLM_ENABLE_THINKING": "false",
    "LLM_TIMEOUT": "600",
    "LLM_TEMPERATURE": "0",
    "LLM_SEED": "13",
    "VISION_PROVIDER": "vllm",
}


@pytest.fixture
def eval_dir(tmp_path, monkeypatch):
    path = tmp_path / "eval"
    monkeypatch.setattr(measure, "EVAL", path)
    monkeypatch.setattr(measure, "git_head", lambda: "0" * 40)
    return path


def _problems(environ: dict, dotenv: dict | None = None, provider: str = "vllm") -> list[str]:
    return measure.check(environ, dotenv or {}, provider)[1]


# ── the qualified configuration (ADR-0100) ───────────────────────────────────

def test_qualified_vllm_configuration_is_accepted_by_dry_run(eval_dir, capsys, monkeypatch):
    """Reproducer for the refusal of any provider but anthropic: on the
    unchanged script this exits 1 with 'LLM_PROVIDER is 'vllm''."""
    def boom(*a, **k):
        raise AssertionError("a dry run runs nothing")
    monkeypatch.setattr(measure, "subprocess", SimpleNamespace(run=boom))
    assert measure.main(["--dry-run"], environ=dict(QUALIFIED_ENV), dotenv={}) == 0
    assert "qualified-vllm-annoctr-1" in capsys.readouterr().out


def test_qualified_configuration_is_the_default_provider(eval_dir):
    settings, problems = measure.check(dict(QUALIFIED_ENV), {})
    assert problems == []
    assert settings == {"provider": "vllm", "temperature": "0", "seed": "13",
                        "timeout": "600", "vision_provider": "vllm",
                        "model": "Inferact/Qwen3.8-27B-NVFP4"}


def test_vllm_needs_no_api_key(eval_dir):
    assert "ANTHROPIC_API_KEY" not in " ".join(_problems(dict(QUALIFIED_ENV)))


def test_base_url_read_from_dotenv_is_enough(eval_dir):
    env = {k: v for k, v in QUALIFIED_ENV.items() if k != "VLLM_BASE_URL"}
    assert _problems(env, {"VLLM_BASE_URL": "http://192.0.2.10:8000"}) == []


def test_missing_base_url_is_refused(eval_dir):
    env = {k: v for k, v in QUALIFIED_ENV.items() if k != "VLLM_BASE_URL"}
    assert any("VLLM_BASE_URL" in p for p in _problems(env))


@pytest.mark.parametrize("key, value", [
    ("VLLM_MODEL", "vllm-model"),
    ("VLLM_MODEL", "Qwen3.8-27B-NVFP4"),
    ("VLLM_ENABLE_THINKING", "true"),
    ("LLM_TIMEOUT", "120"),
    ("LLM_SEED", "7"),
    ("LLM_TEMPERATURE", "0.7"),
])
def test_other_vllm_setting_is_refused(eval_dir, key, value):
    problems = _problems({**QUALIFIED_ENV, key: value})
    assert any(key in p for p in problems), problems


@pytest.mark.parametrize("key", ["VLLM_ENABLE_THINKING", "LLM_TIMEOUT", "LLM_SEED"])
def test_unset_qualified_setting_is_refused(eval_dir, key):
    env = {k: v for k, v in QUALIFIED_ENV.items() if k != key}
    assert any(key in p for p in _problems(env)), key


def test_anthropic_provider_is_refused_while_measuring_vllm(eval_dir):
    problems = _problems({**QUALIFIED_ENV, "LLM_PROVIDER": "anthropic"})
    assert any("LLM_PROVIDER" in p for p in problems)


def test_unset_provider_is_refused_while_measuring_vllm(eval_dir):
    env = {k: v for k, v in QUALIFIED_ENV.items() if k != "LLM_PROVIDER"}
    assert any("LLM_PROVIDER" in p for p in _problems(env))


@pytest.mark.parametrize("value", ["", "auto", "vllm"])
def test_vision_vllm_or_default_is_accepted(eval_dir, value):
    assert _problems({**QUALIFIED_ENV, "VISION_PROVIDER": value}) == []


@pytest.mark.parametrize("value", ["none", "anthropic", "gemini"])
def test_vision_elsewhere_is_refused_for_vllm(eval_dir, value):
    assert any("VISION_PROVIDER" in p for p in _problems({**QUALIFIED_ENV, "VISION_PROVIDER": value}))


def test_vllm_run_names_are_not_the_anthropic_ones(eval_dir):
    assert measure.run_names("vllm")["annoctr"][0] != measure.run_names("anthropic")["annoctr"][0]


def test_child_environment_sets_the_qualified_values(eval_dir):
    settings = measure.check(dict(QUALIFIED_ENV), {})[0]
    env = measure.child_environment(settings, {"PATH": "/bin"})
    assert env["LLM_PROVIDER"] == "vllm"
    assert env["VISION_PROVIDER"] == "vllm"
    assert env["VLLM_ENABLE_THINKING"] == "false"
    assert env["LLM_TIMEOUT"] == "600" and env["LLM_SEED"] == "13"
    assert env["LLM_TEMPERATURE"] == "0"
    assert env["VLLM_MODEL"] == "Inferact/Qwen3.8-27B-NVFP4"


# ── defaults kept equal to the code ──────────────────────────────────────────

def test_defaults_match_stage3_source():
    source = (measure.REPO / "pipeline" / "stage3_llm.py").read_text(encoding="utf-8")
    assert f'os.environ.get("LLM_PROVIDER", "{measure.DEFAULT_PROVIDER}")' in source
    model = re.search(r'_DEFAULT_ANTHROPIC_MODEL = "([^"]+)"', source).group(1)
    assert model == measure.DEFAULT_MODEL


# ── the anthropic option (ADR-0094 item 11, not qualified) ───────────────────

def test_anthropic_configuration_is_accepted(eval_dir):
    settings, problems = measure.check(dict(ANTHROPIC_ENV), {}, "anthropic")
    assert problems == []
    assert settings == {"provider": "anthropic", "temperature": "0",
                        "vision_provider": "auto", "model": measure.DEFAULT_MODEL}


def test_missing_api_key_is_refused(eval_dir):
    problems = _problems({"LLM_TEMPERATURE": "0"}, provider="anthropic")
    assert any("ANTHROPIC_API_KEY" in p for p in problems)


def test_api_key_read_from_dotenv_is_enough(eval_dir):
    assert _problems({"LLM_TEMPERATURE": "0"}, {"ANTHROPIC_API_KEY": "k"}, "anthropic") == []


@pytest.mark.parametrize("environ, dotenv", [
    ({}, {"LLM_PROVIDER": "vllm"}),          # .env says another provider
    ({"LLM_PROVIDER": "gemini"}, {}),        # the environment says another one
    ({"LLM_PROVIDER": ""}, {}),              # empty is not the default
])
def test_other_provider_is_refused_for_anthropic(eval_dir, environ, dotenv):
    problems = _problems({**ANTHROPIC_ENV, **environ}, dotenv, "anthropic")
    assert any("LLM_PROVIDER" in p for p in problems)


def test_unset_provider_means_the_default_and_is_accepted(eval_dir):
    assert _problems(dict(ANTHROPIC_ENV), {}, "anthropic") == []


def test_environment_overrides_dotenv(eval_dir):
    # python -m evaluation does not override a variable already set: the
    # environment's value is the one that counts.
    problems = _problems({**ANTHROPIC_ENV, "LLM_PROVIDER": "anthropic"},
                         {"LLM_PROVIDER": "vllm"}, "anthropic")
    assert problems == []


@pytest.mark.parametrize("value", [None, "", "0.2", "1", "zero"])
def test_temperature_other_than_zero_is_refused(eval_dir, value):
    environ = {"ANTHROPIC_API_KEY": "k"}
    if value is not None:
        environ["LLM_TEMPERATURE"] = value
    problems = _problems(environ, provider="anthropic")
    assert any("LLM_TEMPERATURE" in p for p in problems)


@pytest.mark.parametrize("value", ["0", "0.0"])
def test_temperature_zero_is_accepted(eval_dir, value):
    assert _problems({"ANTHROPIC_API_KEY": "k", "LLM_TEMPERATURE": value}, provider="anthropic") == []


def test_vision_none_is_refused(eval_dir):
    problems = _problems({**ANTHROPIC_ENV, "VISION_PROVIDER": "none"}, provider="anthropic")
    assert any("VISION_PROVIDER=none" in p for p in problems)


@pytest.mark.parametrize("value", ["lmstudio", "gemini", "ollama"])
def test_vision_on_another_provider_is_refused(eval_dir, value):
    problems = _problems({**ANTHROPIC_ENV, "VISION_PROVIDER": value}, provider="anthropic")
    assert any("VISION_PROVIDER" in p for p in problems)


@pytest.mark.parametrize("value", ["", "auto", "anthropic"])
def test_vision_default_or_anthropic_is_accepted(eval_dir, value):
    assert _problems({**ANTHROPIC_ENV, "VISION_PROVIDER": value}, provider="anthropic") == []


def test_other_model_is_refused(eval_dir):
    problems = _problems({**ANTHROPIC_ENV, "ANTHROPIC_MODEL": "claude-haiku-4-5"}, provider="anthropic")
    assert any("ANTHROPIC_MODEL" in p for p in problems)


def test_existing_run_name_is_refused(eval_dir):
    (eval_dir / "runs" / "qualified-vllm-annoctr-2").mkdir(parents=True)
    problems = _problems(dict(QUALIFIED_ENV))
    assert any("qualified-vllm-annoctr-2" in p and "already exists" in p for p in problems)


def test_existing_anthropic_run_name_is_refused(eval_dir):
    (eval_dir / "inhouse-runs" / "default-provider-inhouse-1").mkdir(parents=True)
    assert any("default-provider-inhouse-1" in p for p in _problems(dict(ANTHROPIC_ENV), provider="anthropic"))


def test_refusal_exits_before_any_step(eval_dir, capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no step may start")
    monkeypatch.setattr(measure, "subprocess", SimpleNamespace(run=boom))
    code = measure.main(["--provider", "anthropic"], environ={"LLM_TEMPERATURE": "0"}, dotenv={})
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
    assert measure.main(["--dry-run"], environ=dict(QUALIFIED_ENV), dotenv={}) == 0
    out = capsys.readouterr().out
    assert "run --split test --name qualified-vllm-annoctr-1" in out
    assert "run --split test --name qualified-vllm-annoctr-2" in out
    assert "inhouse-run --name qualified-vllm-inhouse-1" in out
    assert "inhouse-score --name qualified-vllm-inhouse-2 --from bundle" in out
    assert "compare --a qualified-vllm-annoctr-1 --b qualified-vllm-annoctr-2 --task ttp" in out
    assert "inhouse-compare" in out
    assert not (eval_dir / "runs").exists()


def test_anthropic_dry_run_uses_its_own_names(eval_dir, capsys, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("a dry run runs nothing")
    monkeypatch.setattr(measure, "subprocess", SimpleNamespace(run=boom))
    assert measure.main(["--dry-run", "--provider", "anthropic"], environ=dict(ANTHROPIC_ENV), dotenv={}) == 0
    out = capsys.readouterr().out
    assert "run --split test --name default-provider-annoctr-1" in out
    assert "inhouse-run --name default-provider-inhouse-2" in out


@pytest.mark.parametrize("provider", ["vllm", "anthropic"])
def test_plan_runs_two_annoctr_and_two_inhouse_runs(provider):
    labels = [label for label, _, _ in measure.plan("python", provider)]
    assert sum(label.startswith("run ") for label in labels) == 2
    assert sum(label.startswith("inhouse-run ") for label in labels) == 2


# ── the measurement: a fake runner writes the files a real run would ─────────

def _fake_runner(eval_dir, calls, provider, fail_on=None):
    annoctr_1, annoctr_2 = measure.run_names(provider)["annoctr"]
    micro = {
        annoctr_1: {"precision": 0.5, "recall": 0.4, "f1": 0.44},
        annoctr_2: {"precision": 0.52, "recall": 0.4, "f1": 0.45},
    }

    def runner(argv, cwd, env, check, capture_output, text):
        command = argv[3]
        calls.append(argv)
        assert env["LLM_PROVIDER"] == provider and env["LLM_TEMPERATURE"] == "0"
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


@pytest.mark.parametrize("provider", ["vllm", "anthropic"])
def test_measurement_writes_summary_with_spreads(eval_dir, provider):
    calls = []
    environ = dict(QUALIFIED_ENV if provider == "vllm" else ANTHROPIC_ENV)
    settings = measure.check(environ, {}, provider)[0]
    code = measure.measure(measure.plan("python", provider), settings, environ,
                           runner=_fake_runner(eval_dir, calls, provider))
    assert code == 0
    assert len(calls) == len(measure.plan("python", provider))
    summaries = list(eval_dir.glob("default-provider-*.json"))
    assert len(summaries) == 1
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert summary["commit"] == "0" * 40
    assert summary["provider"] == provider and summary["llm_temperature"] == 0
    assert summary["billed"] is (provider == "anthropic")
    f1 = summary["annoctr_test"]["spread_technique_micro"]["f1"]
    assert f1 == {"run_1": 0.44, "run_2": 0.45, "difference": 0.01}
    layer = summary["inhouse"]["spread_micro"]["techniques"]["f1"]
    assert layer["difference"] == pytest.approx(0.05)
    assert summary["inhouse"]["compare"] == {"micro": {}}


def test_failed_step_stops_and_writes_no_summary(eval_dir):
    calls = []
    environ = dict(QUALIFIED_ENV)
    settings = measure.check(environ, {})[0]
    code = measure.measure(measure.plan("python", "vllm"), settings, environ,
                           runner=_fake_runner(eval_dir, calls, "vllm", fail_on="score"))
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
    assert measure.main(["--estimate", "default-provider-inhouse-1", "--provider", "anthropic",
                         "--price-in", "3"]) == 0
    out = capsys.readouterr().out
    assert "input_tokens_estimated: 1000" in out
    assert "cost_usd: 0.003" in out
    assert "output tokens are not recorded" in out


def test_estimate_of_a_vllm_run_states_that_no_cost_is_billed(eval_dir, capsys):
    _write_run(eval_dir, "qualified-vllm-inhouse-1", {"d1": RECORD})
    assert measure.main(["--estimate", "qualified-vllm-inhouse-1", "--price-in", "3"]) == 0
    out = capsys.readouterr().out
    assert "input_tokens_estimated: 1000" in out
    assert "cost_usd: None" in out
    assert "not billed" in out
