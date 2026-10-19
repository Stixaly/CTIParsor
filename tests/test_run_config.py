"""api/run_config.py — the manifest says why it could not pin something,
instead of a bare None (the audit's silent `except: pass`, B 8.1.9)."""
from __future__ import annotations

import fnmatch
import subprocess

import pytest

from api import run_config


def test_the_manifest_records_why_it_has_no_prompt_fingerprint(monkeypatch):
    import pipeline.stage3_llm as s3

    def broken() -> str:
        raise RuntimeError("prompt module half-loaded")
    monkeypatch.setattr(s3, "prompt_fingerprint", broken)
    llm = run_config.build_manifest()["llm"]
    assert llm["prompt_fingerprint"] is None
    assert llm["error"] == "RuntimeError: prompt module half-loaded"


def test_a_working_manifest_has_no_error_key():
    llm = run_config.build_manifest()["llm"]
    assert llm["prompt_fingerprint"] and "error" not in llm


def test_without_git_the_revision_comes_from_the_build_stamp(monkeypatch):
    def no_git(*a, **kw):
        raise FileNotFoundError("git")
    monkeypatch.setattr(subprocess, "run", no_git)
    monkeypatch.setenv("CTIPARSOR_GIT_REV", "abc1234")
    assert run_config._resolve_git_rev() == "abc1234"


def test_every_data_file_is_fingerprinted():
    """A file in pipeline/data/ is data a run loads: the manifest hashes it.
    Only the files present are checked, so a CI without the .npy still passes;
    hidden files and the leftovers of a local edit are not data."""
    leftovers = (".*", "*.tmp", "*.bak", "*~")
    present = sorted(p.name for p in run_config._DATA_DIR.iterdir()
                     if p.is_file() and not any(fnmatch.fnmatch(p.name, pattern) for pattern in leftovers))
    missing = [name for name in present if name not in run_config._DATA_FILES]
    assert not missing, f"pipeline/data files the manifest does not fingerprint: {missing}"


def test_the_manifest_fingerprints_the_data_files_it_lists():
    data = run_config.build_manifest()["data"]
    assert set(data) == set(run_config._DATA_FILES)
    for name, fingerprint in data.items():
        assert (fingerprint is None) == (not (run_config._DATA_DIR / name).is_file()), name


def test_the_packages_that_decide_the_output_are_listed():
    packages = run_config.build_manifest()["packages"]
    assert {"yara-python", "pysigma", "parsuricata", "lark-parser", "lark", "stix2-validator",
            "spacy", "rapidfuzz"} <= set(packages)


# Names and bounds that change what a run emits; none is a secret.
_OUTPUT_ENV = {
    "STIX_TLP": "clear", "STIX_AUTHOR_NAME": "Acme CTI",
    "GAZETTEER_POLICY": "enforce", "BENIGN_IOC_FILTER": "0", "GLINER_ENABLED": "0",
    "GLINER_CHUNK_CHARS": "1200", "CYNER_CHUNK_CHARS": "1300", "NER_PRECISION_FILTERS": "true",
    "LLM_MAX_PROMPT_LENGTH": "16000", "LLM_DOC_MAX_PROMPT_LENGTH": "150000",
    "LLM_MAX_RESPONSE_LENGTH": "24000", "LLM_MAX_OUTPUT_TOKENS": "4096", "LLM_TIMEOUT": "300",
    "STIX_VERIFY_MIN_RELS": "3", "STIX_VERIFY_BATCH_SIZE": "20", "TTP_VERIFY_MIN": "2",
    "VISION_PROVIDER": "vllm", "VISION_MODEL": "vision-model", "VISION_ASSUME_CAPABLE": "1",
    "VISION_TIMEOUT_S": "90",
    "ANTHROPIC_MODEL": "claude-model", "GEMINI_MODEL": "gemini-model", "MISTRAL_MODEL": "mistral-model",
    "OLLAMA_MODEL": "ollama-model", "LMSTUDIO_MODEL": "lmstudio-model", "VLLM_MODEL": "vllm-model",
}


@pytest.fixture()
def stages_imported():
    """Import the stage modules under the real environment first: several read
    these variables at import, and a partial run must never import them with
    the values a test sets."""
    run_config.build_run_config()


def test_the_settings_that_change_the_output_are_recorded_when_set(stages_imported, monkeypatch):
    for name, value in _OUTPUT_ENV.items():
        monkeypatch.setenv(name, value)
    env = run_config.build_run_config()["env"]
    assert {name: env.get(name) for name in _OUTPUT_ENV} == _OUTPUT_ENV


def test_they_are_left_out_when_not_set(stages_imported, monkeypatch):
    for name in _OUTPUT_ENV:
        monkeypatch.delenv(name, raising=False)
    env = run_config.build_run_config()["env"]
    assert not set(_OUTPUT_ENV) & set(env)


# ── The record of a build (ADR-0086) ─────────────────────────────────────────

def test_the_captured_environment_is_the_allow_list_only(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-value")
    monkeypatch.setenv("STIX_TLP", "amber")
    monkeypatch.delenv("STIX_AUTHOR_NAME", raising=False)
    env = run_config.captured_env()
    assert env["STIX_TLP"] == "amber" and "STIX_AUTHOR_NAME" not in env
    assert set(env) <= set(run_config._CAPTURED_ENV) and "sk-secret-value" not in env.values()
    assert run_config.build_run_config()["env"] == env


@pytest.mark.parametrize("kind", ["finalize", "quick"])
def test_a_build_record_names_what_built_the_bundle(monkeypatch, kind):
    monkeypatch.setattr(run_config, "_resolve_git_rev", lambda: "abc1234")
    monkeypatch.setenv("STIX_TLP", "amber")
    policy = {"global": "enforce", "rules": []}

    record = run_config.build_record(policy, kind=kind)

    assert set(record) == {"kind", "built_at", "git_rev", "policy", "env", "manifest"}
    assert (record["kind"], record["git_rev"], record["policy"]) == (kind, "abc1234", policy)
    assert record["built_at"].endswith("Z") and record["env"]["STIX_TLP"] == "amber"
    assert set(record["manifest"]) == {"llm", "models", "attack", "data", "packages"}
    assert "entity_overrides" not in record                      # Stages 4/5 never read them


def test_a_runs_build_record_is_copied_from_its_run_config(monkeypatch):
    monkeypatch.setattr(run_config, "_resolve_git_rev", lambda: "abc1234")
    config = run_config.build_run_config({"rules": []})

    record = run_config.run_build_record(config)

    assert record["kind"] == "run" and record["built_at"].endswith("Z")
    assert {k: record[k] for k in ("git_rev", "policy", "env", "manifest")} == {
        k: config[k] for k in ("git_rev", "policy", "env", "manifest")}

    nothing = run_config.run_build_record(None)                  # the run config could not be built
    assert nothing["kind"] == "run"
    assert [nothing[k] for k in ("git_rev", "policy", "env", "manifest")] == [None] * 4
