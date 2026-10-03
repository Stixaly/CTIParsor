"""api/run_config.py — the manifest says why it could not pin something,
instead of a bare None (the audit's silent `except: pass`, B 8.1.9)."""
from __future__ import annotations

import subprocess

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
