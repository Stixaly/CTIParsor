"""Issue #399 — when cross-model consensus is switched off.

`CONSENSUS_PROVIDER=none` names no second provider, the same as an empty
value: consensus stays off whatever ENABLE_CONSENSUS says, as it does for
`ENABLE_CONSENSUS=false`.
"""
import pytest

from pipeline.stage3e_consensus import consensus_enabled


@pytest.mark.parametrize("second, expected", [
    ("none", False),   # issue_399
    ("NONE", False),   # issue_399: case-insensitive, like the other providers
    ("", False),       # control: unset
    ("mistral", True), # control: a second provider that differs from LLM_PROVIDER
])
def test_no_second_provider_means_no_consensus(monkeypatch, second, expected):  # issue_399
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", second)
    assert consensus_enabled() is expected


def test_enable_consensus_false_still_disables_it(monkeypatch):  # issue_399, control
    monkeypatch.setenv("ENABLE_CONSENSUS", "false")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "mistral")
    assert consensus_enabled() is False
