"""Five bugs found in triage, one regression test each (#802 to #806).

#802  export_plan: an LLM conflict on a role the analyst has set no longer
      withholds both native bounds.
#803  gazetteer _phrase: a typographic apostrophe is matched by one class, not
      rewritten a second time.
#804  strip_reasoning: a `</think>` inside a JSON value after a preamble is data.
#805  AnthropicVisionBackend: the client gets the configured timeout.
#806  capture_url_to_pdf without Playwright raises CaptureUnavailable (503), not
      CaptureError (502).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from pipeline import gazetteer_context as gc
from pipeline import vlm, web_capture
from pipeline.llm_parse import strip_reasoning
from pipeline.temporal import TemporalAssertion, analyst_assertion, export_plan
from pipeline.web_capture import CaptureError, CaptureUnavailable, capture_url_to_pdf

# ── #802 ─────────────────────────────────────────────────────────────────────

def test_802_an_llm_conflict_superseded_by_the_analyst_does_not_withhold_the_bounds():
    times = [
        TemporalAssertion(role="start", time_text="2024-01-01", status="conflict",
                          reason="not_found", origin="llm"),
        analyst_assertion("start", "2024-01-01T00:00:00Z"),
        analyst_assertion("end", "2024-01-02T00:00:00Z"),
    ]
    plan = export_plan(times, mode="faithful")
    assert plan.start_time == datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert plan.stop_time == datetime(2024, 1, 2, tzinfo=timezone.utc)
    assert sorted(d["outcome"] for d in plan.decisions) == ["exported", "exported", "withheld"]


def test_802_an_llm_conflict_on_an_unset_role_still_withholds_both_bounds():
    times = [
        TemporalAssertion(role="start", time_text="2024-01-01", status="conflict",
                          reason="not_found", origin="llm"),
        analyst_assertion("end", "2024-01-02T00:00:00Z"),
    ]
    plan = export_plan(times, mode="faithful")
    assert plan.start_time is None
    assert plan.stop_time is None
    assert {d["reason"] for d in plan.decisions} == {"status_conflict", "conflict"}


# ── #803 ─────────────────────────────────────────────────────────────────────

def test_803_phrase_matches_both_apostrophes_in_one_pass():
    pattern = gc._phrase("joker's stash")
    assert pattern.search("Joker's Stash")
    assert pattern.search("Joker’s Stash")
    assert "['[" not in pattern.pattern


# ── #804 ─────────────────────────────────────────────────────────────────────

def test_804_a_closing_tag_inside_a_json_value_after_a_preamble_is_kept():
    reply = 'Here is the JSON:\n{"quote": "foo </think> bar"}'
    assert json.loads(strip_reasoning(reply)[len("Here is the JSON:\n"):]) == {
        "quote": "foo </think> bar"}


def test_804_implicit_reasoning_before_a_closing_tag_is_still_dropped():
    assert strip_reasoning('Let me think about it. </think>\n{"a": 1}') == '{"a": 1}'


def test_804_a_draft_object_in_the_reasoning_does_not_keep_it_from_being_cut():
    reply = 'Let me think. Draft: {"a": 1} ok.\n</think>\n{"threat_actors": ["APT29"]}'
    assert strip_reasoning(reply) == '{"threat_actors": ["APT29"]}'


def test_804_a_draft_array_in_the_reasoning_does_not_keep_it_from_being_cut():
    assert strip_reasoning('about [1,2].\n</think>\n{"x": 1}') == '{"x": 1}'


# ── #805 ─────────────────────────────────────────────────────────────────────

def test_805_the_anthropic_client_gets_the_configured_timeout(monkeypatch):
    seen: dict = {}

    class _FakeAnthropic:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    class _FakeModule:
        Anthropic = _FakeAnthropic

    monkeypatch.setattr(vlm, "anthropic", _FakeModule)
    backend = vlm.AnthropicVisionBackend("claude-haiku-4-5", timeout=5.0)
    backend._get_client()
    assert seen["timeout"] == 5.0


# ── #806 ─────────────────────────────────────────────────────────────────────

def test_806_missing_playwright_is_unavailable_not_a_bad_page(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(web_capture, "_PLAYWRIGHT_AVAILABLE", False)
    with pytest.raises(CaptureUnavailable):
        capture_url_to_pdf("https://example.com/", tmp_path / "out.pdf")


def test_806_capture_unavailable_is_still_a_capture_error():
    assert issubclass(CaptureUnavailable, CaptureError)
