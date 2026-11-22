"""Issue #998 — three LLM paths that were counted as something else, or given no reason.

* Stage 4c: an unreadable answer is counted (`long_distance_unparsed`), not read
  as "no link"; the stage is degraded when every answer was unreadable.
* Stage 3: a provider with no client is a failed request, not an empty answer.
* Stage 3e: consensus that was asked for and refused gives its reason in the
  stage report.

No request leaves the process: `llm_fn` and the clients are fakes.
"""
from __future__ import annotations

import stix2

from pipeline import llm_stats, stage4b_graph_completion
from pipeline import stage3_llm as s3
from pipeline.orchestrator import DEGRADED, RAN, SKIPPED, Document, Hooks, RunOptions, run_document
from pipeline.stage3e_consensus import consensus_disabled_reason, consensus_enabled
from pipeline.stage4c_long_distance import build_long_distance_inferer

_TEXT = ("APT29 deployed SUNBURST against SolarWinds customers and contacted 185.220.101.45 "
         "over HTTPS. The actor used spearphishing (T1566.001) for initial access.")

_UNSET = "ENABLE_CONSENSUS=true but CONSENSUS_PROVIDER is unset — disabled."
_SAME = ("CONSENSUS_PROVIDER == LLM_PROVIDER (anthropic) — consensus needs two "
         "different models; disabled.")

_NO_LINK = '{"related": false, "source": null, "verb": null, "quote": null}'


def _counted(before: dict) -> dict:
    return llm_stats.delta(before, llm_stats.snapshot())


def _two_entities():
    return stix2.IntrusionSet(name="APT-X"), stix2.Malware(name="MW", is_family=True)


# ── Stage 4c: the answers read by the inferer ────────────────────────────────

def test_an_unreadable_4c_answer_is_counted_and_read_as_no_link():
    actor, mw = _two_entities()
    infer = build_long_distance_inferer(lambda s, u: "not json")
    before = llm_stats.snapshot()

    assert infer(actor, mw, "APT-X deployed MW.") is None
    assert _counted(before) == {"long_distance_unparsed": 1}


def test_a_readable_no_link_answer_is_answered_not_unparsed():
    actor, mw = _two_entities()
    infer = build_long_distance_inferer(lambda s, u: _NO_LINK)
    before = llm_stats.snapshot()

    assert infer(actor, mw, "APT-X deployed MW.") is None
    assert _counted(before) == {"long_distance_answered": 1}


def test_a_readable_link_is_answered_and_returned():
    actor, mw = _two_entities()
    infer = build_long_distance_inferer(lambda s, u: (
        '{"related": true, "source": "a", "verb": "uses", "quote": "APT-X deployed MW."}'))
    before = llm_stats.snapshot()

    edge = infer(actor, mw, "APT-X deployed MW.")
    assert edge is not None and edge.verb == "uses"
    assert _counted(before) == {"long_distance_answered": 1}


# ── Stage 4c: the stage report ───────────────────────────────────────────────

class _WithLongDistance(Hooks):
    """A relationship policy that turns Stage 4c on."""

    def policy(self):
        return {"completion": {"long_distance": True, "transitive": False}}


def _ask_about_two_islands(monkeypatch, answers):
    """The island search is stubbed to ask twice; the inferer and the counters are real."""
    actor, mw = _two_entities()
    replies = iter(answers)

    def islands(stix_objects, report_text, infer, *rest):
        infer(actor, mw, report_text)
        infer(mw, actor, report_text)

    monkeypatch.setattr(stage4b_graph_completion, "_infer_long_distance", islands)
    monkeypatch.setattr("pipeline.stage4c_long_distance.default_long_distance_inferer",
                        lambda policy: build_long_distance_inferer(lambda s, u: next(replies)))


def _opts() -> RunOptions:
    return RunOptions(disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False,
                      consensus=False, document_relations=False, llm_parallelism=1)


def test_every_4c_answer_unreadable_degrades_the_stage(sample_cti_text, mock_llm, monkeypatch):
    _ask_about_two_islands(monkeypatch, ["not json", "still not json"])

    result = run_document(Document(text=sample_cti_text), _opts(), hooks=_WithLongDistance())

    stage = result.outcome("4c")
    assert stage.status == DEGRADED
    assert stage.reason == "2 of 2 answers unreadable, read as no link"
    assert stage.counts["long_distance_unparsed"] == 2 and stage.counts["long_distance_answered"] == 0


def test_some_4c_answers_unreadable_keeps_the_stage_ran_with_the_count(sample_cti_text, mock_llm, monkeypatch):
    _ask_about_two_islands(monkeypatch, ["not json", _NO_LINK])

    result = run_document(Document(text=sample_cti_text), _opts(), hooks=_WithLongDistance())

    stage = result.outcome("4c")
    assert stage.status == RAN
    assert stage.reason == "1 of 2 answers unreadable, read as no link"
    assert stage.counts["long_distance_unparsed"] == 1 and stage.counts["long_distance_answered"] == 1


def test_a_4c_question_with_no_answer_is_counted():
    actor, mw = _two_entities()
    infer = build_long_distance_inferer(lambda s, u: "")
    before = llm_stats.snapshot()

    assert infer(actor, mw, "APT-X deployed MW.") is None
    assert _counted(before) == {"long_distance_unanswered": 1}


def test_a_provider_down_for_every_4c_question_degrades_the_stage(sample_cti_text, mock_llm, monkeypatch):
    _ask_about_two_islands(monkeypatch, ["", ""])

    result = run_document(Document(text=sample_cti_text), _opts(), hooks=_WithLongDistance())

    stage = result.outcome("4c")
    assert stage.status == DEGRADED
    assert stage.reason == "2 of 2 questions got no answer"
    assert stage.counts["long_distance_unanswered"] == 2


# ── Stage 3: a provider with no client ───────────────────────────────────────

def test_no_anthropic_client_is_a_failed_request(monkeypatch):
    monkeypatch.setattr(s3, "_get_anthropic_client", lambda: None)
    before = llm_stats.snapshot()

    assert s3._call_anthropic("s", "u") == ""
    assert llm_stats.last_call_failed() is True
    assert _counted(before) == {"provider_calls": 1, "provider_failures": 1}
    assert llm_stats.snapshot()["last_error"] == "no client: Anthropic is not configured"


def test_no_openai_compatible_client_is_a_failed_request():
    before = llm_stats.snapshot()

    assert s3._call_openai_compatible(None, "m", "s", "u", "vLLM") == ""
    assert llm_stats.last_call_failed() is True
    assert _counted(before) == {"provider_calls": 1, "provider_failures": 1}
    assert llm_stats.snapshot()["last_error"] == "no client: vLLM is not configured"


def test_a_chunk_with_no_client_counts_as_a_provider_failure_not_an_empty_answer(monkeypatch):
    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_get_anthropic_client", lambda: None)
    before = llm_stats.snapshot()

    assert s3.enrich_chunk(_TEXT, [], verify_rels=False, verify_ttps_on=False) == s3.LLMEnrichmentResult()
    counts = _counted(before)
    assert counts["extraction_provider_failed"] == 1
    assert "extraction_empty" not in counts


# ── Stage 3e: the reason a requested consensus was refused ───────────────────

def test_consensus_asked_without_a_second_provider_gives_its_reason(monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("CONSENSUS_PROVIDER", raising=False)

    assert consensus_disabled_reason() == _UNSET
    assert consensus_enabled() is False


def test_consensus_with_the_primary_provider_as_second_gives_its_reason(monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "anthropic")

    assert consensus_disabled_reason() == _SAME
    assert consensus_enabled() is False


def test_consensus_with_another_second_provider_has_no_reason(monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "mistral")

    assert consensus_disabled_reason() is None
    assert consensus_enabled() is True


def test_consensus_not_asked_has_no_reason(monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "false")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "anthropic")

    assert consensus_disabled_reason() is None


def test_consensus_provider_none_is_not_asked_so_has_no_reason(monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "none")

    assert consensus_disabled_reason() is None


def test_stage_3e_report_gives_the_reason_the_consensus_was_refused(sample_cti_text, mock_llm, monkeypatch):
    monkeypatch.setenv("ENABLE_CONSENSUS", "true")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("CONSENSUS_PROVIDER", raising=False)

    result = run_document(Document(text=sample_cti_text), RunOptions(
        disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False,
        document_relations=False, llm_parallelism=1))

    stage = result.outcome("3e")
    assert stage.status == SKIPPED and stage.reason == _UNSET
