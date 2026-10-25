"""pipeline/orchestrator.py — Stage 3r, the baseline reconciliation (ADR-0090).

Offline, like test_orchestrator.py: SKIP_HEAVY_MODELS keeps the models out and
the LLM is the `mock_llm` fixture.  pipeline.baseline_stix.reconcile is always
replaced by a fake here: its body is tested in its own module.
"""
from pathlib import Path

import pytest

from pipeline import baseline_stix
from pipeline import orchestrator as orch
from pipeline.baseline_stix import Reconciliation
from pipeline.orchestrator import Document, Hooks, RunOptions, run_document


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    """Same as test_orchestrator.py: the models are not what these tests are about."""
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _index():
    """A real baseline index: since lot 4 the run's Stage 4 merges it, so a
    stand-in object no longer gets through.  Its objects are not given to the
    Document, so the merge keeps nothing and the run's bundle is CTIParsor's."""
    raw = (Path(__file__).parent / "fixtures" / "baselines" / "opencti_report.json").read_bytes()
    index, _, _ = baseline_stix.intake(raw, validate=False)
    assert index is not None
    return index


def _opts() -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    return RunOptions(disabled=frozenset({"2f"}), consensus=False, document_relations=False,
                      verify_relationships=False, verify_ttps=False, llm_parallelism=1)


class _Order(Hooks):
    """Records, in call order, the two hooks that Stage 3r and extraction_ready feed."""

    def __init__(self):
        self.events: list[str] = []
        self.reconciled: list = []

    def baseline_reconciled(self, reconciliation):
        self.events.append("baseline_reconciled")
        self.reconciled.append(reconciliation)

    def extraction_ready(self, entities, llm_result, text):
        self.events.append("extraction_ready")


def _fake_reconcile(monkeypatch, result=None):
    """Replace the reconciliation; returns the list of its calls' arguments."""
    calls: list[tuple] = []

    def fake(entities, llm_result, text, baseline):
        calls.append((entities, llm_result, text, baseline))
        if result is None:
            return Reconciliation(stats={})
        return result

    monkeypatch.setattr("pipeline.baseline_stix.reconcile", fake)
    return calls


def test_stage_3r_comes_right_after_3doc_and_has_a_label():
    assert orch.STAGES[orch.STAGES.index("3doc") + 1] == "3r"
    assert orch.STAGE_LABELS["3r"] == "baseline reconciliation"


def test_full_mode_skips_3r_and_never_calls_the_reconciliation(mock_llm, sample_cti_text, monkeypatch):
    def must_not_run(*args):
        raise AssertionError("no baseline: Stage 3r must not reconcile")

    monkeypatch.setattr("pipeline.baseline_stix.reconcile", must_not_run)
    hooks = _Order()
    result = run_document(Document(text=sample_cti_text), _opts(), hooks)

    stage = result.outcome("3r")
    assert stage is not None and stage.status == "skipped" and stage.reason == "no baseline"
    assert result.reconciliation is None
    assert "baseline_reconciled" not in hooks.events
    assert "extraction_ready" in hooks.events          # the run itself went on


def test_enrich_mode_reconciles_once_before_extraction_ready(mock_llm, sample_cti_text, monkeypatch):
    fake = Reconciliation(stats={"entities_new": 2, "entities_matched": 1})
    _fake_reconcile(monkeypatch, fake)
    hooks = _Order()
    result = run_document(Document(text=sample_cti_text, baseline=_index()), _opts(), hooks)

    stage = result.outcome("3r")
    assert stage is not None and stage.status == "ran"
    assert stage.counts == {"entities_new": 2, "entities_matched": 1}
    assert result.reconciliation is fake
    assert hooks.reconciled == [fake]
    assert hooks.events.count("baseline_reconciled") == 1
    assert hooks.events.index("baseline_reconciled") < hooks.events.index("extraction_ready")


def test_the_reconciliation_gets_the_extractions_and_the_documents_baseline(mock_llm, sample_cti_text,
                                                                           monkeypatch):
    calls = _fake_reconcile(monkeypatch)
    baseline = _index()
    result = run_document(Document(text=sample_cti_text, baseline=baseline), _opts())

    assert len(calls) == 1
    entities, llm_result, text, got = calls[0]
    assert entities is result.entities
    assert llm_result is result.llm_result
    assert text == result.text
    assert got is baseline


def test_a_failing_reconciliation_fails_the_run_before_any_write(mock_llm, sample_cti_text, monkeypatch):
    def broken(entities, llm_result, text, baseline):
        raise ValueError("baseline index corrupt")

    monkeypatch.setattr("pipeline.baseline_stix.reconcile", broken)
    hooks = _Order()
    with pytest.raises(ValueError, match="baseline index corrupt"):
        run_document(Document(text=sample_cti_text, baseline=_index()), _opts(), hooks)

    assert "extraction_ready" not in hooks.events      # no silent fall back to full mode
    assert hooks.reconciled == []
