"""A name typed two ways is recorded in the ledger, even when Stage 2 resolved it (issue #397).

`resolve_type_conflicts` (Stage 2) drops the losing type of a name typed two
ways before Stage 4 runs, so `with_named_entities` never saw the conflict and
the MappingLedger never recorded it (ADR-0061, ADR-0092).  The run now keeps
what Stage 2 dropped (`RunResult.resolved_away`) and records it as outranked.
The bundle is the same as before: the ledger is stored beside it, not in it.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.bundle_ledger import MappingLedger
from pipeline.named_entities import OutrankedType, with_named_entities
from pipeline.orchestrator import Document, RunOptions, run_document
from pipeline.stage3_llm import LLMEnrichmentResult

_TEXT = "Snake was used against France in 2024."


def _e(value, etype, source="gazetteer"):
    return RawEntity(value=value, entity_type=etype, source=source)


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _options():
    return RunOptions(disabled=frozenset({"2f", "3"}), consensus=False, document_relations=False,
                      llm_parallelism=1, verify_relationships=False, verify_ttps=False)


def _run(monkeypatch, cyner_found):
    """A run whose gazetteer types "Snake" as a tool and whose CyNER returns `cyner_found`."""
    import pipeline.stage2b_gazetteer as gaz
    import pipeline.stage2d_cyner as cyner
    monkeypatch.setattr(gaz, "available", lambda: True)
    monkeypatch.setattr(gaz, "match_gazetteer_traced", lambda text: ([_e("Snake", EntityType.TOOL)], []))
    monkeypatch.setattr(cyner, "cyner_available", lambda: True)
    monkeypatch.setattr(cyner, "extract_cyner_entities", lambda text: list(cyner_found))
    return run_document(Document(text=_TEXT), _options())


def _shipped(r):
    return {(o["type"], o.get("name")) for o in r.bundle.objects}


# ── with_named_entities: resolved_away is recorded, and changes nothing else ──

def test_a_resolved_away_loser_is_recorded_as_outranked_by_the_kept_type_issue_397():
    kept = [_e("Snake", EntityType.TOOL)]
    dropped = [_e("Snake", EntityType.MALWARE, "cyner")]

    out = with_named_entities(LLMEnrichmentResult(), kept, resolved_away=dropped)

    assert out.outranked == ()                                  # the bundle's input is untouched
    assert out.llm_result.malware_families == []
    assert out.resolved_away == (
        OutrankedType("Snake", "malware", ("cyner",), ("tool",), ("gazetteer",)),)
    assert out.keeps(kept[0])


def test_record_writes_the_resolved_away_loser_as_dropped_outranked_type_issue_397():
    ledger = MappingLedger()

    with_named_entities(LLMEnrichmentResult(), [_e("Snake", EntityType.TOOL)],
                        resolved_away=[_e("Snake", EntityType.MALWARE, "cyner")]).record(ledger)

    assert ledger.entities == [{
        "value": "Snake", "entity_type": "malware", "outcome": "dropped", "reason": "outranked_type",
        "sources": ["cyner"], "kept_types": ["tool"], "kept_sources": ["gazetteer"],
    }]


def test_a_resolved_away_loser_already_outranked_by_the_lists_is_not_recorded_twice_issue_397():
    # The LLM lists "Snake" as malware: the outranking records that one already.
    llm = LLMEnrichmentResult(malware_families=["Snake"])

    out = with_named_entities(llm, [_e("Snake", EntityType.TOOL)],
                              resolved_away=[_e("Snake", EntityType.MALWARE, "cyner")])

    assert out.outranked == (OutrankedType("Snake", "malware", ("llm",), ("tool",), ("gazetteer",)),)
    assert out.resolved_away == ()


def test_nothing_resolved_away_records_nothing_new_issue_397():
    out = with_named_entities(LLMEnrichmentResult(), [_e("Snake", EntityType.TOOL)])

    assert out.resolved_away == ()


# ── A run: Stage 2 resolves the conflict, Stage 4 records it ─────────────────

def test_the_run_ledger_records_the_resolved_loser_and_the_bundle_is_the_same_issue_397(monkeypatch):
    conflict = _run(monkeypatch, [_e("Snake", EntityType.MALWARE, "cyner")])
    control = _run(monkeypatch, [])                  # the same run, CyNER finds no malware

    # The bundle: Snake ships as the tool, and as nothing else, as before the fix.
    assert _shipped(conflict) == _shipped(control)
    assert ("tool", "Snake") in _shipped(conflict)
    assert ("malware", "Snake") not in _shipped(conflict)

    # The ledger: the malware Snake is recorded as outranked by the tool.
    entries = [e for e in conflict.ledger["entities"] if e["value"] == "Snake" and e["entity_type"] == "malware"]
    assert entries == [{
        "value": "Snake", "entity_type": "malware", "outcome": "dropped", "reason": "outranked_type",
        "sources": ["cyner"], "kept_types": ["tool"], "kept_sources": ["gazetteer"],
    }]
    assert not [e for e in control.ledger["entities"] if e.get("reason") == "outranked_type"]
