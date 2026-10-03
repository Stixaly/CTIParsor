"""The detectors' named entities reach the bundle on every path (audit B 8.1.2).

`python main.py report.txt --no-llm` produced bundles with 0 malware, 0
threat-actor and 0 tool although the gazetteer had found APT29, WellMess and
Cobalt Strike: Stage 4 reads the LLM's lists, the worker's finalisation
rebuilt them from the job store, the CLI and `run_document` never did.
"""
from __future__ import annotations

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.named_entities import with_named_entities
from pipeline.orchestrator import Document, RunOptions, run_document
from pipeline.stage3_llm import LLMEnrichmentResult


def _e(value, etype, source="gazetteer"):
    return RawEntity(value=value, entity_type=etype, source=source)


def test_names_join_the_matching_list_and_keep_the_llms_spelling():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WellMess"])
    out = with_named_entities(llm, [
        _e("apt29", EntityType.THREAT_ACTOR),            # already there, other case: not duplicated
        _e("SUNBURST", EntityType.MALWARE),
        _e("Cobalt Strike", EntityType.TOOL, "cyner"),
        _e("185.220.101.45", EntityType.IPV4, "ioc"),     # not a named list
        _e("  ", EntityType.TOOL),                         # blank: ignored
    ])
    assert out.threat_actors == ["APT29"]
    assert out.malware_families == ["WellMess", "SUNBURST"]
    assert out.tools == ["Cobalt Strike"]
    assert llm.malware_families == ["WellMess"]            # the input is not mutated


def test_job_store_rows_are_accepted_as_pairs():
    out = with_named_entities(LLMEnrichmentResult(), [("malware", "Emotet"), ("tool", "PsExec"),
                                                      ("threat_actor", "TA505"), ("technique", "T1059"),
                                                      ("not-a-type", "x")])
    assert (out.malware_families, out.tools, out.threat_actors) == (["Emotet"], ["PsExec"], ["TA505"])


def test_nothing_to_add_returns_the_same_object():
    llm = LLMEnrichmentResult(tools=["PsExec"])
    assert with_named_entities(llm, [_e("psexec", EntityType.TOOL)]) is llm


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def test_a_run_without_the_llm_ships_the_gazetteers_entities(sample_cti_text, monkeypatch):
    """The CLI's `--no-llm` case the audit reproduced, with the gazetteer's
    answer fixed (the automaton is off under SKIP_HEAVY_MODELS)."""
    import pipeline.stage2b_gazetteer as gaz
    found = [_e("APT29", EntityType.THREAT_ACTOR), _e("SUNBURST", EntityType.MALWARE),
             _e("Cobalt Strike", EntityType.TOOL)]
    monkeypatch.setattr(gaz, "available", lambda: True)
    monkeypatch.setattr(gaz, "match_gazetteer", lambda text: list(found))
    options = RunOptions(disabled=frozenset({"2f", "3"}), consensus=False, document_relations=False,
                         llm_parallelism=1, verify_relationships=False, verify_ttps=False)

    r = run_document(Document(text=sample_cti_text), options)

    names = {(o["type"], o.get("name")) for o in r.bundle.objects}
    assert {("threat-actor", "APT29"), ("malware", "SUNBURST"), ("tool", "Cobalt Strike")} <= names
    assert r.llm_result is not None and r.llm_result.threat_actors == []   # Stage 3's result untouched
    entries = r.ledger["entities"]
    assert {e["value"] for e in entries if e["outcome"] == "merged"} >= {"APT29", "SUNBURST", "Cobalt Strike"}
    assert not [e for e in entries if e.get("reason") == "not_in_llm_lists"]
