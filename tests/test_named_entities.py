"""The detectors' named entities reach the bundle on every path (audit B 8.1.2).

`python main.py report.txt --no-llm` produced bundles with 0 malware, 0
threat-actor and 0 tool although the gazetteer had found APT29, WellMess and
Cobalt Strike: Stage 4 reads the LLM's lists, the worker's finalisation
rebuilt them from the job store, the CLI and `run_document` never did.

A name typed several ways keeps the type of its best-ranked source (ADR-0092).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.schemas import EntityType, RawEntity
from pipeline.bundle_ledger import MappingLedger
from pipeline.named_entities import OutrankedType, stored_row_source, with_named_entities
from pipeline.orchestrator import Document, RunOptions, run_document
from pipeline.stage3_llm import LLMEnrichmentResult


def _e(value, etype, source="gazetteer"):
    return RawEntity(value=value, entity_type=etype, source=source)


def _lists(out):
    r = out.llm_result
    return r.malware_families, r.threat_actors, r.tools


def test_names_join_the_matching_list_and_keep_the_llms_spelling():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WellMess"])
    out = with_named_entities(llm, [
        _e("apt29", EntityType.THREAT_ACTOR),            # already there, other case: not duplicated
        _e("SUNBURST", EntityType.MALWARE),
        _e("Cobalt Strike", EntityType.TOOL, "cyner"),
        _e("185.220.101.45", EntityType.IPV4, "ioc"),     # not a named list
        _e("  ", EntityType.TOOL),                         # blank: ignored
    ])
    assert out.llm_result.threat_actors == ["APT29"]
    assert out.llm_result.malware_families == ["WellMess", "SUNBURST"]
    assert out.llm_result.tools == ["Cobalt Strike"]
    assert out.outranked == ()
    assert llm.malware_families == ["WellMess"]            # the input is not mutated


def test_job_store_rows_are_accepted_as_pairs():
    out = with_named_entities(LLMEnrichmentResult(), [("malware", "Emotet"), ("tool", "PsExec"),
                                                      ("threat_actor", "TA505"), ("technique", "T1059"),
                                                      ("not-a-type", "x")])
    assert _lists(out) == (["Emotet"], ["TA505"], ["PsExec"])


def test_nothing_to_add_returns_the_same_object():
    llm = LLMEnrichmentResult(tools=["PsExec"])
    assert with_named_entities(llm, [_e("psexec", EntityType.TOOL)]).llm_result is llm


# ── One type per name, by source rank (ADR-0092) ────────────────────────────────

@pytest.mark.parametrize("winner, loser", [
    ("manual", "gazetteer"), ("analyst", "gazetteer"), ("baseline_stix", "gazetteer"),   # the analyst's labels, rank -1
    ("gazetteer", "llm"),             # 0 over 1
    ("ioc", "llm"),
    ("llm", "cyner"),                 # 1 over 2
    ("llm", "gliner"),
    ("cyner", "spacy"),               # 2 over 3
    ("gliner", "alias_list"),
    ("spacy", "some_new_source"),     # any listed source over an unknown one (99)
    ("alias_list", ""),               # a pair has no source
])
def test_each_rank_beats_the_next(winner, loser):
    ents = [_e("Foo", EntityType.TOOL, winner), _e("foo", EntityType.MALWARE, loser)]
    for order in (ents, ents[::-1]):
        out = with_named_entities(LLMEnrichmentResult(), order)

        assert _lists(out) == ([], [], ["Foo"])
        assert out.outranked == (OutrankedType("foo", "malware", (loser,), ("tool",), (winner,)),)


def test_a_name_the_llm_listed_is_dropped_from_its_list_when_outranked():
    llm = LLMEnrichmentResult(malware_families=["PsExec"])

    out = with_named_entities(llm, [_e("PsExec", EntityType.TOOL)])

    assert _lists(out) == ([], [], ["PsExec"])
    assert out.outranked == (OutrankedType("PsExec", "malware", ("llm",), ("tool",), ("gazetteer",)),)
    assert llm.malware_families == ["PsExec"]               # the input is not mutated


def test_a_name_the_llm_lists_beats_the_same_name_from_spacy():
    llm = LLMEnrichmentResult(tools=["NextChat"])

    out = with_named_entities(llm, [_e("NextChat", EntityType.MALWARE, "spacy")])

    assert _lists(out) == ([], [], ["NextChat"])
    assert out.outranked == (OutrankedType("NextChat", "malware", ("spacy",), ("tool",), ("llm",)),)


@pytest.mark.parametrize("source", ["gazetteer", "cyner"])
def test_a_campaign_ranks_after_every_source(source):
    llm = LLMEnrichmentResult(campaign_name="Industroyer2")

    out = with_named_entities(llm, [_e("Industroyer2", EntityType.MALWARE, source)])

    assert out.llm_result.campaign_name is None
    assert out.llm_result.malware_families == ["Industroyer2"]
    assert out.outranked == (OutrankedType("Industroyer2", "campaign", ("llm",), ("malware",), (source,)),)
    assert llm.campaign_name == "Industroyer2"              # the input is not mutated


def test_a_campaign_entity_never_joins_a_list_and_loses_to_the_llms_tool():
    llm = LLMEnrichmentResult(tools=["Impacket"])

    out = with_named_entities(llm, [_e("Impacket", EntityType.CAMPAIGN, "gliner")])

    assert _lists(out) == ([], [], ["Impacket"])
    assert out.outranked == (OutrankedType("Impacket", "campaign", ("gliner",), ("tool",), ("llm",)),)


def test_a_campaign_alone_or_with_another_name_is_untouched():
    llm = LLMEnrichmentResult(campaign_name="Operation Aurora")

    out = with_named_entities(llm, [_e("Elderwood", EntityType.THREAT_ACTOR), _e("Aurora", EntityType.MALWARE)])

    assert out.llm_result.campaign_name == "Operation Aurora"
    assert _lists(out) == (["Aurora"], ["Elderwood"], [])
    assert out.outranked == ()


def test_the_analysts_campaign_beats_a_gazetteer_malware():
    llm = LLMEnrichmentResult(campaign_name="Industroyer2")
    analyst = stored_row_source("llm", 1, "human")

    out = with_named_entities(llm, [("campaign", "Industroyer2", analyst),
                                    ("malware", "Industroyer2", "gazetteer")])

    assert out.llm_result.campaign_name == "Industroyer2"
    assert out.llm_result.malware_families == []
    # the campaign's sources: the analyst's row, and the LLM's campaign_name it was routed from
    assert out.outranked == (
        OutrankedType("Industroyer2", "malware", ("gazetteer",), ("campaign",), ("analyst", "llm")),)


def test_the_analysts_campaign_and_the_analysts_malware_both_stay():
    llm = LLMEnrichmentResult(campaign_name="Industroyer2")
    analyst = stored_row_source("gazetteer", 1, "human")

    out = with_named_entities(llm, [("campaign", "Industroyer2", analyst), ("malware", "Industroyer2", analyst)])

    assert out.llm_result.campaign_name == "Industroyer2"
    assert out.llm_result.malware_families == ["Industroyer2"]
    assert out.outranked == ()


@pytest.mark.parametrize("llm, entities", [
    # CyNER typing one span two ways (BREEZE COMET)
    (LLMEnrichmentResult(), [_e("BREEZE COMET", EntityType.MALWARE, "cyner"),
                             _e("BREEZE COMET", EntityType.THREAT_ACTOR, "cyner")]),
    # a real double name of the gazetteer (Carbanak)
    (LLMEnrichmentResult(), [_e("Carbanak", EntityType.MALWARE), _e("Carbanak", EntityType.THREAT_ACTOR)]),
    # the LLM listing a name as malware and as tool (SoftEther)
    (LLMEnrichmentResult(malware_families=["SoftEther"], tools=["SoftEther"]), []),
])
def test_equal_ranks_all_stay(llm, entities):
    out = with_named_entities(llm, entities)

    assert out.outranked == ()
    kept = [n for names in _lists(out) for n in names]
    assert len(kept) == 2 and len({n.lower() for n in kept}) == 1


def test_the_name_is_compared_by_case_and_outer_spaces():
    out = with_named_entities(LLMEnrichmentResult(), [("tool", "  PSEXEC ", "gazetteer"),
                                                      ("malware", "psexec", "cyner")])

    assert _lists(out) == ([], [], ["PSEXEC"])
    assert out.outranked == (OutrankedType("psexec", "malware", ("cyner",), ("tool",), ("gazetteer",)),)


def test_the_kept_sources_are_those_of_every_kept_type_and_the_sources_every_one_of_the_type():
    out = with_named_entities(LLMEnrichmentResult(), [
        _e("Foo", EntityType.MALWARE, "gazetteer"), _e("foo", EntityType.THREAT_ACTOR, "ioc"),
        _e("FOO", EntityType.TOOL, "spacy"), _e("Foo", EntityType.TOOL, "cyner"),
    ])

    assert _lists(out) == (["Foo"], ["foo"], [])
    assert out.outranked == (OutrankedType("FOO", "tool", ("cyner", "spacy"), ("malware", "threat_actor"),
                                           ("gazetteer", "ioc")),)


@pytest.mark.parametrize("source, accepted, origin, expected", [
    ("gazetteer", 1, "human", "analyst"),          # accepted by the analyst on its own
    ("llm", 1, "human", "analyst"),
    ("gazetteer", 1, "human_bulk", "gazetteer"),   # a bulk accept, the policy, a default: not the analyst's
    ("llm", 1, "auto_policy", "llm"),
    ("llm", 1, "default", "llm"),
    ("cyner", 1, "legacy", "cyner"),
    ("cyner", 1, None, "cyner"),
    ("cyner", None, None, "cyner"),                # unreviewed
    ("cyner", None, "human", "cyner"),
    ("gazetteer", 0, "human", "gazetteer"),        # rejected
    ("manual", None, None, "manual"),              # already the analyst's rank
    ("cyner", 1, "baseline_stix", "baseline_stix"),  # the analyst's baseline holds it (Stage 3r)
    (None, None, None, ""),
])
def test_a_stored_row_counts_as_the_analysts_only_when_the_analyst_accepted_it(source, accepted, origin, expected):
    assert stored_row_source(source, accepted, origin) == expected


def test_keeps_drops_the_raw_entities_of_an_outranked_name_and_type_only():
    llm = LLMEnrichmentResult(tools=["NextChat"])
    spacy_malware = _e("NextChat", EntityType.MALWARE, "spacy")
    cyner_tool = _e("nextchat", EntityType.TOOL, "cyner")
    gazetteer_malware = _e("Industroyer2", EntityType.MALWARE)
    campaign = _e("Industroyer2", EntityType.CAMPAIGN, "llm")
    ip = _e("185.220.101.45", EntityType.IPV4, "ioc")

    out = with_named_entities(llm, [spacy_malware, cyner_tool, gazetteer_malware, campaign, ip])

    assert not out.keeps(spacy_malware)
    assert out.keeps(cyner_tool)
    assert out.keeps(gazetteer_malware)
    assert not out.keeps(campaign)
    assert out.keeps(ip)


def test_record_writes_one_dropped_entry_per_outranked_type():
    llm = LLMEnrichmentResult(tools=["NextChat"], campaign_name="Industroyer2")
    out = with_named_entities(llm, [_e("NextChat", EntityType.MALWARE, "spacy"),
                                    _e("Industroyer2", EntityType.MALWARE, "gazetteer")])
    ledger = MappingLedger()

    out.record(ledger)

    assert ledger.entities == [
        {"value": "Industroyer2", "entity_type": "campaign", "outcome": "dropped", "reason": "outranked_type",
         "sources": ["llm"], "kept_types": ["malware"], "kept_sources": ["gazetteer"]},
        {"value": "NextChat", "entity_type": "malware", "outcome": "dropped", "reason": "outranked_type",
         "sources": ["spacy"], "kept_types": ["tool"], "kept_sources": ["llm"]},
    ]


def test_a_type_the_baseline_holds_is_the_analysts_on_a_run_and_on_a_finalize():
    """Enrich mode: a run asks Stage 3r (`baseline_holds`), a finalize reads the
    row's origin `baseline_stix`.  Both give the analyst's type, the LLM's own
    name included, and the same lists."""
    held = {("malware", "x"), ("malware", "y")}
    run = with_named_entities(
        LLMEnrichmentResult(malware_families=["Y"]),
        [_e("X", EntityType.MALWARE, "cyner"), _e("X", EntityType.THREAT_ACTOR),
         _e("Y", EntityType.TOOL)],
        baseline_holds=lambda t, v: (t, v.lower()) in held,
    )
    finalize = with_named_entities(LLMEnrichmentResult(), [
        ("malware", "Y", stored_row_source("llm", 1, "baseline_stix")),
        ("malware", "X", stored_row_source("cyner", 1, "baseline_stix")),
        ("threat_actor", "X", stored_row_source("gazetteer", None, None)),
        ("tool", "Y", stored_row_source("gazetteer", None, None)),
    ])

    for out in (run, finalize):
        assert sorted(out.llm_result.malware_families) == ["X", "Y"]
        assert (out.llm_result.threat_actors, out.llm_result.tools) == ([], [])
    assert run.outranked == finalize.outranked == (
        OutrankedType("X", "threat_actor", ("gazetteer",), ("malware",), ("baseline_stix",)),
        OutrankedType("Y", "tool", ("gazetteer",), ("malware",), ("baseline_stix",)),
    )
    # Without Stage 3r's answer, the gazetteer outranks the detector and the LLM.
    plain = with_named_entities(LLMEnrichmentResult(malware_families=["Y"]),
                                [_e("X", EntityType.MALWARE, "cyner"), _e("X", EntityType.THREAT_ACTOR),
                                 _e("Y", EntityType.TOOL)])
    assert [(o.value, o.entity_type) for o in plain.outranked] == [("X", "malware"), ("Y", "malware")]


def test_record_writes_nothing_when_nothing_is_outranked():
    ledger = MappingLedger()

    with_named_entities(LLMEnrichmentResult(), [_e("Carbanak", EntityType.MALWARE)]).record(ledger)

    assert ledger.entities == []


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
    monkeypatch.setattr(gaz, "match_gazetteer_traced", lambda text: (list(found), []))
    options = RunOptions(disabled=frozenset({"2f", "3"}), consensus=False, document_relations=False,
                         llm_parallelism=1, verify_relationships=False, verify_ttps=False)

    r = run_document(Document(text=sample_cti_text), options)

    names = {(o["type"], o.get("name")) for o in r.bundle.objects}
    assert {("threat-actor", "APT29"), ("malware", "SUNBURST"), ("tool", "Cobalt Strike")} <= names
    assert r.llm_result is not None and r.llm_result.threat_actors == []   # Stage 3's result untouched
    entries = r.ledger["entities"]
    assert {e["value"] for e in entries if e["outcome"] == "merged"} >= {"APT29", "SUNBURST", "Cobalt Strike"}
    assert not [e for e in entries if e.get("reason") == "not_in_llm_lists"]


def _options():
    return RunOptions(disabled=frozenset({"2f"}), consensus=False, document_relations=False,
                      llm_parallelism=1, verify_relationships=False, verify_ttps=False)


def _ledger_of(r, value):
    return [e for e in r.ledger["entities"] if e["value"] == value]


def test_a_run_ships_the_llms_tool_not_spacys_malware_of_the_same_name(
        sample_cti_text, mock_llm, mock_llm_response, monkeypatch):
    """Stage 3 drops from the LLM's lists a name the gazetteer or CyNER found; a
    spaCy entity it does not know, so the LLM's `tools` and spaCy's malware meet."""
    import pipeline.stage2_extraction as extraction
    regex_and_spacy = extraction.extract_entities
    mock_llm.return_value = json.dumps({**mock_llm_response, "tools": ["NextChat"]})
    monkeypatch.setattr(extraction, "extract_entities",
                        lambda chunk: [*regex_and_spacy(chunk), _e("NextChat", EntityType.MALWARE, "spacy")])

    r = run_document(Document(text=sample_cti_text + " The operators used NextChat to talk to the host."),
                     _options())

    names = {(o["type"], o.get("name")) for o in r.bundle.objects}
    assert ("tool", "NextChat") in names and ("malware", "NextChat") not in names
    assert ("malware", "SUNBURST") in names
    entries = _ledger_of(r, "NextChat")
    assert not [e for e in entries if e.get("reason") == "not_in_llm_lists"]
    (outranked,) = (e for e in entries if e.get("reason") == "outranked_type")
    assert (outranked["entity_type"], outranked["outcome"]) == ("malware", "dropped")
    assert (outranked["sources"], outranked["kept_types"], outranked["kept_sources"]) == (
        ["spacy"], ["tool"], ["llm"])
    assert r.llm_result.tools == ["NextChat"]                         # Stage 3's result untouched


def test_an_enrich_run_keeps_the_type_the_analysts_baseline_holds(
        sample_cti_text, mock_llm, mock_llm_response, monkeypatch):
    """The names of the test above, in enrich mode: Stage 3r says the analyst's
    baseline holds NextChat as a malware, so spaCy's malware is the analyst's type
    and outranks the LLM's tool, as its stored row (origin `baseline_stix`) does
    on a finalize."""
    import pipeline.stage2_extraction as extraction
    from pipeline import baseline_stix
    regex_and_spacy = extraction.extract_entities
    mock_llm.return_value = json.dumps({**mock_llm_response, "tools": ["NextChat"]})
    monkeypatch.setattr(extraction, "extract_entities",
                        lambda chunk: [*regex_and_spacy(chunk), _e("NextChat", EntityType.MALWARE, "spacy")])
    baseline_id = "malware--0b1c2d3e-0000-4000-8000-000000000001"
    held = baseline_stix.Reconciliation(entity_status={("malware", "nextchat"): (baseline_stix.MATCHED, baseline_id)})
    monkeypatch.setattr("pipeline.baseline_stix.reconcile", lambda *args: held)
    raw = (Path(__file__).parent / "fixtures" / "baselines" / "opencti_report.json").read_bytes()
    index, _, _ = baseline_stix.intake(raw, validate=False)

    r = run_document(Document(text=sample_cti_text + " The operators used NextChat to talk to the host.",
                              baseline=index), _options())

    names = {(o["type"], o.get("name")) for o in r.bundle.objects}
    assert ("malware", "NextChat") in names and ("tool", "NextChat") not in names
    (outranked,) = (e for e in _ledger_of(r, "NextChat") if e.get("reason") == "outranked_type")
    assert (outranked["entity_type"], outranked["sources"], outranked["kept_types"],
            outranked["kept_sources"]) == ("tool", ["llm"], ["malware"], ["baseline_stix"])


def test_a_run_ships_the_gazetteers_malware_not_the_llms_campaign_of_the_same_name(
        sample_cti_text, mock_llm, mock_llm_response, monkeypatch):
    import pipeline.stage2b_gazetteer as gaz
    mock_llm.return_value = json.dumps({**mock_llm_response, "campaign_name": "Industroyer2"})
    monkeypatch.setattr(gaz, "available", lambda: True)
    monkeypatch.setattr(gaz, "match_gazetteer_traced",
                        lambda text: ([_e("Industroyer2", EntityType.MALWARE)], []))

    r = run_document(Document(text=sample_cti_text + " The campaign, Industroyer2, hit the grid."), _options())

    names = {(o["type"], o.get("name")) for o in r.bundle.objects}
    assert ("malware", "Industroyer2") in names and ("campaign", "Industroyer2") not in names
    entries = _ledger_of(r, "Industroyer2")
    assert {(e["entity_type"], e["outcome"], e.get("reason")) for e in entries} == {
        ("malware", "emitted", None), ("malware", "merged", "same_value"),
        ("campaign", "dropped", "outranked_type")}
    assert r.llm_result.campaign_name == "Industroyer2"               # Stage 3's result untouched
