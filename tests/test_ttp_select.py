"""Stage 3f select mode (ADR-0072): nothing becomes a technique unless the code
validates what the model chose — an id among the candidates, a quote found
verbatim — and a failed call validates nothing.

Every LLM call is a fake; no API key or model is needed.
"""
from __future__ import annotations

import json

import pytest

from models.schemas import EvidenceLabel
from pipeline import stage3f_ttp_select as sel
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted
from pipeline.ttp_retrieval import TtpCandidate

TEXT = ("The actor sent emails with malicious Word attachments to finance staff. "
        "Once opened, the macro ran PowerShell to download a second-stage loader.\n"
        "Credentials were later dumped from LSASS memory with a custom tool.")


def _cands(*ids):
    return [TtpCandidate(attack_id=i, name=f"name {i}", sources=["dense"], passage="p") for i in ids]


def _answer(*items):
    return lambda system, user: json.dumps({"selected": list(items)})


# ── Parsing ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,n", [
    ('{"selected": [{"attack_id": "T1566.001"}]}', 1),
    ('Sure:\n```json\n{"selected": []}\n```', 0),
    ('[{"attack_id": "T1059.001"}, {"attack_id": "T1105"}]', 2),
])
def test_parse_selection_accepts_the_object_anywhere(raw, n):
    assert len(sel.parse_selection(raw)) == n


@pytest.mark.parametrize("raw", ["", "no json here", '{"chosen": []}', '["T1059"]'])
def test_parse_selection_refuses_anything_else(raw):
    assert sel.parse_selection(raw) is None


# ── Validation ───────────────────────────────────────────────────────────────

def test_a_valid_choice_becomes_a_technique_with_its_quote():
    out = sel.select_ttps(TEXT, _cands("T1566.001", "T1003.001"), _answer(
        {"attack_id": "T1566.001", "evidence_quote": "sent emails with malicious Word attachments",
         "reason": "spearphishing attachment"}))
    assert out.status == sel.OK
    assert [(t.mitre_id, t.evidence_text) for t in out.selected] == [
        ("T1566.001", "sent emails with malicious Word attachments")]
    assert out.selected[0].description == "spearphishing attachment"
    assert out.review == []


def test_an_empty_answer_is_an_abstention_not_a_failure():
    out = sel.select_ttps(TEXT, _cands("T1566.001"), _answer())
    assert out.status == sel.OK and out.selected == [] and out.review == []


def test_an_id_outside_the_candidates_never_ships():
    out = sel.select_ttps(TEXT, _cands("T1566.001"), _answer(
        {"attack_id": "T1003.001", "evidence_quote": "dumped from LSASS memory with a custom tool"}))
    assert out.selected == [] and out.rejected == 1
    assert out.review == []                     # not a candidate: nothing to review either


def test_a_quote_not_in_the_text_goes_to_review():
    out = sel.select_ttps(TEXT, _cands("T1003.001"), _answer(
        {"attack_id": "T1003.001", "evidence_quote": "the actor dumped credentials using Mimikatz"}))
    assert out.selected == []
    assert [r.attack_id for r in out.review] == ["T1003.001"]
    assert "verbatim" in out.review[0].reason


def test_a_too_short_quote_goes_to_review(monkeypatch):
    monkeypatch.delenv("TTP_SELECT_MIN_QUOTE_WORDS", raising=False)
    out = sel.select_ttps(TEXT, _cands("T1059.001"), _answer(
        {"attack_id": "T1059.001", "evidence_quote": "PowerShell"}))
    assert out.selected == [] and len(out.review) == 1


def test_the_quote_may_differ_in_whitespace_and_case_only():
    out = sel.select_ttps(TEXT, _cands("T1059.001"), _answer(
        {"attack_id": "t1059.001", "evidence_quote": "the macro ran   POWERSHELL to download"}))
    assert [t.mitre_id for t in out.selected] == ["T1059.001"]


def test_one_entry_per_id():
    item = {"attack_id": "T1059.001", "evidence_quote": "the macro ran PowerShell to download"}
    out = sel.select_ttps(TEXT, _cands("T1059.001"), _answer(item, item))
    assert len(out.selected) == 1


def test_several_techniques_from_one_text():
    out = sel.select_ttps(TEXT, _cands("T1566.001", "T1059.001", "T1003.001", "T1105"), _answer(
        {"attack_id": "T1566.001", "evidence_quote": "emails with malicious Word attachments"},
        {"attack_id": "T1059.001", "evidence_quote": "the macro ran PowerShell"},
        {"attack_id": "T1003.001", "evidence_quote": "Credentials were later dumped from LSASS memory"}))
    assert [t.mitre_id for t in out.selected] == ["T1566.001", "T1059.001", "T1003.001"]


@pytest.mark.parametrize("raw,status", [("", sel.FAILED), ("I cannot help with that", sel.UNPARSED)])
def test_a_failed_or_unparseable_call_keeps_nothing_and_reviews_everything(raw, status):
    out = sel.select_ttps(TEXT, _cands("T1566.001", "T1105"), lambda s, u: raw)
    assert out.status == status
    assert out.selected == []
    assert {r.attack_id for r in out.review} == {"T1566.001", "T1105"}


def test_no_candidate_no_call():
    called = []
    out = sel.select_ttps(TEXT, [], lambda s, u: called.append(1) or "")
    assert out.status == sel.NOTHING and called == []


def test_the_llm_label_is_kept_and_a_gap_becomes_reported():
    quote = "the macro ran PowerShell to download"
    ans = _answer({"attack_id": "T1059.001", "evidence_quote": quote},
                  {"attack_id": "T1105", "evidence_quote": "download a second-stage loader"})
    out = sel.select_ttps(TEXT, _cands("T1059.001", "T1105"), ans,
                          llm_labels={"T1059.001": EvidenceLabel.OBSERVED, "t1105": EvidenceLabel.GAP})
    labels = {t.mitre_id: t.evidence_label for t in out.selected}
    assert labels == {"T1059.001": EvidenceLabel.OBSERVED, "T1105": EvidenceLabel.REPORTED}


def test_the_prompt_carries_the_text_the_candidates_and_the_example_warning():
    seen = {}

    def fn(system, user):
        seen["system"], seen["user"] = system, user
        return '{"selected": []}'
    cands = [TtpCandidate(attack_id="T1105", name="Ingress Tool Transfer", sources=["bm25"],
                          passage="download a second-stage loader", example="APT1 downloaded tools.",
                          example_kind="procedure"),
             TtpCandidate(attack_id="T1059.001", name="PowerShell", sources=["llm"], passage="ran PowerShell")]
    sel.select_ttps(TEXT, cands, fn)
    assert TEXT in seen["user"]
    assert "T1105 — Ingress Tool Transfer" in seen["user"]
    assert "not evidence" in seen["user"] and "never evidence" in seen["system"]
    assert "proposed by the extraction pass" in seen["user"]
    assert "retrieved for" in seen["user"]


def test_a_long_text_is_cut_never_the_candidates():
    seen = {}

    def fn(system, user):
        seen["user"] = user
        return '{"selected": []}'
    sel.select_ttps("word " * 5000, _cands("T1105"), fn, max_prompt_chars=3000)
    assert len(seen["user"]) <= 3000 and "T1105" in seen["user"]


# ── Candidates from the LLM's proposals ──────────────────────────────────────

def test_llm_proposals_resolve_to_ids_and_unresolvable_ones_are_counted():
    ttps = [TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001", evidence_text="ran PowerShell",
                         evidence_label=EvidenceLabel.OBSERVED),
            TTPExtracted(technique_name="LSASS Memory", mitre_id=None),
            TTPExtracted(technique_name="zzqx unknown behaviour qq", mitre_id=None)]
    cands, labels, no_id = sel.llm_proposals_as_candidates(ttps)
    assert [c.attack_id for c in cands] == ["T1059.001", "T1003.001"]
    assert all(c.sources == ["llm"] for c in cands)
    assert labels["T1059.001"] == EvidenceLabel.OBSERVED
    assert no_id == 1


def test_chunk_candidates_put_the_llm_first_and_merge_provenance():
    retrieved = [TtpCandidate(attack_id="T1105", sources=["dense"], fused_rank=1,
                              example="APT1 downloaded tools.", example_kind="procedure"),
                 TtpCandidate(attack_id="T1566", sources=["bm25"], fused_rank=2)]
    llm = [TtpCandidate(attack_id="t1105", sources=["llm"], example="llm summary", example_kind="llm")]
    out = sel.chunk_candidates(retrieved, llm)
    assert [c.attack_id.upper() for c in out] == ["T1105", "T1566"]
    assert out[0].sources == ["dense", "llm"]
    assert out[0].example_kind == "procedure" and out[0].fused_rank == 1


def test_ttp_mode_reads_the_environment_and_defaults_to_select(monkeypatch):
    # select is the default since docs/eval/baseline-2026-10.md
    monkeypatch.delenv("TTP_MODE", raising=False)
    assert sel.ttp_mode() == "select"
    monkeypatch.setenv("TTP_MODE", "VERIFY")
    assert sel.ttp_mode() == "verify"
    monkeypatch.setenv("TTP_MODE", "both")
    assert sel.ttp_mode() == "select"


# ── enrich_chunk in select mode ──────────────────────────────────────────────

_EXTRACTION = {"threat_actors": [], "malware_families": [], "tools": [], "relationships": [],
               "ttps": [{"technique_name": "PowerShell", "mitre_id": "T1059.001",
                         "description": "ran powershell", "evidence_text": "the macro ran PowerShell",
                         "evidence_label": "reported"}]}


@pytest.fixture()
def calls(monkeypatch):
    """_call_llm answers the extraction prompt, then the selection prompt."""
    from pipeline import stage3_llm as s3
    log: list[str] = []
    answers = {"select": '{"selected": []}'}

    def fake(system, user, provider=None):
        if system.startswith(sel._SELECT_SYSTEM):
            log.append("select")
            return answers["select"]
        log.append("extract")
        return json.dumps(_EXTRACTION)
    monkeypatch.setattr(s3, "_call_llm", fake)
    monkeypatch.setattr(s3, "_provider_ready", lambda provider=None: True)
    return log, answers


def test_select_mode_ships_only_what_the_selector_validated(calls):
    from pipeline.stage3_llm import enrich_chunk
    log, answers = calls
    answers["select"] = json.dumps({"selected": [
        {"attack_id": "T1105", "evidence_quote": "download a second-stage loader", "reason": "r"}]})
    retrieved = [TtpCandidate(attack_id="T1105", name="Ingress Tool Transfer", sources=["dense"])]
    res = enrich_chunk(TEXT, [], verify_ttps_on=True, verify_rels=False, ttp_mode="select",
                       ttp_candidates=retrieved)
    assert log == ["extract", "select"]
    # The LLM proposed T1059.001 but the selector did not choose it: gone.
    assert [t.mitre_id for t in res.ttps] == ["T1105"]


def test_select_mode_failure_reviews_instead_of_keeping(calls):
    from pipeline.stage3_llm import enrich_chunk
    _, answers = calls
    answers["select"] = ""
    res = enrich_chunk(TEXT, [], verify_ttps_on=True, verify_rels=False, ttp_mode="select")
    assert res.ttps == []
    assert [r.attack_id for r in res.ttp_review] == ["T1059.001"]


def test_select_mode_with_3f_off_passes_the_llm_unchecked(calls):
    from pipeline.stage3_llm import enrich_chunk
    log, _ = calls
    res = enrich_chunk(TEXT, [], verify_ttps_on=False, verify_rels=False, ttp_mode="select",
                       ttp_candidates=_cands("T1105"))
    assert log == ["extract"]
    assert [t.mitre_id for t in res.ttps] == ["T1059.001"]


def test_verify_mode_never_calls_the_selector(calls):
    from pipeline.stage3_llm import enrich_chunk
    log, _ = calls
    enrich_chunk(TEXT, [], verify_ttps_on=False, verify_rels=False, ttp_candidates=_cands("T1105"))
    assert "select" not in log


# ── The merge ────────────────────────────────────────────────────────────────

def test_review_is_merged_once_and_dropped_when_another_chunk_selected_it():
    from pipeline.stage3_llm import _merge_results
    from pipeline.stage3f_ttp_select import TtpReview
    a = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001",
                                               evidence_text="ran PowerShell")],
                            ttp_review=[TtpReview(attack_id="T1105", reason="x")])
    b = LLMEnrichmentResult(ttp_review=[TtpReview(attack_id="T1105", reason="y"),
                                        TtpReview(attack_id="T1059.001", reason="z")])
    merged = _merge_results([a, b])
    assert [r.attack_id for r in merged.ttp_review] == ["T1105"]
    assert merged.ttp_review[0].reason == "x"


# ── The orchestrator in select mode ──────────────────────────────────────────

def _run_opts(**kw):
    from pipeline.orchestrator import RunOptions
    kw.setdefault("disabled", frozenset({"2f", "4", "5"}))
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1,
                      verify_relationships=False, **kw)


def test_run_options_refuse_an_unknown_ttp_mode(monkeypatch):
    from pipeline.orchestrator import RunOptions
    with pytest.raises(ValueError):
        RunOptions(ttp_mode="both")
    assert RunOptions().ttp_mode == "select"
    monkeypatch.setenv("TTP_MODE", "verify")
    assert RunOptions.from_env().ttp_mode == "verify"


@pytest.fixture()
def select_pipeline(monkeypatch, mock_llm_response):
    """Retrieval stubbed to one candidate per chunk; the LLM answers the
    extraction prompt with the fixture and the selection prompt with
    `answer["select"]` (a callable of the excerpt)."""
    from pipeline import stage3_llm as s3
    from pipeline import ttp_retrieval as tr

    monkeypatch.setattr(tr, "retrieval_available", lambda: True)
    monkeypatch.setattr(tr, "candidates_for_chunks", lambda chunks: [
        [TtpCandidate(attack_id="T1190", name="Exploit Public-Facing Application", sources=["bm25"],
                      passage="CVE-2020-10148 was exploited for initial access.")] for _ in chunks])
    answer = {"select": lambda excerpt: '{"selected": []}'}
    prompts: list[str] = []

    def fake(system, user, provider=None):
        if system.startswith(sel._SELECT_SYSTEM):
            prompts.append(user)
            excerpt = user.split("---\n", 2)[1].rsplit("\n---", 1)[0]
            return answer["select"](excerpt)
        return json.dumps(mock_llm_response)
    monkeypatch.setattr(s3, "_call_llm", fake)
    return answer, prompts


def test_select_mode_retrieves_candidates_and_ships_only_selections(select_pipeline, sample_cti_text):
    from pipeline.orchestrator import Document, run_document
    answer, prompts = select_pipeline
    answer["select"] = lambda excerpt: json.dumps({"selected": [
        {"attack_id": "T1190", "evidence_quote": "CVE-2020-10148 was exploited for initial access",
         "reason": "exploited a public-facing flaw"}]})
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True))
    s2c = result.outcome("2c")
    assert s2c.status == "ran" and s2c.reason == "candidates only (select mode)"
    assert s2c.counts["candidates"] >= 1
    assert result.semantic_ttps == []                      # no technique straight from 2c
    assert "T1190" in prompts[0] and "T1566.001" in prompts[0]   # retrieved + LLM proposal
    ids = {t.mitre_id for t in result.llm_result.ttps}
    assert ids == {"T1190"}                                # the LLM's T1566.001 was not selected
    assert result.outcome("3f").status == "ran"


def test_select_mode_reports_a_selector_that_never_answers(select_pipeline, sample_cti_text):
    from pipeline.orchestrator import Document, run_document
    answer, _ = select_pipeline
    answer["select"] = lambda excerpt: "no"
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True))
    f = result.outcome("3f")
    assert f.status == "failed" and "review" in f.reason
    assert result.llm_result.ttps == []
    assert {r.attack_id for r in result.llm_result.ttp_review} == {"T1190", "T1566.001"}


def test_select_mode_without_an_llm_falls_back_and_says_so(monkeypatch, sample_cti_text):
    from models.schemas import EntityType, RawEntity
    from pipeline import stage2c_ttp_semantic as s2c
    from pipeline.orchestrator import Document, run_document

    monkeypatch.setattr("pipeline.stage3_llm._provider_ready", lambda provider=None: False)
    monkeypatch.setattr(s2c, "semantic_available", lambda: True)
    monkeypatch.setattr(s2c, "detect_ttps_semantic", lambda text: [
        RawEntity(value="Phishing", entity_type=EntityType.TTP, mitre_id="T1566", confidence=0.7,
                  source="semantic", context="spearphishing")])
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True))
    o = result.outcome("2c")
    assert o.status == "ran" and "offline fallback" in o.reason and "less reliable" in o.reason
    assert [e.mitre_id for e in result.semantic_ttps] == ["T1566"]


def test_select_mode_with_2c_off_still_selects_among_the_llm_proposals(select_pipeline, sample_cti_text):
    from pipeline.orchestrator import Document, run_document
    answer, prompts = select_pipeline
    answer["select"] = lambda excerpt: json.dumps({"selected": [
        {"attack_id": "T1566.001", "evidence_quote": "The threat actor used T1566.001 spearphishing"}]})
    result = run_document(Document(text=sample_cti_text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True,
                                    disabled=frozenset({"2c", "2f", "4", "5"})))
    assert "T1190" not in prompts[0]
    assert {t.mitre_id for t in result.llm_result.ttps} == {"T1566.001"}


def test_past_the_limit_retrieved_candidates_go_before_the_text_or_the_llm_proposals():
    seen = {}

    def fn(system, user):
        seen["user"] = user
        return '{"selected": []}'
    llm = TtpCandidate(attack_id="T1059.001", name="PowerShell", sources=["llm"])
    retrieved = [TtpCandidate(attack_id=f"T1{i:03d}", name="x" * 150, sources=["dense"], passage="y" * 150)
                 for i in range(100, 160)]
    out = sel.select_ttps(TEXT, [llm, *retrieved], fn, max_prompt_chars=6000)
    assert TEXT in seen["user"]                       # the evidence is whole
    assert "T1059.001" in seen["user"]                # the LLM's proposal is offered
    assert "T1100" in seen["user"] and "T1159" not in seen["user"]   # the lowest ranks go first
    assert len(seen["user"]) <= 6000
    assert out.status == sel.OK


def test_a_chunk_without_signals_but_with_candidates_gets_a_selection_only_call(
        select_pipeline, monkeypatch):
    from pipeline.orchestrator import Document, run_document
    answer, prompts = select_pipeline
    monkeypatch.setenv("TTP_SELECT_SKIPPED_CHUNKS", "true")
    answer["select"] = lambda excerpt: json.dumps({"selected": [
        {"attack_id": "T1190", "evidence_quote": "exploited the VPN appliance for initial access"}]})
    # No IoC and no entity name anywhere: Stage 3 skips the chunk.
    text = ("Overview of the intrusion. The operators exploited the VPN appliance for initial access, "
            "then moved between servers over several weeks before anyone noticed the activity at all.")
    result = run_document(Document(text=text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True))
    s3 = result.outcome("3")
    assert s3.counts["llm_calls"] == 0 and s3.counts["selection_only_chunks"] == 1
    assert len(prompts) == 1 and "T1566.001" not in prompts[0]     # no extraction, no LLM proposal
    assert {t.mitre_id for t in result.llm_result.ttps} == {"T1190"}


def test_selection_only_calls_are_opt_in(select_pipeline, monkeypatch):
    from pipeline.orchestrator import Document, run_document
    _, prompts = select_pipeline
    monkeypatch.delenv("TTP_SELECT_SKIPPED_CHUNKS", raising=False)
    text = ("Overview of the intrusion. The operators exploited the VPN appliance for initial access, "
            "then moved between servers over several weeks before anyone noticed the activity at all.")
    result = run_document(Document(text=text, original_filename="r.txt"),
                          _run_opts(ttp_mode="select", verify_ttps=True))
    assert prompts == [] and result.outcome("3").counts["skipped_chunks"] == 1
