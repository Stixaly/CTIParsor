"""Two user settings that could stay without effect with nothing in the stage
report (issue #999, ADR-0104).

- The `alias_list` threshold for threat_actor above Stage 2g's confidence cuts
  the stage: it is recorded `skipped` with the reason, not `ran` with 0 entities.
- A TTP_RETRIEVAL_EXCLUDE_CITED file that cannot be read gives a reason through
  exclusions_error(), and a retriever built while it is unreadable is not cached.
"""
import json

import pytest

import pipeline.thresholds as thresholds
from pipeline import calibration as cal
from pipeline import stage2g_alias_list as sut
from pipeline import ttp_retrieval as tr
from pipeline.orchestrator import RAN, SKIPPED, Document, RunOptions, run_document


@pytest.fixture(autouse=True)
def _fresh_cache():
    thresholds.reload()
    yield
    thresholds.reload()


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _opts() -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1,
                      disabled=frozenset({"2f"}), verify_relationships=False, verify_ttps=False)


def _a_report(tmp_path) -> str:
    report = tmp_path / "report.txt"
    report.write_text("Static Tundra (aka Berserk Bear) struck the ministry.", encoding="utf-8")
    return str(report)


# ── 2g: the policy threshold ─────────────────────────────────────────────────

def test_a_threshold_above_the_stage_confidence_gives_a_reason(temp_db):
    cal.set_override(temp_db.get_conn(), "alias_list", "threat_actor", 0.6, temp_db.now_iso())
    thresholds.reload()
    assert sut.policy_cut_reason() == (
        "the policy threshold for alias_list/threat_actor (0.6) is above this stage's "
        "confidence (0.55): nothing it finds could pass")
    assert sut.extract_alias_list_entities("Static Tundra (aka Berserk Bear) struck.") == []


def test_a_threshold_at_or_below_the_stage_confidence_gives_no_reason(temp_db):
    cal.set_override(temp_db.get_conn(), "alias_list", "threat_actor", 0.55, temp_db.now_iso())
    thresholds.reload()
    assert sut.policy_cut_reason() is None
    assert len(sut.extract_alias_list_entities("Static Tundra (aka Berserk Bear) struck.")) == 2


def test_the_policy_cut_is_read_on_each_call_after_reload(temp_db):
    assert sut.policy_cut_reason() is None
    cal.set_override(temp_db.get_conn(), "alias_list", "threat_actor", 0.7, temp_db.now_iso())
    thresholds.reload()
    assert sut.policy_cut_reason() is not None


def test_a_policy_cut_records_stage_2g_skipped_with_the_reason(temp_db, tmp_path, mock_llm):
    cal.set_override(temp_db.get_conn(), "alias_list", "threat_actor", 0.6, temp_db.now_iso())
    thresholds.reload()

    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage2g = result.outcome("2g")
    assert stage2g.status == SKIPPED
    assert stage2g.reason == sut.policy_cut_reason()
    assert stage2g.counts == {"entities": 0}
    assert result.llm_result is not None                 # the run goes on without the stage


def test_without_a_policy_cut_stage_2g_runs(temp_db, tmp_path, mock_llm):
    result = run_document(Document(file_path=_a_report(tmp_path)), _opts())

    stage2g = result.outcome("2g")
    assert stage2g.status == RAN
    assert stage2g.reason == ""
    assert stage2g.counts == {"entities": 2}


# ── TTP_RETRIEVAL_EXCLUDE_CITED ──────────────────────────────────────────────

def test_an_unreadable_exclusions_file_gives_a_reason(monkeypatch, tmp_path):
    missing = tmp_path / "absent.txt"
    monkeypatch.setenv("TTP_RETRIEVAL_EXCLUDE_CITED", str(missing))
    reason = tr.exclusions_error()
    assert reason is not None
    assert reason.startswith(f"TTP_RETRIEVAL_EXCLUDE_CITED={missing} cannot be read (FileNotFoundError: ")
    assert reason.endswith("): nothing excluded")
    assert tr._exclusions(str(missing)) == []


def test_no_exclusions_setting_gives_no_reason(monkeypatch):
    monkeypatch.delenv("TTP_RETRIEVAL_EXCLUDE_CITED", raising=False)
    assert tr.exclusions_error() is None


def test_a_readable_exclusions_file_gives_no_reason_and_its_lines_are_excluded(monkeypatch, tmp_path):
    cited = tmp_path / "cited.txt"
    cited.write_text("report-cited-one\n\n  report-cited-two  \n", encoding="utf-8")
    monkeypatch.setenv("TTP_RETRIEVAL_EXCLUDE_CITED", str(cited))
    assert tr.exclusions_error() is None
    assert tr._exclusions(str(cited)) == ["report-cited-one", "report-cited-two"]

    entries = [
        {"id": "T1105", "name": "Ingress Tool Transfer", "kind": "procedure", "domain": "enterprise-attack",
         "text": "The loader fetched a second stage.", "urls": ["https://example.org/report-cited-one"]},
        {"id": "T1566", "name": "Phishing", "kind": "procedure", "domain": "enterprise-attack",
         "text": "A phishing mail was sent.", "urls": ["https://example.org/report-other"]},
    ]
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps({"manifest": {"version": "v-test", "model": ""}, "entries": entries}))
    monkeypatch.setenv("TTP_SEMANTIC_DOMAINS", "all")
    tr._built_corpus.cache_clear()
    corpus = tr.load_corpus("procedure", path=path, emb_path=tmp_path / "absent.npy",
                            exclude_cited=tr._exclusions(str(cited)))
    assert corpus.ids == ["T1566"]


def test_a_retriever_built_while_the_exclusions_are_unreadable_is_not_cached(monkeypatch, tmp_path):
    cited = tmp_path / "cited.txt"                       # absent for now
    monkeypatch.setenv("TTP_RETRIEVAL_EXCLUDE_CITED", str(cited))
    seen = []

    def fake_corpus(kind, *, exclude_cited=()):
        seen.append(list(exclude_cited))
        return tr.Corpus(ids=["T1105"], names=["Ingress Tool Transfer"], kinds=["procedure"],
                         domains=["enterprise-attack"], texts=["The loader fetched a second stage."],
                         urls=[[]], embeddings=None, model="", version="test")

    monkeypatch.setattr(tr, "load_corpus", fake_corpus)
    tr._production_retriever.cache_clear()
    try:
        assert tr._current_retriever("both", "bm25", str(cited)) is not None
        assert seen == [[]]                              # unreadable: nothing excluded, reason given
        cited.write_text("report-cited-one\n", encoding="utf-8")
        assert tr._current_retriever("both", "bm25", str(cited)) is not None
        assert seen == [[], ["report-cited-one"]]        # rebuilt once the file is readable
    finally:
        tr._production_retriever.cache_clear()
