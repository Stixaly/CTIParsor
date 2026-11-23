"""Issue #995 — an embedded data file that cannot be read is reported, not silent.

The warning lists (benign.py), the revoked ATT&CK ids (mitre_db.py) and the ATT&CK
reference pairs of Stage 4b say why they are unreadable (`load_error()`,
`revoked_error()`, `attack_pairs_error()`), and a failed read is never cached: a
file that is readable again is loaded.  The orchestrator records Stage 4 failed
(warning lists) or degraded (revoked ids), and Stage 4b degraded (pairs).
"""
import json
from unittest.mock import Mock

import pytest

from models.schemas import EntityType
from pipeline import benign, mitre_db
from pipeline import orchestrator as orch
from pipeline import stage4b_graph_completion as s4b
from pipeline.orchestrator import DEGRADED, FAILED, RAN, Document, RunOptions, StageRequired, run_document


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _opts(**kw) -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    kw.setdefault("disabled", frozenset({"2f"}))   # the CVE cache needs a database
    kw.setdefault("verify_relationships", False)
    kw.setdefault("verify_ttps", False)
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, **kw)


# ── benign: the warning lists ────────────────────────────────────────────────

@pytest.fixture()
def lists_file(tmp_path, monkeypatch):
    """The warning lists read from a temporary file; no cached read outlives the test."""
    path = tmp_path / "warninglists.json"
    monkeypatch.setattr(benign, "_PATH", path)
    benign._lists.cache_clear()
    yield path
    benign._lists.cache_clear()


def test_corrupt_warning_lists_are_reported_and_apply_nothing(lists_file):
    lists_file.write_text("{not json", encoding="utf-8")
    assert "unreadable" in benign.load_error()
    assert benign._lists() == {}


@pytest.mark.parametrize("content, reason", [
    ("[]", "warninglists.json holds no `lists` object"),                   # not an object
    ('{"other": 1}', "warninglists.json holds no `lists` object"),          # no lists
    ('{"lists": {}}', "warninglists.json holds no `lists` object"),        # no list at all
    ('{"lists": {"tranco10k": ["x"]}}', "warninglists.json has a malformed list"),
])
def test_a_malformed_warning_list_file_is_reported(lists_file, content, reason):
    lists_file.write_text(content, encoding="utf-8")
    assert benign.load_error().startswith(reason)
    assert benign._lists() == {}


def test_a_failed_warning_list_read_is_not_cached(lists_file):
    lists_file.write_text("{not json", encoding="utf-8")
    assert benign.load_error() is not None

    # The same path, now readable: the earlier failure must not be kept.
    lists_file.write_text(json.dumps({"lists": {"tranco10k": {"values": ["example.org"]}}}),
                          encoding="utf-8")
    assert benign.load_error() is None
    assert benign._lists()["tranco10k"] == frozenset({"example.org"})
    assert benign.benign_reason(EntityType.DOMAIN, "example.org") == "popular_domain:tranco10k"


def test_the_shipped_warning_lists_are_readable():
    benign._lists.cache_clear()
    assert benign.load_error() is None
    assert benign._lists()


# ── mitre_db: the revoked ids ────────────────────────────────────────────────

@pytest.fixture()
def revoked_file(tmp_path, monkeypatch):
    path = tmp_path / "attack_revoked.json"
    monkeypatch.setattr(mitre_db, "_REVOKED_PATH", path)
    monkeypatch.setattr(mitre_db.attack_data, "resolve", lambda p: p)
    mitre_db._revoked.cache_clear()
    yield path
    mitre_db._revoked.cache_clear()


def test_corrupt_revoked_file_is_reported_and_replaces_nothing(revoked_file):
    revoked_file.write_text("{not json", encoding="utf-8")
    assert "unreadable" in mitre_db.revoked_error()
    assert mitre_db.replacement_for("T0001") is None


def test_a_revoked_file_that_is_not_an_object_is_reported(revoked_file):
    revoked_file.write_text("[]", encoding="utf-8")
    assert mitre_db.revoked_error() == "attack_revoked.json is not a JSON object"
    assert mitre_db.revoked_names() == {}


def test_a_failed_revoked_read_is_not_cached(revoked_file):
    revoked_file.write_text("{not json", encoding="utf-8")
    assert mitre_db.revoked_error() is not None

    # The same path, now readable: the earlier failure must not be kept.
    revoked_file.write_text(json.dumps({"revoked_by": {"T0001": "T9999"}, "names": {}}), encoding="utf-8")
    assert mitre_db.revoked_error() is None
    assert mitre_db.replacement_for("t0001") == "T9999"


def test_a_good_revoked_read_stays_cached(revoked_file):
    revoked_file.write_text(json.dumps({"revoked_by": {"T0001": "T9999"}, "names": {}}), encoding="utf-8")
    assert mitre_db.revoked_error() is None
    revoked_file.write_text("{not json", encoding="utf-8")   # the cached success is kept
    assert mitre_db.revoked_error() is None
    assert mitre_db.replacement_for("T0001") == "T9999"


def test_the_shipped_revoked_file_is_readable():
    mitre_db._revoked.cache_clear()
    assert mitre_db.revoked_error() is None


# ── stage 4b: the ATT&CK reference pairs ─────────────────────────────────────

@pytest.fixture()
def pairs_file(tmp_path, monkeypatch):
    path = tmp_path / "attack_relationships.json"
    monkeypatch.setattr(s4b, "_ATTACK_REL_PATH", path)
    monkeypatch.setattr(s4b.attack_data, "resolve", lambda p: p)
    s4b._attack_pairs.cache_clear()
    yield path
    s4b._attack_pairs.cache_clear()


def test_corrupt_pairs_file_is_reported_and_yields_no_pair(pairs_file):
    pairs_file.write_text("{not json", encoding="utf-8")
    assert "unreadable" in s4b.attack_pairs_error()
    assert s4b._attack_pairs() == {}


@pytest.mark.parametrize("content, reason", [
    ("[]", "attack_relationships.json is not a JSON object"),
    ('{"pairs": [["G9999"]]}', "attack_relationships.json has a malformed pair"),
])
def test_a_malformed_pairs_file_is_reported(pairs_file, content, reason):
    pairs_file.write_text(content, encoding="utf-8")
    assert s4b.attack_pairs_error().startswith(reason)
    assert s4b._attack_pairs() == {}


def test_a_failed_pairs_read_is_not_cached(pairs_file):
    pairs_file.write_text("{not json", encoding="utf-8")
    assert s4b.attack_pairs_error() is not None

    # The same path, now readable: the earlier failure must not be kept.
    pairs_file.write_text(json.dumps({"pairs": [["G9999", "uses", "T9999"]]}), encoding="utf-8")
    assert s4b.attack_pairs_error() is None
    assert s4b._attack_pairs() == {("G9999", "T9999"): "uses"}


def test_the_shipped_pairs_file_is_readable():
    s4b._attack_pairs.cache_clear()
    assert s4b.attack_pairs_error() is None


# ── orchestrator ─────────────────────────────────────────────────────────────

def test_unreadable_warning_lists_fail_stage_4_before_the_bundle(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.benign.load_error", lambda: "warninglists.json unreadable: boom")
    build = Mock(side_effect=AssertionError("the bundle must not be built"))
    monkeypatch.setattr(orch, "build_bundle", build)

    with pytest.raises(StageRequired) as err:
        run_document(Document(text=sample_cti_text), _opts(required=frozenset({"4"})))

    assert err.value.outcome.stage == "4" and err.value.outcome.status == FAILED
    assert err.value.outcome.reason == "benign warning lists unreadable: warninglists.json unreadable: boom"
    assert build.call_count == 0


def test_unreadable_warning_lists_stop_the_run_without_a_required_stage(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.benign.load_error", lambda: "warninglists.json unreadable: boom")

    with pytest.raises(StageRequired) as err:
        run_document(Document(text=sample_cti_text), _opts())

    assert err.value.outcome.stage == "4" and err.value.outcome.status == FAILED


def test_unreadable_warning_lists_do_not_matter_when_the_filter_is_off(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.benign.load_error", lambda: "warninglists.json unreadable: boom")
    monkeypatch.setattr("pipeline.benign.enabled", lambda: False)

    result = run_document(Document(text=sample_cti_text), _opts())

    assert result.outcome("4").status == RAN and result.bundle is not None


def test_unreadable_revoked_ids_degrade_stage_4(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.mitre_db.revoked_error", lambda: "attack_revoked.json unreadable: boom")

    result = run_document(Document(text=sample_cti_text), _opts())

    stage4 = result.outcome("4")
    assert stage4.status == DEGRADED
    assert stage4.reason == "revoked ATT&CK ids not replaced: attack_revoked.json unreadable: boom"
    assert result.ran("4") and result.bundle is not None


def test_unreadable_attack_pairs_degrade_stage_4b(mock_llm, sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage4b_graph_completion.attack_pairs_error",
                        lambda: "attack_relationships.json unreadable: boom")

    result = run_document(Document(text=sample_cti_text), _opts())

    stage4b = result.outcome("4b")
    assert stage4b.status == DEGRADED
    assert stage4b.reason == ("ATT&CK reference pairs unreadable, no reference edge added: "
                              "attack_relationships.json unreadable: boom")
    assert result.ran("4b")


def test_an_ordinary_run_leaves_stages_4_and_4b_ran(mock_llm, sample_cti_text):
    result = run_document(Document(text=sample_cti_text), _opts())

    assert result.outcome("4").status == RAN and result.outcome("4").reason == ""
    assert result.outcome("4b").status == RAN and result.outcome("4b").reason == ""
