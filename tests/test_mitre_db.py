"""pipeline/mitre_db.py — the ATT&CK + CAPEC index behind Stage 3c and search."""
from __future__ import annotations

import json

import pytest

from pipeline import mitre_db

_INDEX = {
    "tactics": [
        {"id": "TA0001", "name": "Initial Access", "shortname": "initial-access"},
        {"id": "TA0002", "name": "Execution", "shortname": "execution"},
    ],
    "techniques": [
        {"id": "T1566", "name": "Phishing"},
        {"id": "T1566.001", "name": "Spearphishing Attachment"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
        {"id": "T1204", "name": "User Execution"},
        {"id": "CAPEC-98", "name": "Phishing"},
    ],
}


@pytest.fixture()
def index(tmp_path, monkeypatch):
    """Point the module at a small index; the lru_cache is cleared both ways so
    neither this fixture nor the real index leaks into another test."""
    path = tmp_path / "mitre_index.json"
    path.write_text(json.dumps(_INDEX), encoding="utf-8")
    monkeypatch.setattr(mitre_db, "_INDEX_PATH", path)
    mitre_db._load.cache_clear()
    yield path
    mitre_db._load.cache_clear()


def test_lookup_is_case_insensitive_and_checks_tactics_first(index):
    assert mitre_db.lookup_by_id("ta0002")["name"] == "Execution"
    assert mitre_db.lookup_by_id("t1566.001")["name"] == "Spearphishing Attachment"
    assert mitre_db.lookup_by_id("capec-98")["id"] == "CAPEC-98"
    assert mitre_db.lookup_by_id("T9999") is None


def test_search_ranks_id_prefix_matches_before_name_matches(index):
    ids = [e["id"] for e in mitre_db.search("t1566")]
    assert ids == ["T1566", "T1566.001"]

    # "execution" is TA0002's name and T1204's: the tactic comes first.
    assert [e["id"] for e in mitre_db.search("  Execution ")] == ["TA0002", "T1204"]


def test_search_lists_each_entry_once_and_honours_the_limit(index):
    # "phishing" matches T1566 and T1566.001 by name, CAPEC-98 too.
    ids = [e["id"] for e in mitre_db.search("phishing")]
    assert ids == ["T1566", "T1566.001", "CAPEC-98"]
    assert len(mitre_db.search("t", limit=2)) == 2


def test_an_empty_query_finds_nothing(index):
    assert mitre_db.search("   ") == []


def test_a_missing_index_is_empty_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(mitre_db, "_INDEX_PATH", tmp_path / "absent.json")
    mitre_db._load.cache_clear()
    try:
        assert mitre_db.available() is False
        assert mitre_db.get_techniques() == [] and mitre_db.get_tactics() == []
        assert mitre_db.lookup_by_id("T1566") is None
    finally:
        mitre_db._load.cache_clear()


@pytest.mark.parametrize("content", ["{not json", json.dumps({"something": "else"})])
def test_a_corrupt_or_wrong_shape_index_is_empty(tmp_path, monkeypatch, content):
    path = tmp_path / "mitre_index.json"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(mitre_db, "_INDEX_PATH", path)
    mitre_db._load.cache_clear()
    try:
        assert mitre_db.available() is True
        assert mitre_db.get_techniques() == [] and mitre_db.get_tactics() == []
        assert mitre_db.search("t1") == []
    finally:
        mitre_db._load.cache_clear()


def test_the_shipped_index_has_the_attack_ids_the_pipeline_relies_on():
    mitre_db._load.cache_clear()
    if not mitre_db.available():
        pytest.skip("pipeline/data/mitre_index.json not built")
    assert mitre_db.lookup_by_id("TA0001")["name"] == "Initial Access"
    assert mitre_db.lookup_by_id("T1566.001")["name"] == "Spearphishing Attachment"
