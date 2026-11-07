"""pipeline/mitre_db.py — issue #404: a wrong-shape index, a mutated cache, a padded id."""
from __future__ import annotations

import json

import pytest

from pipeline import mitre_db

_TECHNIQUES = [{"id": "T1059", "name": "Command and Scripting Interpreter"}]


@pytest.fixture()
def index_at(tmp_path, monkeypatch):
    """Write `content` as the index file and point the module at it (cache emptied both ways)."""
    path = tmp_path / "mitre_index.json"
    monkeypatch.setattr(mitre_db, "_INDEX_PATH", path)

    def write(content: str) -> None:
        path.write_text(content, encoding="utf-8")
        mitre_db._load.cache_clear()

    yield write
    mitre_db._load.cache_clear()


@pytest.mark.parametrize("content", ["null", "[]", '"text"', "42"])
def test_a_valid_json_index_of_the_wrong_shape_is_empty_not_a_crash(index_at, content):
    """Issue #404: `null` or `[]` made every getter raise AttributeError."""
    index_at(content)
    assert mitre_db.get_techniques() == []
    assert mitre_db.get_tactics() == []
    assert mitre_db.lookup_by_id("T1059") is None
    assert mitre_db.search("t1") == []


@pytest.mark.parametrize("content", [
    json.dumps({"techniques": None, "tactics": []}),
    json.dumps({"techniques": {"id": "T1059"}, "tactics": []}),
])
def test_an_index_whose_lists_are_not_lists_is_empty(index_at, content):
    index_at(content)
    assert mitre_db.get_techniques() == []
    assert mitre_db.lookup_by_id("T1059") is None


def test_a_caller_clearing_its_techniques_does_not_empty_the_cache(index_at):
    """Issue #404: get_techniques() returned the cached list itself."""
    index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": []}))
    mine = mitre_db.get_techniques()
    mine.clear()
    assert [t["id"] for t in mitre_db.get_techniques()] == ["T1059"]
    assert mitre_db.lookup_by_id("T1059")["name"] == "Command and Scripting Interpreter"


def test_get_techniques_returns_a_new_list_each_time(index_at):
    index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": []}))
    assert mitre_db.get_techniques() is not mitre_db.get_techniques()
    assert mitre_db.get_techniques() == _TECHNIQUES


def test_lookup_by_id_ignores_surrounding_spaces(index_at):
    """Issue #404: lookup_by_id(' t1059 ') returned None."""
    index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": []}))
    assert mitre_db.lookup_by_id(" t1059 ")["id"] == "T1059"
    assert mitre_db.lookup_by_id("\tT1059\n")["id"] == "T1059"
    # Control: the plain spelling still works, and an absent id is still None.
    assert mitre_db.lookup_by_id("t1059")["id"] == "T1059"
    assert mitre_db.lookup_by_id(" T9999 ") is None
