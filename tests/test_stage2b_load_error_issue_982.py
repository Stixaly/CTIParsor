"""Stage 2b — issue #982 point 4: an unreadable embedded gazetteer is reported by
load_error() instead of matching nothing silently, and a failed read is never
cached.
"""
from __future__ import annotations

import json

import pytest

from pipeline import stage2b_gazetteer as gaz


@pytest.fixture()
def index_file(tmp_path, monkeypatch):
    """The index read from a temporary file; no cached read outlives the test."""
    path = tmp_path / "gazetteer.json"
    monkeypatch.setattr(gaz, "_INDEX_PATH", path)
    gaz._read_index.cache_clear()
    yield path
    gaz._read_index.cache_clear()


def test_a_corrupt_file_is_reported_and_matches_nothing(index_file):
    index_file.write_text("{not json", encoding="utf-8")
    assert "not valid JSON" in gaz.load_error()
    assert gaz._load() == []
    assert gaz.match_gazetteer("The Lazarus Group deployed WannaCry.") == []


@pytest.mark.parametrize("content, reason", [
    (None, "gazetteer.json not found"),
    ("[]", "gazetteer.json holds no entry"),
])
def test_a_missing_or_empty_file_is_reported(index_file, content, reason):
    if content is not None:
        index_file.write_text(content, encoding="utf-8")
    else:
        assert not index_file.exists()
    assert gaz.load_error() == reason


def test_a_failure_is_not_cached(index_file):
    index_file.write_text("{not json", encoding="utf-8")
    assert "not valid JSON" in gaz.load_error()

    # The same path, now readable: the earlier failure must not be kept.
    index_file.write_text(json.dumps([{"name": "wannacry", "canonical": "WannaCry",
                                       "entity_type": "malware", "mitre_id": "S0366"}]),
                          encoding="utf-8")
    assert gaz.load_error() is None
    assert "WannaCry" in {e["canonical"] for e in gaz._load()}


def test_the_shipped_gazetteer_is_readable():
    if not gaz.available():
        pytest.skip("gazetteer.json not built")
    gaz._read_index.cache_clear()
    assert gaz.load_error() is None
