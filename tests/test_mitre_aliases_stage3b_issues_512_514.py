"""pipeline/mitre_db.py, pipeline/aliases.py, pipeline/stage3b_validate.py — issues #512, #513, #514.

#512: get_tactics() handed out the cached list; lookup_by_id(None) and search(None) crashed.
#513: a non-object mitre_index.json (`[]`, `null`) crashed aliases' readers.
#514: validate_llm_result(doc_context=None) crashed on the campaign word-level fallback.
"""
from __future__ import annotations

import json

import pytest

from pipeline import aliases, mitre_db
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage3b_validate import validate_llm_result

_TACTICS = [{"id": "TA0002", "name": "Execution"}]
_TECHNIQUES = [{"id": "T1059", "name": "Command and Scripting Interpreter", "domain": "enterprise-attack"}]


@pytest.fixture()
def mitre_index_at(tmp_path, monkeypatch):
    """Point mitre_db and aliases at one index file; write `content` into it and clear both caches."""
    path = tmp_path / "mitre_index.json"
    monkeypatch.setattr(mitre_db, "_INDEX_PATH", path)
    monkeypatch.setattr(aliases, "_MITRE_INDEX", path)

    def write(content: str) -> None:
        path.write_text(content, encoding="utf-8")
        mitre_db._load.cache_clear()
        aliases._load_techniques.cache_clear()
        aliases._tactic_ids.cache_clear()

    yield write
    mitre_db._load.cache_clear()
    aliases._load_techniques.cache_clear()
    aliases._tactic_ids.cache_clear()


# ── #512 ─────────────────────────────────────────────────────────────────────

def test_a_caller_clearing_its_tactics_does_not_empty_the_cache(mitre_index_at):
    """Issue #512: get_tactics() returned the cached list, so clear() emptied the process-wide index."""
    mitre_index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": _TACTICS}))
    mitre_db.get_tactics().clear()
    assert [t["id"] for t in mitre_db.get_tactics()] == ["TA0002"]
    assert mitre_db.lookup_by_id("TA0002")["name"] == "Execution"


def test_get_tactics_returns_a_new_list_each_time(mitre_index_at):
    """Issue #512: same contract as get_techniques(); the dicts stay shared, the list does not."""
    mitre_index_at(json.dumps({"techniques": [], "tactics": _TACTICS}))
    assert mitre_db.get_tactics() is not mitre_db.get_tactics()
    assert mitre_db.get_tactics() == _TACTICS


@pytest.mark.parametrize("bad", [None, 42, ["T1059"]])
def test_lookup_by_id_of_a_non_string_is_none_not_a_crash(mitre_index_at, bad):
    """Issue #512: lookup_by_id(None) raised AttributeError on .strip()."""
    mitre_index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": _TACTICS}))
    assert mitre_db.lookup_by_id(bad) is None
    # Control: a real string still resolves.
    assert mitre_db.lookup_by_id("T1059")["id"] == "T1059"


@pytest.mark.parametrize("bad", [None, 42, ["t1"]])
def test_search_of_a_non_string_is_empty_not_a_crash(mitre_index_at, bad):
    """Issue #512: search(None) raised AttributeError on .lower()."""
    mitre_index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": _TACTICS}))
    assert mitre_db.search(bad) == []
    # Control: a real query still finds the technique.
    assert [e["id"] for e in mitre_db.search("t1059")] == ["T1059"]


# ── #513 ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("content", ["[]", "null", '"text"', "42"])
def test_aliases_treats_a_non_object_index_as_unreadable(mitre_index_at, content):
    """Issue #513: a valid JSON that is not an object crashed _load_techniques and _tactic_ids
    with AttributeError; it is now read like a missing or unreadable file: nothing resolves."""
    mitre_index_at(content)
    assert aliases.technique_id_for("Command and Scripting Interpreter") is None
    assert aliases.technique_name_for("T1059") is None
    assert aliases.is_attack_id("T1059") is False
    assert aliases.is_attack_id("TA0002") is False


def test_aliases_still_resolves_from_an_object_index(mitre_index_at):
    """Issue #513 control: a well-formed index keeps resolving names and ids."""
    mitre_index_at(json.dumps({"techniques": _TECHNIQUES, "tactics": _TACTICS}))
    assert aliases.technique_id_for("command and scripting interpreter") == "T1059"
    assert aliases.is_attack_id("TA0002") is True


# ── #514 ─────────────────────────────────────────────────────────────────────

def test_a_campaign_with_doc_context_none_is_checked_like_an_empty_context():
    """Issue #514: doc_context=None raised TypeError in the campaign keyword fallback.
    It must give the same answer as doc_context=""."""
    def run(doc_context):
        result = LLMEnrichmentResult(campaign_name="Operation Ghost Storm")
        return validate_llm_result(result, chunk_text="Operation Ghost", doc_context=doc_context)

    with_none = run(None)
    assert with_none.campaign_name == run("").campaign_name == "Operation Ghost Storm"


def test_a_campaign_with_no_keyword_in_the_text_is_dropped_when_doc_context_is_none():
    """Issue #514 control: None still drops a campaign that shares no keyword with the source."""
    result = LLMEnrichmentResult(campaign_name="Operation Silent Harbor")
    kept = validate_llm_result(result, chunk_text="Operation Ghost", doc_context=None)
    assert kept.campaign_name is None
