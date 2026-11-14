"""Regression tests for three Stage 3 bugs found in the 2026-11 triage.

#772 — a `null` on a field with a non-null default cost the whole TTP or
relationship, and a TTP given only by its MITRE id was dropped before stage3c
could resolve its name.
#773 — a second chunk's evidence quote was lost when the first chunk had the
same technique without an id.
#776 — a MITRE id with surrounding spaces skipped the direct id lookup.
"""
from __future__ import annotations

import logging

from pipeline import stage3c_mitre
from pipeline.stage3_llm import (
    LLMEnrichmentResult,
    TTPExtracted,
    _merge_results,
    _parse_llm_response,
)

QUOTE = "The actor sent spearphishing emails to the finance team."


# --- #772 ------------------------------------------------------------------

def test_772_null_description_and_confidence_do_not_drop_the_entries():
    raw = (
        '{"ttps": [{"technique_name": "Phishing", "mitre_id": "T1566", '
        '"description": null, "evidence_text": "Sent phishing emails."}], '
        '"relationships": [{"source_value": "APT29", "relationship_type": "uses", '
        '"target_value": "Mimikatz", "confidence": null}]}'
    )
    result = _parse_llm_response(raw)
    assert [t.mitre_id for t in result.ttps] == ["T1566"]
    assert result.ttps[0].description == ""
    assert len(result.relationships) == 1
    assert result.relationships[0].confidence == 0.8


def test_772_a_ttp_given_only_by_its_mitre_id_is_kept():
    raw = '{"ttps": [{"mitre_id": "T1059.001"}]}'
    result = _parse_llm_response(raw)
    assert len(result.ttps) == 1
    assert result.ttps[0].mitre_id == "T1059.001"
    assert result.ttps[0].technique_name == ""


def test_772_a_ttp_with_neither_name_nor_id_is_still_dropped():
    raw = '{"ttps": [{"description": "something vague"}]}'
    result = _parse_llm_response(raw)
    assert result.ttps == []


def test_772_an_id_only_ttp_is_resolved_by_stage3c_when_known(monkeypatch):
    index = {"t1566": {"name": "Phishing", "id": "T1566", "url": "u1566"}}
    monkeypatch.setattr(stage3c_mitre, "_load_index", lambda: index)
    ttp = TTPExtracted(technique_name="", mitre_id="T1566")
    out = stage3c_mitre.normalize_ttps([ttp])
    assert [(t.technique_name, t.mitre_id) for t in out] == [("Phishing", "T1566")]


def test_772_an_unknown_id_with_no_name_is_discarded_by_stage3c(monkeypatch):
    index = {"t1566": {"name": "Phishing", "id": "T1566", "url": "u1566"}}
    monkeypatch.setattr(stage3c_mitre, "_load_index", lambda: index)
    ttp = TTPExtracted(technique_name="", mitre_id="T1234")
    assert stage3c_mitre.normalize_ttps([ttp]) == []


def test_772_the_discarded_unknown_id_is_logged_by_stage3c(monkeypatch, caplog):
    index = {"t1566": {"name": "Phishing", "id": "T1566", "url": "u1566"}}
    monkeypatch.setattr(stage3c_mitre, "_load_index", lambda: index)
    ttp = TTPExtracted(technique_name="", mitre_id="T1234")
    with caplog.at_level(logging.DEBUG, logger="pipeline.stage3c_mitre"):
        stage3c_mitre.normalize_ttps([ttp])
    assert "TTP discarded" in caplog.text
    assert "T1234" in caplog.text


# --- #773 ------------------------------------------------------------------

def test_773_quote_of_a_later_chunk_survives_an_id_less_first_chunk():
    r1 = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="Phishing")])
    r2 = LLMEnrichmentResult(ttps=[TTPExtracted(
        technique_name="Phishing", evidence_text=QUOTE)])
    merged = _merge_results([r1, r2])
    assert len(merged.ttps) == 1
    assert merged.ttps[0].evidence_text == QUOTE


# --- #776 ------------------------------------------------------------------

def test_776_a_padded_mitre_id_is_looked_up_directly(monkeypatch):
    index = {
        "t1566": {"name": "Phishing", "id": "T1566", "url": "u1566"},
        "t1190": {"name": "Exploit Public-Facing Application", "id": "T1190", "url": "u1190"},
        # The fuzzy path would answer T1190 here: the name matches it exactly.
        "suspicious email": {"name": "Exploit Public-Facing Application", "id": "T1190", "url": "u1190"},
    }
    monkeypatch.setattr(stage3c_mitre, "_load_index", lambda: index)

    def no_fuzzy(*args, **kwargs):
        raise AssertionError("the fuzzy name match must not run for a known id")

    monkeypatch.setattr(stage3c_mitre.rfprocess, "extractOne", no_fuzzy)
    assert stage3c_mitre._resolve("Suspicious Email", " T1566 ") == (
        "Phishing", "T1566", "u1566")
