"""Stage 2b — gazetteer matching with the analyst-promoted overlay and the
deny list (ADR-0052), on both the Aho-Corasick path and the regex fallback.
"""
from __future__ import annotations

import pytest

import pipeline.overrides as ov
from models.schemas import EntityType
from pipeline import promotion as pm
from pipeline import stage2b_gazetteer as gaz

pytestmark = pytest.mark.skipif(not gaz.available(), reason="gazetteer.json not built")


@pytest.fixture(params=["aho", "regex"])
def matcher(request, monkeypatch):
    """Run each test on both matching paths."""
    if request.param == "regex":
        monkeypatch.setattr(gaz, "_AHO_AVAILABLE", False)
    ov.reload()          # rebuild the automaton / entry list under the patched flag
    return request.param


def test_base_index_still_matches(matcher):
    results = gaz.match_gazetteer("The Lazarus Group deployed WannaCry against the target.")
    found = {(r.value, r.entity_type) for r in results}
    assert ("Lazarus Group", EntityType.THREAT_ACTOR) in found
    assert ("WannaCry", EntityType.MALWARE) in found


def test_a_promoted_term_is_matched_at_gazetteer_confidence(temp_db, matcher):
    pm.add_manual(temp_db.get_conn(), "ArguePatch", "malware", "promote", temp_db.now_iso(), display="ARGUEPATCH")
    ov.reload()

    [r] = gaz.match_gazetteer("The ARGUEPATCH loader was recovered from the host.")
    assert (r.value, r.entity_type, r.source, r.confidence, r.mitre_id) == \
        ("ARGUEPATCH", EntityType.MALWARE, "gazetteer", 0.92, None)
    assert "ARGUEPATCH" in r.context

    # Whole-word only, like every other gazetteer entry.
    assert gaz.match_gazetteer("ARGUEPATCHX is unrelated.") == []


def test_a_promoted_term_does_not_shadow_a_longer_base_name(temp_db, matcher):
    # "lazarus" alone is promoted; "Lazarus Group" in the text must still win as the longer match.
    pm.add_manual(temp_db.get_conn(), "Lazarus", "threat_actor", "promote", temp_db.now_iso())
    ov.reload()
    results = gaz.match_gazetteer("Attributed to the Lazarus Group.")
    assert [r.value for r in results if r.entity_type == EntityType.THREAT_ACTOR] == ["Lazarus Group"]


def test_a_denied_name_is_dropped_from_the_gazetteer_output(temp_db, matcher):
    pm.add_manual(temp_db.get_conn(), "WannaCry", "malware", "deny", temp_db.now_iso())
    ov.reload()
    results = gaz.match_gazetteer("The Lazarus Group deployed WannaCry against the target.")
    values = {r.value for r in results}
    assert "Lazarus Group" in values and "WannaCry" not in values
