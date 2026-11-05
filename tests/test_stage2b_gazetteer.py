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


def test_context_survives_a_length_changing_lowercase_prefix(matcher):
    # #299: U+0130 lowercases to two code points; offsets must map back.
    results = gaz.match_gazetteer("İ" * 80 + " APT29")
    [r] = [r for r in results if r.value.lower() == "apt29" or "APT29" in r.context]
    assert "APT29" in r.context


@pytest.mark.parametrize("text, expected", [
    ("Emperor Dragonfly attacked X. Later, Emperor Dragonfly attacked Y.", {"G1021"}),
    ("Threat Group-3390 (Emissary Panda) attacked X.", {"G0027"}),
    ("Carbon Spider attacked X. Later, Carbon Spider attacked Y.", {"G0046"}),
])
def test_repeated_mention_or_alias_claims_its_span(matcher, text, expected):
    # #318: a repeated mention must still block shorter aliases of other entries.
    assert {r.mitre_id for r in gaz.match_gazetteer(text)} == expected


@pytest.mark.parametrize("mode", ["off", "shadow", "apply"])
def test_homonyms_of_different_types_both_match_the_same_span(matcher, mode):
    # #319: Machete is both a group (G0095) and a malware (S0409).
    results, _ = gaz.match_gazetteer_traced(
        "The Machete (G0095) group deployed the Machete (S0409) tool.", policy_mode=mode)
    found = {(r.mitre_id, r.entity_type) for r in results}
    assert ("G0095", EntityType.THREAT_ACTOR) in found
    assert ("S0409", EntityType.MALWARE) in found


def test_a_mention_glued_to_a_length_changing_letter_is_not_matched(matcher):
    # #350: "İ" lowers to "i" + U+0307, which the regex lookbehind takes for a
    # boundary; both paths must judge the boundary on the original text.
    assert [r for r in gaz.match_gazetteer("İAPT29 was seen.") if r.mitre_id == "G0016"] == []
    assert [r.mitre_id for r in gaz.match_gazetteer("İ APT29 was seen.") if r.mitre_id == "G0016"] == ["G0016"]


def test_repeated_mentions_are_linear_in_the_number_of_claims():
    # #351: every repeated mention claims its span (#318); looking a span up
    # must not scan every earlier claim.
    claims = gaz._Claims()
    for k in range(2000):
        assert not claims.blocks(6 * k, 6 * k + 5, "threat_actor")
        claims.add(6 * k, 6 * k + 5, "threat_actor")
    assert claims.blocks(6 * 1000 + 2, 6 * 1000 + 4, "malware")       # inside
    assert claims.blocks(6 * 1000 - 3, 6 * 1000 + 1, "malware")       # straddles a start
    assert not claims.blocks(6 * 1000, 6 * 1000 + 5, "malware")       # homonym on the same span
    assert claims.blocks(6 * 1000, 6 * 1000 + 5, "threat_actor")
    assert not claims.blocks(6 * 1000 + 5, 6 * 1000 + 6, "malware")   # the gap between two


def test_many_repeated_mentions_still_emit_one_entity(matcher):
    results = gaz.match_gazetteer("APT29 " * 2000)
    assert [r.mitre_id for r in results if r.mitre_id == "G0016"] == ["G0016"]
