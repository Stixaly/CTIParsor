"""The gazetteer's ordinary-word policy, step 1 (docs/gazetteer-ordinary-words.md):
the reviewed decisions, what the policy makes of one occurrence, and Stage 2b
in each mode on both matcher paths.
"""
from __future__ import annotations

import json
from collections import Counter

import pytest

import pipeline.overrides as ov
from pipeline import gazetteer_context
from pipeline import gazetteer_policy as gp
from pipeline import promotion as pm
from pipeline import stage2b_gazetteer as gaz
from scripts.build_gazetteer_policy import build

pytestmark = pytest.mark.skipif(not gaz.available(), reason="gazetteer.json not built")


@pytest.fixture(params=["aho", "regex"])
def matcher(request):
    """Run each test on both matching paths, and leave the caches as found."""
    saved = gaz._SKIP_HEAVY, gaz._AHO_AVAILABLE
    if request.param == "aho":
        if not saved[1]:
            pytest.skip("pyahocorasick not installed")
        gaz._SKIP_HEAVY = False
    else:
        gaz._AHO_AVAILABLE = False
    ov.reload()
    yield request.param
    gaz._SKIP_HEAVY, gaz._AHO_AVAILABLE = saved
    ov.reload()


def _found(text: str, mode: str) -> set[tuple[str, str | None]]:
    return {(e.value, e.mitre_id) for e in gaz.match_gazetteer_traced(text, policy_mode=mode)[0]}


@pytest.fixture(scope="module")
def index():
    return gp.build_index(gaz._load())


def judge(index, sentence: str, surface: str, identity: str | None = None) -> gp.Judgement:
    """The policy's outcome for `surface`'s first occurrence in `sentence`."""
    start = gazetteer_context._name_re(surface.lower()).search(sentence).start()   # the matcher's boundaries
    name = surface.lower()
    identity = identity or next(iter(index.candidates[name]))
    return gp.judge(gp.Occurrence(sentence, start, start + len(surface), name, identity), index)


# ── The reviewed decisions ───────────────────────────────────────────────────

def test_the_policy_file_is_the_reviewed_document():
    shipped = json.loads(gp._PATH.read_text(encoding="utf-8"))
    assert shipped == build(), "run: python scripts/build_gazetteer_policy.py"
    assert Counter(shipped["forms"].values()) == {"CASE": 105, "CONTEXT": 45, "RETAIN": 1}
    assert gp.version() == f"{shipped['version']}+{gazetteer_context.rules_version()}"


def test_every_reviewed_form_is_a_gazetteer_name():
    names = {e["name"] for e in gaz._load()}
    assert set(gp.decisions()) <= names


def test_the_index_names_23_ambiguous_forms():
    ambiguous = gp.ambiguous_forms(gaz._load())
    assert {"play", "snake", "machete", "carbanak", "akira"} <= ambiguous
    assert len(ambiguous) == 23


# ── One occurrence ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("surface, outcome", [
    ("Barium", "resolved"), ("BARIUM", "resolved"), ("barium", "excluded")])
def test_a_case_form_needs_an_initial_capital(index, surface, outcome):
    verdict = judge(index, f"Attributed to {surface}.", surface)
    assert (verdict.outcome, verdict.decision) == (outcome, "CASE")
    assert verdict.reason == (None if outcome == "resolved" else "case_mismatch")


def test_internal_capitals_pass_the_case_rule(index):
    assert judge(index, "PatchWork again.", "PatchWork").outcome == "resolved"


@pytest.mark.parametrize("surface", ["Page", "page", "PAGE"])
def test_a_context_form_without_its_construction_is_unresolved(index, surface):
    verdict = judge(index, f"See the {surface} below.", surface)
    assert (verdict.outcome, verdict.reason, verdict.decision) == ("unresolved", "missing_context", "CONTEXT")


@pytest.mark.parametrize("surface", ["elfin", "Elfin"])
def test_the_retained_form_matches_in_any_case(index, surface):
    assert judge(index, f"The {surface} actors.", surface) == gp.Judgement("resolved", None, "RETAIN")


def test_a_capital_does_not_resolve_a_same_name_collision(index):
    verdict = judge(index, "The Snake implant.", "Snake", "G0010")
    assert (verdict.outcome, verdict.reason, verdict.decision) == ("unresolved", "ambiguous_identity", "CONTEXT")
    # Ambiguous without a reviewed decision too: Carbanak the group and the malware.
    assert judge(index, "The Carbanak group.", "Carbanak", "G0008").reason == "ambiguous_identity"


def test_a_form_without_a_decision_is_resolved_as_before(index):
    assert judge(index, "the lazarus group", "lazarus group") == gp.RESOLVED


def test_the_mode_defaults_to_shadow(monkeypatch):
    monkeypatch.delenv("GAZETTEER_POLICY", raising=False)
    assert gp.mode() == "shadow"
    monkeypatch.setenv("GAZETTEER_POLICY", " Apply ")
    assert gp.mode() == "apply"
    monkeypatch.setenv("GAZETTEER_POLICY", "enforce")
    assert gp.mode() == "shadow"


def test_the_summary_counts_an_ambiguous_occurrence_once():
    item = {"start": 4, "end": 9, "outcome": "unresolved", "reason": "ambiguous_identity"}
    trace = [item, dict(item), {"start": 20, "end": 26, "outcome": "excluded", "reason": "case_mismatch"},
             {"start": 30, "end": 35, "outcome": "resolved", "reason": None}]
    assert gp.summary(trace) == {"policy_ambiguous_identity": 1, "policy_case_mismatch": 1}


# ── Stage 2b, both paths ─────────────────────────────────────────────────────

# The ordinary "barium" is more than the 60-character context window before the name.
TEXT = ("A barium meal was ordered for the patient, who then waited for the radiology team.  "
        "Later, Barium operators sent a page with Page, and the Snake implant beaconed.")


def test_shadow_mode_emits_what_no_policy_emits(matcher):
    off, off_trace = gaz.match_gazetteer_traced(TEXT, policy_mode="off")
    shadow, trace = gaz.match_gazetteer_traced(TEXT, policy_mode="shadow")
    assert off_trace == []
    assert [e.model_dump() for e in shadow] == [e.model_dump() for e in off]
    assert [e.model_dump() for e in gaz.match_gazetteer(TEXT)] == [e.model_dump() for e in off]
    # The emitted occurrences the policy would withhold, by reason.
    assert gp.summary(trace) == {"policy_ambiguous_identity": 1, "policy_case_mismatch": 1,
                                 "policy_missing_context": 1}


def test_apply_withholds_an_ordinary_use_and_finds_the_later_name(matcher):
    entities, trace = gaz.match_gazetteer_traced(TEXT, policy_mode="apply")
    [apt41] = [e for e in entities if e.mitre_id == "G0096"]
    assert "Barium operators" in apt41.context and "meal" not in apt41.context
    assert {"G0096"} == {e.mitre_id for e in entities}
    assert [i["surface"] for i in trace if i["outcome"] == "resolved"] == ["Barium"]
    reasons = {(i["surface"], i["reason"]) for i in trace if i["outcome"] != "resolved"}
    assert {("barium", "case_mismatch"), ("page", "missing_context"), ("Page", "missing_context"),
            ("Snake", "ambiguous_identity")} <= reasons


def test_apply_never_chooses_an_ambiguous_identity_by_index_order(matcher):
    for text in ("The Snake implant beaconed.", "Machete targeted Latin America.",
                 "Play ransomware encrypted the files."):
        entities, trace = gaz.match_gazetteer_traced(text, policy_mode="apply")
        assert entities == []
        assert {i["outcome"] for i in trace} == {"unresolved"}
        assert len({i["mitre_id"] for i in trace}) == 2      # both identities are recorded


def test_apply_lets_capitalised_and_retained_forms_through(matcher):
    assert _found("BARIUM and PatchWork, then elfin.", "apply") == {
        ("APT41", "G0096"), ("Patchwork", "G0040"), ("APT33", "G0064")}


def test_apply_leaves_names_the_policy_does_not_review(matcher):
    text = "The Lazarus Group deployed WannaCry."
    assert _found(text, "apply") == _found(text, "off")


def test_an_analyst_promotion_matches_as_before(temp_db, matcher):
    # A promoted term the policy has a CASE decision on: the analyst's row wins.
    pm.add_manual(temp_db.get_conn(), "patchwork", "malware", "promote", temp_db.now_iso(),
                  display="PATCHWORK-X")
    ov.reload()
    entities, _ = gaz.match_gazetteer_traced("a patchwork of loaders", policy_mode="apply")
    assert [(e.value, e.mitre_id) for e in entities] == [("PATCHWORK-X", None)]
