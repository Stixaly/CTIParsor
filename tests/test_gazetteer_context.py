"""The gazetteer's ordinary-word policy, step 2: the naming constructions
(docs/gazetteer-ordinary-words.md, "Acceptance examples for contextual rules"
and the protected cases of its gates), on both matcher paths where the
matcher is involved.
"""
from __future__ import annotations

import json

import pytest

import pipeline.overrides as ov
from pipeline import gazetteer_context as gc
from pipeline import gazetteer_policy as gp
from pipeline import stage2b_gazetteer as gaz

pytestmark = pytest.mark.skipif(not gaz.available(), reason="gazetteer.json not built")


@pytest.fixture(scope="module")
def index():
    return gp.build_index(gaz._load())


def judge(index, sentence: str, surface: str, identity: str | None = None) -> gp.Judgement:
    start = gc._name_re(surface.lower()).search(sentence).start()   # the matcher's boundaries
    name = surface.lower()
    identity = identity or next(iter(index.candidates[name]))
    return gp.judge(gp.Occurrence(sentence, start, start + len(surface), name, identity), index)


# ── The rules file ───────────────────────────────────────────────────────────

def test_the_rules_cover_exactly_the_context_forms():
    rules = json.loads(gc._PATH.read_text(encoding="utf-8"))["forms"]
    assert set(rules) == {f for f, d in gp.decisions().items() if d == "CONTEXT"}


def test_no_type_resolves_an_ambiguous_form(index):
    # "Play ransomware" does not say actor or software (the spec's step 4).
    for form in index.ambiguous:
        assert not gc.form_rule(form).get("typed"), form


# ── The spec's acceptance examples ───────────────────────────────────────────

POSITIVES = [
    ("Joker, the Android billing-fraud malware also called Bread", "Joker", "S0432", "typed"),
    ("The Derusbi backdoor, also called Photo", "Photo", "S0021", "alias"),
    ("Elise malware, also known as Page", "Page", "S0081", "alias"),
    ("Playcrypt ransomware, also called Play", "Play", "S1162", "alias"),
    ("the Play threat actor (G1040)", "Play", "G1040", "attached_id"),
    ("Snake, the Uroburos malware", "Snake", "S0022", "alias"),
    ("Turla, also called Snake", "Snake", "G0010", "alias"),
    ("The MEDUSA Linux rootkit (S1220)", "MEDUSA", "S1220", "attached_id"),
    ("The meek Tor transport tunnels over HTTPS", "meek", "S0175", "typed"),
    ("The Cuba ransomware family encrypted files", "Cuba", "S0625", "typed"),
    ("The Equation threat group (G0020)", "Equation", "G0020", "attached_id"),
    ("Sandworm Team, also known as ELECTRUM, targeted the grid", "ELECTRUM", "G0034", "alias"),
    ("Exodus (S0405) was installed", "Exodus", "S0405", "attached_id"),
    ("Epic (S0091) was the first stage", "Epic", "S0091", "attached_id"),
    ("Spark (S0543) beaconed", "Spark", "S0543", "attached_id"),
    ("Proton (S0279) was signed", "Proton", "S0279", "attached_id"),
    ("The Royal ransomware family (S1073)", "Royal", "S1073", "attached_id"),
    ("Wiper (S0041) is the malware family named in this report", "Wiper", "S0041", "attached_id"),
    ("The command expand.exe extracts this CAB archive", "expand", "S0361", "executable"),
    ("cmd /c ping -n 1 localhost", "ping", "S0097", "command"),
    ("The actor uses the ping utility", "ping", "S0097", "typed"),
    ("The command route print lists routes", "route", "S0103", "command"),
    # And the ones the protected-cases gate names.
    ("Joker, the Android malware, subscribed victims to premium services", "Joker", "S0432", "typed"),
    ("A [Machete](https://attack.mitre.org/software/S0409) sample", "Machete", "S0409", "attached_id"),
    ("tools such as “ipconfig.exe”, “ping.exe” and “net.exe”", "ping", "S0097",
     "executable"),
]


@pytest.mark.parametrize("sentence, surface, identity, rule", POSITIVES)
def test_a_naming_construction_resolves_the_occurrence(index, sentence, surface, identity, rule):
    verdict = judge(index, sentence, surface, identity)
    assert (verdict.outcome, verdict.rule) == ("resolved", rule), verdict


@pytest.mark.parametrize("sentence, surface, identity, other", [
    ("Playcrypt ransomware, also called Play", "Play", "S1162", "G1040"),
    ("the Play threat actor (G1040)", "Play", "G1040", "S1162"),
    ("Turla, also called Snake", "Snake", "G0010", "S0022"),
    ("Snake, the Uroburos malware", "Snake", "S0022", "G0010"),
])
def test_the_other_identity_of_an_ambiguous_form_is_excluded(index, sentence, surface, identity, other):
    assert judge(index, sentence, surface, other).reason == "other_identity"


NEGATIVES = [
    ("Joker’s Stash closed", "Joker", "conflicting_sense"),
    ("Joker's Stash closed", "Joker", "conflicting_sense"),
    ("the KR.joker worm", "joker", "embedded"),
    ("a photo attachment", "photo", "missing_context"),
    ("see https://example.com/photo/2", "photo", "embedded"),
    ("visit the Page", "Page", "missing_context"),
    ("landing_page.png", "page", "embedded"),
    ("Google Play hosted it", "Play", "conflicting_sense"),
    ("Play ransomware encrypted the files", "Play", "ambiguous_identity"),
    ("Snake Keylogger stole passwords", "Snake", "conflicting_sense"),
    ("Snake malware was found", "Snake", "ambiguous_identity"),
    ("Medusa Android malware", "Medusa", "conflicting_sense"),
    ("Medusa ransomware", "Medusa", "conflicting_sense"),
    ("Medusa malware", "Medusa", "missing_context"),
    ("a meek response", "meek", "missing_context"),
    ("organisations in Cuba were attacked", "Cuba", "missing_context"),
    ("malware exploits Equation Editor", "Equation", "conflicting_sense"),
    ("malware steals Electrum and Exodus wallets", "Electrum", "missing_context"),
    ("malware steals Electrum and Exodus wallets", "Exodus", "conflicting_sense"),
    ("Epic Privacy Browser", "Epic", "conflicting_sense"),
    ("Apache Spark vulnerability", "Spark", "conflicting_sense"),
    ("Proton email", "Proton", "conflicting_sense"),
    ("Royal Road weaponizer", "Royal", "conflicting_sense"),
    ("Royal Thai Police", "Royal", "conflicting_sense"),
    ("a destructive wiper", "wiper", "missing_context"),
    ("Shamoon is a wiper", "wiper", "missing_context"),
    ("expand access", "expand", "missing_context"),
    ("the Salsa20 constant \"expand 32-byte k\"", "expand", "missing_context"),
    ("Bandook Client Ping Reply", "Ping", "conflicting_sense"),
    ("maritime route", "route", "missing_context"),
    ("copy the file to that route", "route", "missing_context"),
    ("echo \"route print\"", "route", "missing_context"),
    ("Machete targeted Latin America", "Machete", "ambiguous_identity"),
    ("Turla is not known as Snake", "Snake", "ambiguous_identity"),
]


@pytest.mark.parametrize("sentence, surface, reason", NEGATIVES)
def test_without_its_construction_the_mapping_is_withheld(index, sentence, surface, reason):
    for identity in index.candidates[surface.lower()]:
        verdict = judge(index, sentence, surface, identity)
        assert (verdict.withheld, verdict.reason) == (True, reason), (identity, verdict)


# ── The unit: no evidence borrowed from elsewhere ────────────────────────────

@pytest.mark.parametrize("text, outcome", [
    ("The Derusbi backdoor,\nalso called Photo, was found.", "resolved"),        # a wrapped paragraph
    ("- The Derusbi backdoor\n- also called Photo", "unresolved"),                 # another list item
    ("The Derusbi backdoor is old. Also called Photo, it returns.", "unresolved"), # another sentence
    ("# Derusbi backdoor\nalso called Photo", "unresolved"),                       # a heading
])
def test_the_unit_is_the_sentence(index, text, outcome):
    assert judge(index, text, "Photo").outcome == outcome


def test_an_anchor_must_be_identified_itself(index):
    # "Elise" is a CONTEXT form: as an anchor it needs its own construction.
    assert judge(index, "Elise malware, also known as Page", "Page").outcome == "resolved"
    assert judge(index, "Elise, also known as Page", "Page").outcome == "unresolved"
    # A CASE anchor needs its capital.
    assert gp.decisions()["barium"] == "CASE"


# ── Stage 2b, both paths ─────────────────────────────────────────────────────

@pytest.fixture(params=["aho", "regex"])
def matcher(request):
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


def test_a_valid_mention_after_an_excluded_one_is_found(matcher):
    text = ("Joker’s Stash closed in 2021, long before this campaign.  Months later, Joker, the "
            "Android malware, subscribed victims to premium services.")
    entities, trace = gaz.match_gazetteer_traced(text, policy_mode="apply")
    [bread] = [e for e in entities if e.mitre_id == "S0432"]
    assert "premium" in bread.context
    assert [(i["reason"], i["rule"]) for i in trace if i["form"] == "joker"] == [
        ("conflicting_sense", None), (None, "typed")]


def test_apply_resolves_an_ambiguous_form_by_its_attached_id(matcher):
    entities, _ = gaz.match_gazetteer_traced("The Play threat actor (G1040) was active.", policy_mode="apply")
    assert [(e.value, e.mitre_id) for e in entities] == [("Play", "G1040")]


def test_shadow_mode_still_emits_what_no_policy_emits(matcher):
    text = "Turla, also called Snake, ran Google Play apps and route print."
    off = gaz.match_gazetteer_traced(text, policy_mode="off")[0]
    shadow = gaz.match_gazetteer_traced(text, policy_mode="shadow")[0]
    assert [e.model_dump() for e in shadow] == [e.model_dump() for e in off]
