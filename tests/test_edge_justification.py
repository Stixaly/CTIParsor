"""The description of a relationship (ADR-0093): what each SRO says about itself.

Each test pins one origin's sentence, or one rule of how the text is built, so
a change to the Markdown shows up here and not in an analyst's OpenCTI view.
"""
import pytest

from pipeline.edge_justification import justify

NAMES = {
    "intrusion-set--a": "APT29",
    "malware--b": "WINELOADER",
    "tool--c": "Cobalt Strike",
}


def _sro(**kw):
    base = {"relationship_type": "uses", "source_ref": "intrusion-set--a", "target_ref": "malware--b"}
    return {**base, **kw}


def _why(text):
    """The Why block of `text` without its label; None when there is none."""
    for block in text.split("\n\n"):
        if block.startswith("**Why:** "):
            return block[len("**Why:** "):]
    return None


# ── the full text, on three complete cases ──────────────────────────────────

def test_extracted_with_quote_has_the_full_text():
    sro = _sro(confidence=85, x_evidence_label="reported",
               x_evidence_text="APT29 deployed WINELOADER on the host.")
    assert justify(sro, {"origin": "extracted"}, NAMES) == (
        "**APT29** `uses` **WINELOADER**\n\n"
        "> APT29 deployed WINELOADER on the host.\n\n"
        "**Why:** The report states this link in the sentence quoted above.\n\n"
        "**Evidence:** reported · **Confidence:** 85/100"
    )


def test_policy_pin_cosentence_has_the_full_text():
    sro = _sro(confidence=60, x_evidence_label="assessed",
               x_policy_rule="pin-actor-malware", x_pin_evidence="cosentence")
    assert justify(sro, {"origin": "policy_pin"}, NAMES) == (
        "**APT29** `uses` **WINELOADER**\n\n"
        "**Why:** Added by the relationship policy rule `pin-actor-malware`: "
        "the analyst's link model, not a claim the report makes. "
        "Both objects are named in one sentence of the report.\n\n"
        "**Evidence:** assessed · **Confidence:** 60/100"
    )


def test_transitive_with_two_named_premises_has_the_full_text():
    sro = _sro(target_ref="tool--c", confidence=42, x_evidence_label="inferred",
               x_inference_rule="transitive:uses+uses",
               x_inferred_from=["relationship--1111", "relationship--2222"])
    names = {**NAMES, "relationship--1111": "APT29 uses WINELOADER",
             "relationship--2222": "WINELOADER uses Cobalt Strike"}
    assert justify(sro, {"origin": "completion_transitive"}, names) == (
        "**APT29** `uses` **Cobalt Strike**\n\n"
        "**Why:** Inferred by composing two links of this bundle: "
        "APT29 uses WINELOADER; WINELOADER uses Cobalt Strike. The report does not state it.\n\n"
        "**Evidence:** inferred · **Confidence:** 42/100"
    )


# ── the Why sentence, by origin ──────────────────────────────────────────────

def test_extracted_without_quote_says_no_sentence_supports_it():
    text = justify(_sro(confidence=50), {"origin": "extracted"}, NAMES)
    assert "> " not in text
    assert _why(text) == ("A relationship row of this job (extracted from the report or added by an analyst), "
                          "with no supporting sentence quoted.")


def test_whitespace_only_quote_counts_as_no_quote():
    text = justify(_sro(x_evidence_text="  \n "), {"origin": "extracted"}, NAMES)
    assert "> " not in text
    assert _why(text).startswith("A relationship row of this job")


def test_ioc_based_on_says_the_pattern_is_built_from_the_observable():
    sro = _sro(relationship_type="based-on", source_ref="indicator--x", target_ref="ipv4-addr--y")
    names = {"indicator--x": "C2 indicator", "ipv4-addr--y": "203.0.113.7"}
    assert _why(justify(sro, {"origin": "ioc_based_on"}, names)) == (
        "The indicator's pattern is built from this observable, which the report lists.")


def test_ioc_association_names_the_value_and_the_malware():
    sro = _sro(relationship_type="indicates", source_ref="indicator--x", target_ref="malware--b")
    origin = {"origin": "ioc_association", "ioc_value": "evil.example", "malware_name": "WINELOADER"}
    names = {**NAMES, "indicator--x": "evil.example"}
    assert _why(justify(sro, origin, names)) == (
        "The report associates the indicator value evil.example with **WINELOADER**.")


def test_ioc_association_without_malware_name_says_this_malware():
    sro = _sro(relationship_type="indicates", source_ref="indicator--x", target_ref="malware--b")
    origin = {"origin": "ioc_association", "ioc_value": "evil.example"}
    assert _why(justify(sro, origin, NAMES)) == (
        "The report associates the indicator value evil.example with this malware.")


def test_ioc_value_is_escaped():
    sro = _sro(relationship_type="indicates", source_ref="indicator--x", target_ref="malware--b")
    origin = {"origin": "ioc_association", "ioc_value": "evil_dropper.exe", "malware_name": "WINELOADER"}
    assert _why(justify(sro, origin, NAMES)) == (
        "The report associates the indicator value evil\\_dropper.exe with **WINELOADER**.")


def test_embedded_rule_title_names_the_rule_and_the_malware():
    sro = _sro(relationship_type="indicates", source_ref="indicator--r", target_ref="malware--b")
    origin = {"origin": "embedded_rule_title", "title": "Possible WINELOADER loader", "name": "WINELOADER"}
    assert _why(justify(sro, origin, NAMES)) == (
        "The detection rule **Possible WINELOADER loader**, quoted in the report, "
        "names **WINELOADER** in its title.")


def test_targeted_location_names_actor_and_target_from_the_ledger():
    sro = _sro(relationship_type="targets", source_ref="intrusion-set--a", target_ref="location--f")
    names = {**NAMES, "location--f": "France"}
    origin = {"origin": "targeted_location", "actor": "APT29", "target": "France"}
    assert _why(justify(sro, origin, names)) == (
        "The report names **APT29** as a threat actor and **France** as a target. "
        "CTIParsor links every threat actor of the report to every target it names, "
        "so the report may not say that this actor targets this one.")


def test_targeted_location_falls_back_on_the_titles():
    sro = _sro(relationship_type="targets", source_ref="intrusion-set--a", target_ref="location--f")
    names = {**NAMES, "location--f": "France"}
    why = _why(justify(sro, {"origin": "targeted_location"}, names))
    assert why.startswith("The report names **APT29** as a threat actor and **France** as a target. ")


@pytest.mark.parametrize("pin, tail", [
    ("cosentence", " Both objects are named in one sentence of the report."),
    ("unanchorable", " Whether the report names them together could not be checked."),
    ("window:2", " The report names them 2 sentences apart."),
    ("window:1", " The report names them 1 sentence apart."),
    ("window:x", ""),
    ("unchecked", ""),
    (None, ""),
])
def test_policy_pin_says_what_was_checked(pin, tail):
    extra = {} if pin is None else {"x_pin_evidence": pin}
    sro = _sro(x_policy_rule="pin-actor-malware", **extra)
    assert _why(justify(sro, {"origin": "policy_pin"}, NAMES)) == (
        "Added by the relationship policy rule `pin-actor-malware`: "
        "the analyst's link model, not a claim the report makes." + tail)


def test_policy_rule_with_a_backtick_is_escaped_not_quoted():
    sro = _sro(x_policy_rule="pin`x")
    assert _why(justify(sro, {"origin": "policy_pin"}, NAMES)) == (
        "Added by the relationship policy rule pin\\`x: "
        "the analyst's link model, not a claim the report makes.")


def test_reference_names_both_attack_ids():
    sro = _sro(relationship_type="uses", source_ref="intrusion-set--a", target_ref="tool--c",
               x_inference_rule="attack-reference:G0016>S0002")
    assert _why(justify(sro, {"origin": "completion_reference"}, NAMES)) == (
        "MITRE ATT&CK records this link (G0016 → S0002); the report does not state it.")


@pytest.mark.parametrize("rule", [
    "attack-reference",
    "attack-reference:G0016",
    "attack-reference:G0016>S0002>X",
    "attack-reference:>S0002",
])
def test_unreadable_reference_rule_gives_the_plain_sentence(rule):
    sro = _sro(x_inference_rule=rule)
    assert _why(justify(sro, None, NAMES)) == (
        "MITRE ATT&CK records this link; the report does not state it.")


def test_transitive_with_one_unnamed_premise_leaves_its_id_out():
    sro = _sro(target_ref="tool--c", x_inference_rule="transitive:uses+uses",
               x_inferred_from=["relationship--1111", "relationship--2222"])
    names = {**NAMES, "relationship--2222": "WINELOADER uses Cobalt Strike"}
    text = justify(sro, {"origin": "completion_transitive"}, names)
    assert _why(text) == ("Inferred by composing two links of this bundle: "
                          "WINELOADER uses Cobalt Strike. The report does not state it.")
    assert "relationship--" not in text


def test_transitive_with_no_named_premise_says_so_without_ids():
    sro = _sro(target_ref="tool--c", x_inference_rule="transitive:uses+uses",
               x_inferred_from=["relationship--1111"])
    text = justify(sro, {"origin": "completion_transitive"}, NAMES)
    assert _why(text) == "Inferred by composing two links of this bundle. The report does not state it."
    assert "relationship--" not in text


def test_long_distance_says_the_language_model_inferred_it():
    sro = _sro(x_inference_rule="long-distance", x_evidence_label="inferred")
    assert _why(justify(sro, {"origin": "completion_long_distance"}, NAMES)) == (
        "Inferred by the language model from the report; the quoted sentence was found in its text.")


def test_unknown_origin_has_no_why():
    text = justify(_sro(confidence=30), {"origin": "unknown"}, NAMES)
    assert _why(text) is None
    assert text == "**APT29** `uses` **WINELOADER**\n\n**Confidence:** 30/100"


# ── origin: ledger first, then the SRO's own properties ─────────────────────

def test_origin_none_is_classified_by_the_sro_properties():
    assert _why(justify(_sro(x_policy_rule="pin-x"), None, NAMES)).startswith(
        "Added by the relationship policy rule `pin-x`")
    assert _why(justify(_sro(x_inference_rule="long-distance"), None, NAMES)).startswith(
        "Inferred by the language model")
    assert _why(justify(_sro(), None, NAMES)) is None


def test_unknown_origin_falls_back_to_the_sro_properties():
    text = justify(_sro(x_policy_rule="pin-x"), {"origin": "unknown"}, NAMES)
    assert _why(text).startswith("Added by the relationship policy rule `pin-x`")


def test_recorded_origin_wins_over_the_sro_properties():
    text = justify(_sro(x_policy_rule="pin-x"), {"origin": "extracted"}, NAMES)
    assert _why(text).startswith("A relationship row of this job")


# ── escaping and names ───────────────────────────────────────────────────────

def test_name_and_quote_are_escaped():
    sro = _sro(x_evidence_text="# Not a heading", confidence=10)
    names = {**NAMES, "intrusion-set--a": "Evil*Bot"}
    blocks = justify(sro, {"origin": "extracted"}, names).split("\n\n")
    assert blocks[0] == "**Evil\\*Bot** `uses` **WINELOADER**"
    assert blocks[1] == "> \\# Not a heading"


def test_object_without_a_name_is_shown_by_its_id():
    text = justify(_sro(), {"origin": "extracted"}, {})
    assert text.split("\n\n")[0] == "**intrusion-set--a** `uses` **malware--b**"


# ── evidence line ────────────────────────────────────────────────────────────

def test_bool_confidence_is_not_a_confidence():
    text = justify(_sro(confidence=True, x_evidence_label="reported"), {"origin": "extracted"}, NAMES)
    assert text.endswith("**Evidence:** reported")
    assert "Confidence" not in text


def test_evidence_block_is_omitted_when_the_sro_carries_neither():
    text = justify(_sro(), {"origin": "extracted"}, NAMES)
    assert "Evidence" not in text and "Confidence" not in text
    assert text.split("\n\n")[-1].startswith("**Why:** ")


def test_text_has_no_trailing_newline():
    assert not justify(_sro(confidence=1), {"origin": "extracted"}, NAMES).endswith("\n")
