"""
NER precision filters (ADR-0088) and the malware lead (ADR-0089) —
`pipeline/ner_precision.py` and its two hooks.

The filters are pure functions, tested directly.  The two integration groups
stub the models (`stage2d_cyner._load_pipeline`, `stage2_extraction._nlp`) and
keep the job store out of it, so they do not depend on whether the heavy
models are installed: CI's second pytest job runs without SKIP_HEAVY_MODELS.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from models.schemas import EntityType, RawEntity
from pipeline import ner_precision, orchestrator, overrides, stage2_extraction, stage2d_cyner, thresholds

MALWARE = EntityType.MALWARE
ACTOR = EntityType.THREAT_ACTOR
LOCATION = EntityType.LOCATION


# ── The switch ──────────────────────────────────────────────────────────────

def test_the_filters_are_on_when_the_variable_is_unset(monkeypatch):
    monkeypatch.delenv("NER_PRECISION_FILTERS", raising=False)
    assert ner_precision.enabled() is True


def test_the_variable_turns_the_filters_on_and_off(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    assert ner_precision.enabled() is True
    monkeypatch.setenv("NER_PRECISION_FILTERS", "false")
    assert ner_precision.enabled() is False


# ── A. CyNER threat actors: ordinary language ───────────────────────────────

@pytest.mark.parametrize("value", [
    "cybercriminals", "underground forums", "same threat actor",   # no capital, no digit
    "Cybercriminals", "Bad Actors", "Criminal Groups",              # only category words
    "Chinese threat actors", "North Korean hackers", "Iran",       # a nationality or a country
    "United States", "Saudi Arabia", "New Zealand", "Hong Kong",   # a country of two words too
    "Windows", "Linux operators",                                   # a platform
    "Agent", "Crew",                                                # part of a name, never one alone
    "2020", "CVE-2020-1234",
])
def test_what_is_not_an_actor_name_is_dropped(value):
    assert ner_precision.refine_cyner(value, ACTOR) == ""


@pytest.mark.parametrize("space", ["\xa0", " "])
def test_words_split_on_any_whitespace_whatever_the_regex_engine(space):
    """A non-breaking or thin space from a PDF separates words too: under RE2,
    a `[\\s\\-]+` pattern would have kept "Chinese<nbsp>threat" as one token."""
    assert ner_precision.refine_cyner(f"Chinese{space}threat actors", ACTOR) == ""


@pytest.mark.parametrize("value", [
    "APT27", "TA574", "ReconHellcat", "Golden Chickens", "Cozy Bear", "TrickBot gang",
    "Lazarus Group", "XAKNET Cyber Army of Russia Reborn", "Shell Crew", "Backdoor Diplomacy",
    "Group 123", "Threat Group 3390", "Spring Dragon",
    "apt29",                                     # no capital letter, but a digit: written as a name
])
def test_actor_names_are_kept(value):
    assert ner_precision.refine_cyner(value, ACTOR) == value


@pytest.mark.parametrize("value", ["banking trojan", "Ryuk ransomware", "Windows", "cybercriminals"])
def test_malware_is_not_filtered(value):
    """Rule A was measured on malware too and not adopted (+2.6 points on dev)."""
    assert ner_precision.refine_cyner(value, MALWARE) == value


def test_case_says_nothing_in_a_text_written_in_lower_case():
    assert ner_precision.text_is_cased("APT29 used Emotet against the Ministry.")
    assert not ner_precision.text_is_cased("anyone seen the wizard spider crew? lol")
    assert ner_precision.refine_cyner("wizard spider", ACTOR, cased=True) == ""
    assert ner_precision.refine_cyner("wizard spider", ACTOR, cased=False) == "wizard spider"
    # The vocabulary still applies.
    assert ner_precision.refine_cyner("cybercriminals", ACTOR, cased=False) == ""


def test_an_appendix_of_lowercase_hashes_does_not_make_a_report_lowercase():
    prose = "APT29 used Emotet against the Ministry of Foreign Affairs. " * 20
    # 2,000 SHA-256 values: about 80,000 lowercase letters, 160 capitals in the prose.
    hashes = " ".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(2000))
    urls = " ".join(f"hxxp://bad{i}.example/path/file.php" for i in range(500))
    assert ner_precision.text_is_cased(prose + hashes + urls)


# ── D. spaCy places ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("value, place", [
    ("the United States", "United States"),
    ("The United Arab Emirates", "United Arab Emirates"),
    ("Saudi\nArabia", "Saudi Arabia"),               # a GPE across a wrapped line
    ("the\nUnited  States", "United States"),
    ("the United States'", "United States"),       # a plural possessive
])
def test_a_place_is_put_on_one_line_without_its_article(value, place):
    assert ner_precision.refine_spacy(value, LOCATION) == place


@pytest.mark.parametrize("value", [
    "U.S.", "US", "UK", "USA", "PRC", "Oldsmar", "Jeddah", "Hong Kong", "Saudi Arabia", "Russia",
    "São Paulo", "Zürich", "Côte d’Ivoire",    # any Unicode letter, the typographic apostrophe
    "McLean", "MacKenzie",                           # "Mc"/"Mac" at the start of a word is not camel case
    "St. John's",                                    # a name that ends in 's keeps it
])
def test_place_names_are_kept(value):
    assert ner_precision.refine_spacy(value, LOCATION) == value


@pytest.mark.parametrize("value", [
    "C&C", "C++", "XSS", "SCADA", "IRGC", "GitHub", "DocuSign", "beirut", "regsvr32",
    "Payload", "Linux", "logs.txt", "iTextSharp",
])
def test_what_cannot_be_a_place_is_dropped(value):
    assert ner_precision.refine_spacy(value, LOCATION) == ""


def test_other_spacy_types_pass_unchanged():
    """Dropping spaCy's PRODUCT-as-malware was measured and not adopted (+3.5 points on dev)."""
    assert ner_precision.refine_spacy("Excel", MALWARE) == "Excel"
    assert ner_precision.refine_spacy("C&C", EntityType.DOMAIN) == "C&C"


# ── Stage 2d with a stubbed model ───────────────────────────────────────────

@pytest.fixture()
def no_store(monkeypatch):
    """Calibrated cutoffs and deny rows come from the job store; no test here
    needs it."""
    monkeypatch.setenv("THRESHOLD_CALIBRATION_ENABLED", "false")
    monkeypatch.setenv("ENTITY_OVERRIDES_ENABLED", "false")
    thresholds.reload()
    overrides.reload()


# Written with capitals, as a report is: the capital-letter test applies.
_REPORT = "The Report: APT29 and Emotet, as Seen by the Vendor."


def _cyner_entities(monkeypatch, *spans: tuple, text: str = _REPORT) -> list[RawEntity]:
    """Stage 2d's entities for these (entity_group, word) or (entity_group,
    word, score) predictions; the score is 0.95 unless given."""
    preds = [{"entity_group": group, "word": word, "score": score[0] if score else 0.95}
             for group, word, *score in spans]
    monkeypatch.setattr(stage2d_cyner, "_load_pipeline", lambda: lambda _inputs, **_kw: preds)
    return stage2d_cyner.extract_cyner_entities(text)


def _cyner(monkeypatch, *spans: tuple, text: str = _REPORT) -> list[tuple[str, EntityType]]:
    """Stage 2d's entities for these predictions, as (value, type)."""
    return [(r.value, r.entity_type) for r in _cyner_entities(monkeypatch, *spans, text=text)]


_SPANS = (("Threat_group", "cybercriminals"), ("Threat_group", "Chinese threat actors"),
          ("Threat_group", "APT27"), ("Malware", "banking trojan"))


def test_cyner_is_unchanged_while_the_filters_are_off(monkeypatch, no_store):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "false")
    assert _cyner(monkeypatch, *_SPANS) == [
        ("cybercriminals", ACTOR), ("Chinese threat actors", ACTOR), ("APT27", ACTOR),
        ("banking trojan", MALWARE)]


def test_cyner_drops_ordinary_actors_when_the_filters_are_on(monkeypatch, no_store):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "false")      # ADR-0088 alone: malware is untouched
    assert _cyner(monkeypatch, *_SPANS) == [("APT27", ACTOR), ("banking trojan", MALWARE)]


def test_the_lowercase_copy_is_dropped_before_the_case_insensitive_dedup(monkeypatch, no_store):
    """The filter runs before `seen`: the lowercase copy goes first and the
    capitalised one survives, whichever CyNER reported first."""
    spans = (("Threat_group", "reconhellcat"), ("Threat_group", "ReconHellcat"))
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    assert _cyner(monkeypatch, *spans) == [("ReconHellcat", ACTOR)]
    monkeypatch.setenv("NER_PRECISION_FILTERS", "false")
    assert _cyner(monkeypatch, *spans) == [("reconhellcat", ACTOR)]


def test_a_lowercase_report_keeps_its_lowercase_actors(monkeypatch, no_store):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    text = "anyone seen the wizard spider crew? they are back on the forums"
    assert _cyner(monkeypatch, ("Threat_group", "wizard spider"), ("Threat_group", "cybercriminals"),
                  text=text) == [("wizard spider", ACTOR)]


# ── Stage 2 with a stubbed spaCy ────────────────────────────────────────────

def _spacy(monkeypatch, *ents: tuple[str, str]) -> list[tuple[str, EntityType]]:
    """What Stage 2's spaCy pass returns for these (label, text) entities."""
    doc = SimpleNamespace(ents=[
        SimpleNamespace(text=text, label_=label, sent=SimpleNamespace(text=f"They mention {text} here."))
        for label, text in ents])
    monkeypatch.setattr(stage2_extraction, "_nlp", lambda _text: doc)
    return [(r.value, r.entity_type) for r in stage2_extraction._extract_ner_entities("irrelevant text")]


_ENTS = (("PRODUCT", "Excel"), ("GPE", "C&C"), ("GPE", "the United States"))


def test_spacy_is_unchanged_while_the_filters_are_off(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "false")
    assert _spacy(monkeypatch, *_ENTS) == [
        ("Excel", MALWARE), ("C&C", LOCATION), ("the United States", LOCATION)]


def test_spacy_keeps_only_place_names_when_the_filters_are_on(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "false")      # ADR-0088 alone: PRODUCT still proposes malware
    assert _spacy(monkeypatch, *_ENTS) == [("Excel", MALWARE), ("United States", LOCATION)]


def test_a_two_letter_place_stays_dropped_once_its_article_is_gone(monkeypatch):
    """Stage 2 drops a value of two characters or fewer ("US"); "the US" ends
    the same way rather than slipping past that rule."""
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    assert _spacy(monkeypatch, ("GPE", "the US"), ("GPE", "US"), ("GPE", "the U.S.")) == [
        ("U.S.", LOCATION)]


# ═══ ADR-0089: the malware lead ═════════════════════════════════════════════

def test_the_malware_lead_is_on_when_both_variables_are_unset(monkeypatch):
    monkeypatch.delenv("NER_PRECISION_FILTERS", raising=False)
    monkeypatch.delenv("NER_PRECISION_MALWARE", raising=False)
    assert ner_precision.malware_enabled() is True


def test_the_variable_turns_the_malware_lead_on_and_off(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_MALWARE", "false")
    assert ner_precision.malware_enabled() is False
    monkeypatch.setenv("NER_PRECISION_MALWARE", "true")
    assert ner_precision.malware_enabled() is True


def test_the_malware_lead_is_off_whenever_the_filters_are_off(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "false")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "true")
    assert ner_precision.malware_enabled() is False


# ── A for malware ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("value", [
    "banking trojan", "same malware", "Malware",   # only category words
    "Linux backdoor",                              # a platform and a category word
    "2020", "CVE-2021-44228",
])
def test_what_is_not_a_malware_name_is_dropped(value):
    assert ner_precision.refine_cyner(value, MALWARE, malware=True) == ""


@pytest.mark.parametrize("value", [
    "Emotet", "QakBot", "njRAT",
    "China Chopper",                               # a country is not a category word for malware
])
def test_malware_names_are_kept(value):
    assert ner_precision.refine_cyner(value, MALWARE, malware=True) == value


# ── B. A name with its category around it ───────────────────────────────────

@pytest.mark.parametrize("value, etype, name", [
    ("Ryuk ransomware", MALWARE, "Ryuk"),
    ("TrickBot banking trojan", MALWARE, "TrickBot"),
    ("multipurpose trojan QBot", MALWARE, "QBot"),
    ("hacking group TA505", ACTOR, "TA505"),
    ("TA575 campaign", ACTOR, "TA575"),
])
def test_a_name_with_its_category_around_it_is_shortened(value, etype, name):
    assert ner_precision.cyner_normalise(value, etype) == name
    assert ner_precision.refine_cyner(value, etype, malware=True) == name


@pytest.mark.parametrize("value, etype", [
    ("Smoke Loader", MALWARE), ("Hallaj Pro RAT", MALWARE), ("Miner Dropper", MALWARE),
    ("RIG Exploit Kit", MALWARE),                  # "loader", "RAT", "dropper", "kit" end real names
    ("Backdoor Diplomacy", ACTOR), ("Group 123", ACTOR),
])
def test_a_name_that_includes_a_category_word_is_kept_whole(value, etype):
    assert ner_precision.cyner_normalise(value, etype) == value
    assert ner_precision.refine_cyner(value, etype, malware=True) == value


def test_without_the_lead_malware_is_untouched_and_nothing_is_shortened():
    assert ner_precision.refine_cyner("Ryuk ransomware", MALWARE) == "Ryuk ransomware"
    assert ner_precision.refine_cyner("banking trojan", MALWARE) == "banking trojan"
    assert ner_precision.refine_cyner("hacking group TA505", ACTOR) == "hacking group TA505"


@pytest.mark.parametrize("raw, parts", [
    ("Winnti Group (APT41", ["Winnti Group", "APT41"]),
    ("AZORULT, FORMBOOK/TRICKBOT", ["AZORULT", "FORMBOOK", "TRICKBOT"]),
    ("Emotet (4.2)", ["Emotet", "4.2"]),
    ("Emotet", ["Emotet"]),
])
def test_cyner_spans_are_split_on_separators_and_brackets(raw, parts):
    assert ner_precision.split_cyner(raw) == parts


# ── C. spaCy's PRODUCT label ────────────────────────────────────────────────

def test_spacy_product_no_longer_proposes_malware_with_the_lead():
    assert ner_precision.refine_spacy("Excel", MALWARE, malware=True) == ""
    assert ner_precision.refine_spacy("Excel", MALWARE) == "Excel"


@pytest.mark.parametrize("value, place", [("the United States", "United States"), ("C&C", ""), ("Oldsmar", "Oldsmar")])
def test_a_location_is_judged_the_same_with_and_without_the_lead(value, place):
    assert ner_precision.refine_spacy(value, LOCATION, malware=True) == place
    assert ner_precision.refine_spacy(value, LOCATION) == place


# ── Stage 2d with a stubbed model ───────────────────────────────────────────

@pytest.fixture()
def lead_on(monkeypatch):
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "true")


@pytest.fixture()
def lead_off(monkeypatch):
    """ADR-0088 alone."""
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "false")


_RYUK = (("Malware", "Ryuk ransomware", 0.95), ("Malware", "Ryuk", 0.80))


@pytest.mark.parametrize("spans", [_RYUK, _RYUK[::-1]])
def test_a_shortened_name_meeting_the_bare_name_keeps_the_higher_confidence(monkeypatch, no_store, lead_on, spans):
    found = _cyner_entities(monkeypatch, *spans)
    assert [(r.value, r.entity_type, r.confidence) for r in found] == [("Ryuk", MALWARE, 0.95)]


def test_without_the_lead_the_shortened_name_and_the_bare_name_stay_two(monkeypatch, no_store, lead_off):
    found = _cyner_entities(monkeypatch, *_RYUK)
    assert [(r.value, r.confidence) for r in found] == [("Ryuk ransomware", 0.95), ("Ryuk", 0.80)]


def test_cyner_splits_a_bracketed_group_and_its_alias_with_the_lead(monkeypatch, no_store, lead_on):
    assert _cyner(monkeypatch, ("Threat_group", "Winnti Group (APT41")) == [
        ("Winnti Group", ACTOR), ("APT41", ACTOR)]


def test_cyner_drops_ordinary_malware_only_with_the_lead(monkeypatch, no_store):
    span = ("Malware", "banking trojan")
    monkeypatch.setenv("NER_PRECISION_FILTERS", "true")
    monkeypatch.setenv("NER_PRECISION_MALWARE", "true")
    assert _cyner(monkeypatch, span) == []
    monkeypatch.setenv("NER_PRECISION_MALWARE", "false")
    assert _cyner(monkeypatch, span) == [("banking trojan", MALWARE)]


# ── Stage 2 with a stubbed spaCy ────────────────────────────────────────────

def test_spacy_product_is_not_malware_with_the_lead(monkeypatch, lead_on):
    assert _spacy(monkeypatch, *_ENTS) == [("United States", LOCATION)]


def test_spacy_product_is_malware_without_the_lead(monkeypatch, lead_off):
    assert _spacy(monkeypatch, *_ENTS) == [("Excel", MALWARE), ("United States", LOCATION)]


# ── The stage report ────────────────────────────────────────────────────────

@pytest.mark.parametrize("filters, malware, note", [
    ("true", "true", "precision filters on (ADR-0088), malware lead on (ADR-0089)"),
    ("true", "false", "precision filters on (ADR-0088)"),
    ("false", "true", ""),                     # the lead is off whenever the filters are
])
def test_the_stage_report_says_which_filters_were_on(monkeypatch, sample_cti_text, filters, malware, note):
    monkeypatch.setenv("NER_PRECISION_FILTERS", filters)
    monkeypatch.setenv("NER_PRECISION_MALWARE", malware)
    monkeypatch.setattr(stage2d_cyner, "cyner_available", lambda: True)
    monkeypatch.setattr(stage2d_cyner, "extract_cyner_entities", lambda _text: [])
    opts = orchestrator.RunOptions(
        disabled=frozenset(orchestrator.STAGES) - {"1", "2", "2d"}, consensus=False,
        document_relations=False, verify_relationships=False, verify_ttps=False, llm_parallelism=1)

    result = orchestrator.run_document(orchestrator.Document(text=sample_cti_text), opts)

    assert result.outcome("2").reason == result.outcome("2d").reason == note
