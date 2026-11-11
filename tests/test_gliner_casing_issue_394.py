"""Stage 2e — casing of GLiNER values (issue #394).

`_recover_casing` searched the context with no word boundary, so the malware
"RAT" came back as "rat", the "rat" inside "crates"; and the casing GLiNER gave
the span was thrown away.  The model is stubbed: nothing is downloaded.
"""
from __future__ import annotations

from models.schemas import EntityType
from pipeline import stage2e_gliner


class _FakeGLiNER:
    """Mimics GLiNER.inference for a list of chunks: one list per chunk."""

    def __init__(self, predictions: list[dict]):
        self.predictions = predictions

    def inference(self, texts, labels, threshold=0.5, **kw):
        return [list(self.predictions) for _ in texts]


def _default_cutoff(source, entity_type, default):
    return default


def _stub(monkeypatch, predictions: list[dict]) -> None:
    monkeypatch.setattr(stage2e_gliner, "_load_gliner", lambda: _FakeGLiNER(predictions))
    monkeypatch.setattr(stage2e_gliner, "get_threshold", _default_cutoff)
    # The six labels, whatever GLINER_ENTITY_TYPES says in the environment (ADR-0098).
    monkeypatch.setattr(stage2e_gliner, "_GLINER_LABELS", list(stage2e_gliner._LABEL_MAP))


# ── _recover_casing: whole words only ────────────────────────────────────────

def test_rat_is_not_matched_inside_crates():
    """The case of the triage: the RAT of the sentence, not the rat of "crates"."""
    assert stage2e_gliner._recover_casing(
        "rat", "Operators used crates and tools; the RAT was dropped."
    ) == "RAT"


def test_control_without_a_whole_word_falls_back_to_lower_case():
    assert stage2e_gliner._recover_casing("rat", "it used crates only") == "rat"


def test_hyphenated_name_is_found_whole_and_not_inside_a_longer_number():
    assert stage2e_gliner._recover_casing("apt-29", "Operators of APT-29 were seen.") == "APT-29"
    assert stage2e_gliner._recover_casing("apt-29", "the APT-290 cluster") == "apt-29"


def test_a_non_ascii_letter_glues_a_match_to_a_longer_word():
    assert stage2e_gliner._recover_casing("rat", "the RATé only") == "rat"
    assert stage2e_gliner._recover_casing("rat", "the RATé and RAT") == "RAT"


# ── extract_gliner_entities: the casing of the span ──────────────────────────

def test_the_span_keeps_its_casing_from_the_offsets(monkeypatch):
    text = "Operators used crates and tools; the RAT was dropped."
    start = text.index("RAT")
    _stub(monkeypatch, [
        {"label": "malware family", "score": 0.9, "text": "RAT", "start": start, "end": start + 3},
    ])

    [result] = stage2e_gliner.extract_gliner_entities(text)
    assert (result.value, result.entity_type) == ("RAT", EntityType.MALWARE)


def test_the_span_at_its_offsets_wins_over_the_first_whole_word_match(monkeypatch):
    """"a rat" comes first in the context; the offsets say the span is "Rat"."""
    text = "a rat was seen, then the Rat was dropped."
    start = text.index("Rat")
    _stub(monkeypatch, [
        {"label": "malware family", "score": 0.9, "text": "Rat", "start": start, "end": start + 3},
    ])

    [result] = stage2e_gliner.extract_gliner_entities(text)
    assert result.value == "Rat"


def test_offsets_that_select_other_text_are_ignored(monkeypatch):
    """Control: offsets pointing at "Ope" do not select "RAT"; the context search runs."""
    text = "Operators used crates and tools; the RAT was dropped."
    _stub(monkeypatch, [
        {"label": "malware family", "score": 0.9, "text": "RAT", "start": 0, "end": 3},
    ])

    [result] = stage2e_gliner.extract_gliner_entities(text)
    assert result.value == "RAT"


def test_a_hyphenated_value_keeps_its_casing_end_to_end(monkeypatch):
    text = "Operators of APT-29 were seen."
    start = text.index("APT-29")
    _stub(monkeypatch, [
        {"label": "threat actor group", "score": 0.9, "text": "APT-29",
         "start": start, "end": start + 6},
    ])

    [result] = stage2e_gliner.extract_gliner_entities(text)
    assert (result.value, result.entity_type) == ("APT-29", EntityType.THREAT_ACTOR)
