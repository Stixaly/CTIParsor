"""Stage 2 ATT&CK ids written in the report (#980).

An id keeps the form the report writes it (a revoked one is replaced at Stage 4,
not here), a tactic gives no entity, and a technique entity carries the sentence
or table row that holds it, with the offset of that citation in the text.
"""
from models.schemas import EntityType
from pipeline.stage2_extraction import _extract_mitre_ttps


class TestCitation:
    """#980 — the sentence or table row that holds a technique id is its citation."""

    def test_a_technique_in_a_sentence_is_cited_with_its_offset(self):
        text = "Earlier text. The loader ran PowerShell (T1059.001) at boot. Last one."
        [ttp] = _extract_mitre_ttps(text)
        assert ttp.entity_type == EntityType.TTP
        assert ttp.value == ttp.mitre_id == "T1059.001"
        assert ttp.evidence_text == "The loader ran PowerShell (T1059.001) at boot."
        assert text[ttp.evidence_start:ttp.evidence_start + len(ttp.evidence_text)] == ttp.evidence_text

    def test_a_table_row_is_the_citation(self):
        text = (
            "| ID | Name |\n"
            "| T1059.001 | PowerShell |\n"
            "| T1053.005 | Scheduled Task |"
        )
        ttps = {t.value: t for t in _extract_mitre_ttps(text)}
        assert ttps["T1059.001"].evidence_text == "| T1059.001 | PowerShell |"
        assert text[ttps["T1059.001"].evidence_start:].startswith("| T1059.001 | PowerShell |")

    def test_the_first_citation_is_kept_when_the_id_repeats(self):
        text = "First, T1059.001 ran. Then T1059.001 again."
        [ttp] = _extract_mitre_ttps(text)
        assert ttp.evidence_text == "First, T1059.001 ran."

    def test_a_long_sentence_is_cut_to_300_characters_around_the_id(self):
        text = "x" * 400 + " T1059.001 " + "y" * 400
        [ttp] = _extract_mitre_ttps(text)
        assert len(ttp.evidence_text) <= 300
        assert "T1059.001" in ttp.evidence_text
        start = ttp.evidence_start
        assert text[start:start + len(ttp.evidence_text)] == ttp.evidence_text


class TestTacticAndCase:
    """#980 — a tactic is no technique, and a lower-case id follows the index."""

    def test_a_tactic_gives_no_entity(self):
        assert _extract_mitre_ttps("The steps belong to the Initial Access tactic, TA0001.") == []

    def test_a_lower_case_revoked_id_is_kept_as_written(self):
        [ttp] = _extract_mitre_ttps("The actor used t1562 for defence evasion.")
        assert ttp.value == ttp.mitre_id == "T1562"

    def test_an_upper_case_unknown_id_is_kept(self):
        [ttp] = _extract_mitre_ttps("Seen: T9999 in the sample.")
        assert ttp.value == ttp.mitre_id == "T9999"

    def test_a_lower_case_unknown_id_is_dropped(self):
        assert _extract_mitre_ttps("The t9999 model shipped.") == []
