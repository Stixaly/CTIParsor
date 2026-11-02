"""Stage 2 extraction, one class per GitHub issue (#252, #255 to #258).

Each class has the cases the issue is about (positive) and the ones that must
keep their current result (negative and controls).
"""
from models.schemas import EntityType
from pipeline import stage2f_cve_enrichment as stage2f
from pipeline.stage2_extraction import (
    extract_entities,
    refang,
    refang_with_offsets,
)


def _values(text: str, entity_type: EntityType) -> list[str]:
    return [e.value for e in extract_entities(text) if e.entity_type == entity_type]


class TestRefangBesideAt:
    """#252 — a defanged dot next to an "@" is the address's own separator."""

    def test_a_dot_right_after_an_at_is_dropped(self):
        assert refang("me@[.]evil[.]com") == "me@evil.com"

    def test_a_dot_right_before_an_at_is_dropped(self):
        assert refang("me[.]@evil.com") == "me@evil.com"

    def test_a_defanged_at_beside_a_dot_is_dropped_too(self):
        assert refang("me[at][.]evil.com") == "me@evil.com"
        assert refang("me[@][.]evil[.]com") == "me@evil.com"

    def test_dots_between_labels_still_refang(self):
        assert refang("evil[.]com") == "evil.com"
        assert refang("192[.]168[.]1[.]1") == "192.168.1.1"

    def test_at_and_dot_words_still_refang(self):
        assert refang("analyst[at]example[dot]org") == "analyst@example.org"

    def test_the_offsets_variant_agrees(self):
        assert refang_with_offsets("me@[.]evil[.]com")[0] == "me@evil.com"

    def test_the_address_is_extracted_whole(self):
        assert _values("Contact me@[.]evil[.]com today.", EntityType.EMAIL) == ["me@evil.com"]


class TestLongDomains:
    """#255 — up to 30 labels; a name over 253 characters is refused."""

    def test_a_domain_of_more_than_five_labels_is_kept_whole(self):
        assert _values("Seen at a.b.c.d.e.f.example.com today.", EntityType.DOMAIN) == [
            "a.b.c.d.e.f.example.com"]

    def test_a_name_longer_than_253_characters_is_refused(self):
        domain = ".".join(["x" * 63] * 4 + ["com"])
        assert len(domain) > 253
        assert _values(f"Beacons to {domain} daily.", EntityType.DOMAIN) == []

    def test_a_name_of_253_characters_is_kept(self):
        domain = ".".join(["x" * 63] * 3 + ["y" * 57, "com"])
        assert len(domain) == 253
        assert _values(f"Beacons to {domain} daily.", EntityType.DOMAIN) == [domain]


class TestCveSequenceDigits:
    """#256 and #258 — a sequence number of 4 to 12 digits is one id."""

    def test_an_eight_digit_sequence_number_is_kept_whole(self):
        assert _values("CVE-2024-12345678 was exploited.", EntityType.CVE) == ["CVE-2024-12345678"]

    def test_seven_and_four_digit_sequence_numbers_still_extract(self):
        assert sorted(_values("CVE-2024-1234567 and CVE-2021-44228.", EntityType.CVE)) == [
            "CVE-2021-44228", "CVE-2024-1234567"]

    def test_the_enrichment_check_accepts_eight_digits(self):
        assert stage2f.is_valid_cve("CVE-2024-12345678") is True
        assert stage2f.is_valid_cve("CVE-2024-1234") is True

    def test_the_enrichment_check_still_refuses_three_digits(self):
        assert stage2f.is_valid_cve("CVE-2024-123") is False

    def test_a_run_longer_than_twelve_digits_is_refused_not_cut(self):
        assert _values("CVE-2024-" + "1" * 13 + " here.", EntityType.CVE) == []
        assert stage2f.is_valid_cve("CVE-2024-" + "1" * 13) is False


class TestGluedCve:
    """#257 — a CVE with a letter glued to either end is part of another word."""

    def test_a_letter_glued_before_the_id_refuses_it(self):
        assert _values("XCVE-2024-3400 was exploited.", EntityType.CVE) == []

    def test_a_letter_glued_after_the_id_refuses_it(self):
        assert _values("CVE-2024-3400X was exploited.", EntityType.CVE) == []

    def test_an_id_set_off_by_punctuation_is_kept(self):
        assert sorted(_values("(CVE-2024-3400), CVE-2024-3401.", EntityType.CVE)) == [
            "CVE-2024-3400", "CVE-2024-3401"]
