"""Stage 2 extraction, one class per GitHub issue (#252 to #258).

Each class has the cases the issue is about (positive) and the ones that must
keep their current result (negative and controls).
"""
from models.schemas import EntityType
from pipeline import aliases
from pipeline import stage2f_cve_enrichment as stage2f
from pipeline.stage2_extraction import (
    _extract_mitre_ttps,
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


class TestLongTld:
    """#253 — a TLD of more than 12 letters is a domain when IANA lists it."""

    def test_a_listed_long_tld_is_extracted(self):
        assert _values("Stage at example.international today.", EntityType.DOMAIN) == [
            "example.international"]
        assert _values("Seen at x.travelersinsurance now.", EntityType.DOMAIN) == [
            "x.travelersinsurance"]

    def test_a_long_word_that_is_no_tld_keeps_the_old_result(self):
        # "serialization" is code, not a TLD: nothing is extracted, as before.
        assert _values("The object.serialization method ran.", EntityType.DOMAIN) == []
        # A longer listed word does not turn into a TLD by its prefix.
        assert _values("Stage at example.internationalx today.", EntityType.DOMAIN) == []

    def test_a_common_tld_is_unchanged(self):
        assert _values("Stage at example.com today.", EntityType.DOMAIN) == ["example.com"]


class TestPunycodeTld:
    """An IDN TLD written as its A-label is the domain's end, not "xn"."""

    def test_an_a_label_tld_is_extracted_whole(self):
        # .рф used to give "test.xn".
        assert _values("C2 at test.xn--p1ai today.", EntityType.DOMAIN) == ["test.xn--p1ai"]
        assert _values("C2 at XN--80AK6AA92E.XN--P1AI today.", EntityType.DOMAIN) == [
            "xn--80ak6aa92e.xn--p1ai"]

    def test_the_hyphen_punycode_puts_before_its_encoded_part_is_kept(self):
        # The longest TLD IANA lists, 24 characters.
        assert _values("Seen at x.xn--vermgensberatung-pwb now.", EntityType.DOMAIN) == [
            "x.xn--vermgensberatung-pwb"]

    def test_an_xn_prefix_that_is_no_a_label_gives_no_domain(self):
        # Code (a decrement), and an A-label glued to a word: no "p.xn", no "foo.xn".
        assert _values("Then p.xn--; returns.", EntityType.DOMAIN) == []
        assert _values("Then foo.xn--p1ai_bar returns.", EntityType.DOMAIN) == []

    def test_a_two_letter_tld_is_unchanged(self):
        assert _values("Seen at test.xn now.", EntityType.DOMAIN) == ["test.xn"]
        assert _values("An example.com-based lure.", EntityType.DOMAIN) == ["example.com"]


class TestMitreIdCase:
    """#254 — a lower-case ATT&CK id is kept, in upper case, when the index holds it."""

    def test_a_known_lower_case_id_is_extracted_upper_cased(self):
        ttps = _values("The actor used t1059.001 and ta0001 again.", EntityType.TTP)
        assert set(ttps) == {"T1059.001", "TA0001"}

    def test_an_unknown_lower_case_id_is_dropped(self):
        assert not aliases.is_attack_id("T1000")
        assert _values("The t1000 model shipped.", EntityType.TTP) == []

    def test_an_upper_case_id_is_kept_known_or_not(self):
        # A newer release than the bundled one may hold it.
        assert set(_values("Seen: T1000 and T1059.001.", EntityType.TTP)) == {"T1000", "T1059.001"}

    def test_the_same_id_in_two_cases_is_one_entity(self):
        [ttp] = _extract_mitre_ttps("t1059.001 then T1059.001")
        assert ttp.value == ttp.mitre_id == "T1059.001"

    def test_an_id_glued_to_a_word_or_a_longer_number_is_not_extracted(self):
        assert _values("rest1059 st1059 and t10591 here", EntityType.TTP) == []
