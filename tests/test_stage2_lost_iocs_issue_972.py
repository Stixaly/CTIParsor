"""Common observables that Stage 2 used to lose (#972).

Each row of the issue's table is a sentence of a real report.  Windows paths with
a space or an environment variable at the root, SHA-512 hashes, CIDR ranges, and
the extensions that a dropper names (docm, dat...) are kept; a domain no longer
swallows a payload's name.
"""
import time

import pytest
from stix2patterns.v21.pattern import Pattern

from models.schemas import EntityType, RawEntity
from pipeline import benign
from pipeline import stage2_extraction as s2
from pipeline import stage4_stix_mapping as s4
from pipeline.stage2_extraction import extract_entities

T = EntityType
SHA512_HEX = "a" * 64 + "0123456789abcdef" * 4          # 128 hexadecimal characters
SHA512_VALUE = SHA512_HEX.lower()


def _by_type(text, entity_type):
    return {e.value for e in extract_entities(text) if e.entity_type == entity_type}


@pytest.mark.parametrize("sentence, entity_type, value", [
    ("The loader is dropped to C:\\Program Files\\Acme\\update.exe and run.",
     T.FILE, "C:\\Program Files\\Acme\\update.exe"),
    ("It copies itself to %APPDATA%\\Microsoft\\svc.exe at startup.",
     T.FILE, "%APPDATA%\\Microsoft\\svc.exe"),
    (f"The archive is unpacked with SHA512: {SHA512_HEX} before it runs.",
     T.SHA512, SHA512_VALUE),
    ("Scanning originated from 203.0.113.0/24 during the week.",
     T.IPV4, "203.0.113.0/24"),
])
def test_the_lost_observable_of_the_issue_table_is_extracted(sentence, entity_type, value):
    assert value in _by_type(sentence, entity_type)


def test_the_path_that_was_already_found_is_unchanged():
    assert _by_type("It writes C:\\Users\\Public\\svc.exe on disk.", T.FILE) == {"C:\\Users\\Public\\svc.exe"}


def test_a_dropper_names_two_files_and_no_domain():
    text = "The lure invoice_2026.docm drops payload.dat in the temp folder."
    entities = extract_entities(text)
    assert {e.value for e in entities if e.entity_type == T.FILE} == {"invoice_2026.docm", "payload.dat"}
    assert not [e for e in entities if e.entity_type == T.DOMAIN]


def test_the_range_is_one_ipv4_observable_not_its_first_address():
    ipv4 = {e.value for e in extract_entities("Scanning originated from 203.0.113.0/24 during the week.")
            if e.entity_type == T.IPV4}
    assert ipv4 == {"203.0.113.0/24"}


def test_a_path_at_the_end_of_a_sentence_loses_its_full_stop():
    assert _by_type("It writes C:\\Program Files\\Acme\\update.exe.", T.FILE) == {
        "C:\\Program Files\\Acme\\update.exe"}


def test_a_quoted_path_ends_at_the_closing_quote():
    assert _by_type('The dropper runs "C:\\Program Files\\Acme\\update.exe" at logon.', T.FILE) == {
        "C:\\Program Files\\Acme\\update.exe"}


def test_two_paths_in_one_sentence_are_two_files():
    assert _by_type("It copies C:\\Program Files\\Acme\\a.exe and C:\\Users\\Public\\b.dll.", T.FILE) == {
        "C:\\Program Files\\Acme\\a.exe", "C:\\Users\\Public\\b.dll"}


def test_program_files_in_prose_without_a_path_is_no_file():
    assert _by_type("Many families target the Program Files directory of the host.", T.FILE) == set()


def test_a_spaced_folder_name_in_prose_is_not_a_path():
    # No known extension after the folder: the sentence's "." ends the match.
    assert _by_type("C:\\Program Files\\Acme is the folder. It is large.", T.FILE) == set()


def test_a_filename_with_a_space_is_not_a_path():
    # The filename has no space: no path is taken, only the bare name after the blank.
    assert _by_type("It writes C:\\Program Files\\Acme\\my update.exe on disk.", T.FILE) == {"update.exe"}


def test_example_com_is_still_a_domain():
    assert _by_type("Visit example.com for the advisory.", T.DOMAIN) == {"example.com"}


def test_a_hash_of_another_length_is_still_refused():
    # SHA-384 (96 hexadecimal characters) is not in the vocabulary of STIX 2.1 hashes.
    assert not [e for e in extract_entities("SHA-384: " + "b" * 96) if len(e.value) == 96]


def test_a_cidr_prefix_out_of_range_keeps_the_address_as_before():
    # /33 is not a prefix: the plain address pass sees it as before.
    assert _by_type("Scanning from 203.0.113.0/33 today.", T.IPV4) == {"203.0.113.0"}


def test_the_plain_address_is_still_one_observable():
    assert _by_type("It beacons to 203.0.113.5.", T.IPV4) == {"203.0.113.5"}


def test_stage4_stix_pattern_for_a_sha512():
    sco = s4._entity_to_sco(RawEntity(value=SHA512_VALUE, entity_type=T.SHA512))
    assert sco["hashes"]["SHA-512"] == SHA512_VALUE
    pattern = s4._build_stix_pattern(SHA512_VALUE, sco)
    assert pattern == f"[file:hashes.'SHA-512' = '{SHA512_VALUE}']"
    Pattern(pattern)                                  # parses as a STIX 2.1 pattern


def test_stage4_stix_pattern_for_a_cidr_range():
    sco = s4._entity_to_sco(RawEntity(value="203.0.113.0/24", entity_type=T.IPV4))
    assert sco["value"] == "203.0.113.0/24"
    pattern = s4._build_stix_pattern("203.0.113.0/24", sco)
    assert pattern == "[ipv4-addr:value = '203.0.113.0/24']"
    Pattern(pattern)


def test_the_benign_filter_judges_a_range_by_its_network_address():
    # 203.0.113.0/24 is a documentation range: judged like 203.0.113.0.
    assert benign.benign_reason(T.IPV4, "203.0.113.0/24") == "non_routable_address"
    assert benign.benign_reason(T.IPV4, "203.0.113.0") == "non_routable_address"
    assert benign.benign_reason(T.IPV4, "10.0.0.0/8") == "non_routable_address"


def test_the_windows_path_pattern_is_linear_on_a_run_of_spaced_components():
    text = "C:\\" + "x y\\" * 20_000 + "no"
    start = time.perf_counter()
    list(s2._WIN_PATH_PATTERN.finditer(text))
    assert time.perf_counter() - start < 1.0


def test_the_head_of_a_file_name_is_not_a_domain():
    """reminder.uue.rar is a file; its head reminder.uue is no domain."""
    from pipeline.stage2_extraction import extract_entities
    found = {(e.entity_type.value, e.value) for e in extract_entities("The archive reminder.uue.rar was sent.")}
    assert ("domain", "reminder.uue") not in found
    assert ("file", "reminder.uue.rar") in found
