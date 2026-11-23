"""Cases the review of #972/#973 found: none may regress."""
import time

import pytest

from pipeline.stage2_extraction import _extract_file_paths, extract_entities


def _found(text):
    return {(e.entity_type.value, e.value) for e in extract_entities(text)}


@pytest.mark.parametrize("text", [
    "Look in C:\\Users\\Public. The loader is at D\\x.dll",
    "It dropped C:\\Temp\\a is dropped. Then it ran c\\d.exe later",
    "Open C:\\Users\\Bob, then the loader is at D\\x.dll",
])
def test_a_sentence_end_ends_a_path(text):
    for _type, value in _found(text):
        assert ". " not in value and ", " not in value, value


@pytest.mark.parametrize("text", ["%a%\\b " * 33000, "%A%\\Program Files\\x " * 9000],
                         ids=["env-vars", "spaced-dirs"])
def test_a_hostile_text_of_paths_stays_fast(text):
    t0 = time.perf_counter()
    _extract_file_paths(text)
    assert time.perf_counter() - t0 < 5.0


def test_a_url_host_with_a_path_is_its_address_not_a_range():
    found = _found("The C2 http://203.0.113.5/24 answered.")
    assert ("ipv4", "203.0.113.5") in found
    assert not any(v.endswith("/24") for t, v in found if t == "ipv4")


def test_a_range_in_a_path_is_no_range():
    assert not any(t == "ipv4" and "/" in v for t, v in _found("cached in /var/1.2.3.4/24 today"))


def test_the_word_commit_in_prose_does_not_hide_a_hash():
    h = "a" * 64
    assert ("sha256", h) in _found(f"Attackers commit fraud using sample {h}")


@pytest.mark.parametrize("text", [
    "JA3 fingerprint 51c64c77e60f3980eea90869b68c58a8 was observed.",
    "imphash: 0123456789abcdef0123456789abcdef",
])
def test_a_label_right_before_its_value_still_refuses_it(text):
    assert not any(t in ("md5", "sha1", "sha256") for t, _v in _found(text))


@pytest.mark.parametrize("text, ip", [
    ("Last update: 198.51.100.7 hosting", "198.51.100.7"),
    ("release 8.8.4.4 resolver", "8.8.4.4"),
    ("C2 server update 1.2.3.4 was seen", "1.2.3.4"),
    ("Attacker IP v 45.9.148.10", "45.9.148.10"),
])
def test_ordinary_words_before_an_address_keep_it(text, ip):
    assert ("ipv4", ip) in _found(text)


@pytest.mark.parametrize("text", ["Log4j v2.17.1.0 is affected", "version 2.17.1.0", "rev. 1.2.3.4"])
def test_version_numbers_are_still_refused(text):
    assert not any(t == "ipv4" for t, _v in _found(text))
