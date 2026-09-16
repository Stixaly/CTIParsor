from __future__ import annotations

import importlib.util
import re
import time

import pytest

from pipeline.stage2_extraction import _compile_pattern, extract_entities, refang

_HAS_RE2 = importlib.util.find_spec("re2") is not None


def test_compile_pattern_returns_stdlib_when_re2_absent_or_flag_unsupported():
    assert isinstance(_compile_pattern(r"abc", re.VERBOSE), re.Pattern)


@pytest.mark.skipif(not _HAS_RE2, reason="re2 not installed")
def test_compile_pattern_uses_re2_when_available_and_supported():
    import re2 as re2_module  # noqa: F401

    p = _compile_pattern(r"abc")
    assert type(p).__module__ == "re2"
    assert not isinstance(p, re.Pattern)

    p2 = _compile_pattern(r"abc", re.IGNORECASE)
    assert bool(p2.search("ABC"))
    assert type(p2).__module__ == "re2"


@pytest.mark.skipif(not _HAS_RE2, reason="re2 not installed")
def test_ignorecase_via_re2_matches_correctly():
    p = _compile_pattern(r"hello", re.IGNORECASE)
    assert p.search("HELLO WORLD") is not None
    assert p.search("goodbye") is None


@pytest.mark.skipif(not _HAS_RE2, reason="re2 not installed")
def test_catastrophic_backtracking_pattern_finishes_fast_under_re2():
    p = _compile_pattern(r"(a+)+$")
    text = "a" * 30 + "b"
    start = time.monotonic()
    p.search(text)
    elapsed = time.monotonic() - start
    # this exact pattern is catastrophic on stdlib `re` (exponential blowup
    # past ~25 "a"s); re2 guarantees linear time regardless.
    assert elapsed < 1.0


def test_extract_entities_same_result_with_and_without_re2(monkeypatch):
    text = (
        "CVE-2024-12345 "
        "5d41402abc4b2a76b9719d911017c592 "
        "192.168.1.1 "
        "evil-domain.com "
        "https://example.com/path "
        "test@example.com "
        "C:\\Windows\\System32\\cmd.exe "
        "HKLM\\SOFTWARE\\Test "
        "T1059.001"
    )
    result_with_re2 = extract_entities(text)
    monkeypatch.setattr("pipeline.stage2_extraction._RE2_AVAILABLE", False)
    result_without_re2 = extract_entities(text)

    assert len(result_with_re2) == len(result_without_re2)
    set_with = {(e.value.lower(), e.entity_type) for e in result_with_re2}
    set_without = {(e.value.lower(), e.entity_type) for e in result_without_re2}
    assert set_with == set_without


def test_refang_same_result_with_and_without_re2(monkeypatch):
    text = "see hxxps://evil[.]com and foo[at]bar(dot)com and normal text[.]here"
    result_with_re2 = refang(text)
    monkeypatch.setattr("pipeline.stage2_extraction._RE2_AVAILABLE", False)
    result_without_re2 = refang(text)
    assert result_with_re2 == result_without_re2
