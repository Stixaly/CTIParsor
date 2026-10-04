"""The regexes CodeQL flagged as polynomial (py/polynomial-redos) stay linear
without re2.

`compile_pattern` uses re2 when it is installed (the image, CI), and stdlib
`re` otherwise — a source install, a dev venv.  Each pattern below once had
two adjacent quantifiers sharing a character, which backtracking `re` tries
pairwise: quadratic (one, cubic) on a run of blanks.  Every check compiles the
pattern with stdlib `re` on purpose, on the input CodeQL named; the old forms
took seconds to minutes there.
"""
import re
import time

import pytest

from pipeline import stage2_extraction as s2
from pipeline import stage2c_ttp_semantic as s2c
from pipeline import stage4_stix_mapping as s4
from pipeline import temporal
from pipeline.detection import yara_atoms

N = 50_000
BUDGET_S = 1.0          # linear: milliseconds; the old forms: seconds or more


def _stdlib(compiled) -> re.Pattern:
    return re.compile(compiled.pattern)       # re2's `.pattern` carries flags inline


def _fast(fn, arg) -> None:
    start = time.perf_counter()
    fn(arg)
    assert time.perf_counter() - start < BUDGET_S


@pytest.mark.parametrize("rx, text", [
    (temporal._R_Q, "q1" + " " * N + "x"),
    (temporal._R_Y_Q, "2024" + " " * N + "x"),
    (temporal._R_H, "h1" + " " * N + "x"),
    (yara_atoms._RE_META_LINE, "_=" + " " * N + "\n\n"),
    (yara_atoms._RE_STRING_DECL, "$=" + " " * N + "\n\n"),
])
def test_anchored_patterns_are_linear_under_stdlib_re(rx, text):
    _fast(_stdlib(rx).match, text)


@pytest.mark.parametrize("text", ["rule a :" + "\t" * N, "rule a" + "\t" * N])
def test_the_yara_rule_header_is_linear_under_stdlib_re(text):
    rx = _stdlib(yara_atoms._RE_RULE)
    _fast(lambda s: list(rx.finditer(s)), text)


def test_refang_is_linear_under_stdlib_re():
    rx = _stdlib(s2._DEFANG_PATTERN)
    _fast(lambda s: rx.sub(s2._defang_repl, s), " " * N + "x")


def test_stripping_and_pattern_literals_are_linear():
    _fast(s2c._strip_non_letters, "a" + "`" * N + "a")
    _fast(s4._pattern_strings, "'" + "\\'&" * N)


# ── Same results as before ───────────────────────────────────────────────────

def test_quarters_and_halves_still_parse():
    assert temporal._R_Q.match("q3 - 2024").groups() == ("3", "2024")
    assert temporal._R_Q.match("q3/2024").groups() == ("3", "2024")
    assert temporal._R_Q.match("q32024").groups() == ("3", "2024")
    assert temporal._R_Y_Q.match("2024 q2").groups() == ("2024", "2")
    assert temporal._R_H.match("h2 2023").groups() == ("2", "2023")
    assert temporal._R_Q.match("q3 -- 2024") is None


def test_yara_headers_tags_and_meta_still_parse():
    rules = yara_atoms.split_rules(
        'rule a : apt  tag2\n{\n meta:\n  author =   "x"\n strings:\n  $s =   "evil"\n'
        " condition:\n  $s\n}\n"
        "private rule b\n{\n condition:\n  true\n}\n")
    assert [(r.name, r.is_private, r.tags) for r in rules] == [
        ("a", False, ["apt", "tag2"]), ("b", True, [])]
    assert rules[0].meta == {"author": "x"}
    assert rules[0].strings == [("$s", "text", "evil")]


def test_spaced_defang_still_collapses():
    assert s2.refang("evil [.] com and evil (.) org") == "evil.com and evil.org"


def test_non_letter_edges_and_pattern_literals():
    assert s2c._strip_non_letters("(Enforce") == "Enforce"
    assert s2c._strip_non_letters("Restrict,") == "Restrict"
    assert s2c._strip_non_letters("1234") == ""
    assert s4._pattern_strings("[file:hashes.'SHA-256' = 'ab'] AND [url:value = 'x\\'y']") == [
        "SHA-256", "ab", "x\\'y"]
    assert s4._pattern_strings("[url:value = 'never closed") == []
