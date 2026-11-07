"""Regression tests for issue #427: YARA regexes after ``matches`` in ``condition:``.

``_find_rule_end`` used to read a ``/`` as a regex only after ``=`` (the strings
section).  A regex after the ``matches`` operator was then scanned as code, so its
braces and quotes moved the closing brace of the rule.
"""
from __future__ import annotations

from pipeline.detection.yara_atoms import split_rules

# Each rule is written as it appears in a file; ``body`` must equal it exactly.
R1 = "\n".join([
    "rule R1 {",
    "  condition:",
    r"    filename matches /\{abc/ and true",
    "}",
])
R2 = "\n".join([
    "rule R2 {",
    "  condition:",
    "    true",
    "}",
])
R3 = "\n".join([
    "rule R3 {",
    "  condition:",
    r"    filename matches /ab\}c/ and true",
    "}",
])
R4 = "\n".join([
    "rule R4 {",
    "  condition:",
    '    filename matches /"/ and true',
    "}",
])
R5 = "\n".join([
    "rule R5 {",
    "  condition:",
    "    true",
    "}",
])


def test_brace_in_matches_regex_keeps_rule_issue_427():
    """``/\\{abc/`` after ``matches`` must not count as an opening brace."""
    rules = split_rules(R1 + "\n" + R2 + "\n")
    assert [r.name for r in rules] == ["R1", "R2"]
    assert rules[0].body == R1
    assert rules[1].body == R2


def test_closing_brace_in_matches_regex_does_not_truncate_next_rule_issue_427():
    """``/ab\\}c/`` after ``matches`` must not close the rule early."""
    rules = split_rules(R3 + "\n" + R5 + "\n")
    assert [r.name for r in rules] == ["R3", "R5"]
    assert rules[0].body == R3
    assert rules[1].body == R5


def test_quote_in_matches_regex_does_not_hide_next_rule_issue_427():
    """``/"/`` after ``matches`` must not open a double-quoted string."""
    rules = split_rules(R4 + "\n" + R5 + "\n")
    assert [r.name for r in rules] == ["R4", "R5"]
    assert rules[0].body == R4
    assert rules[1].body == R5


def test_escaped_slash_and_modifier_in_matches_regex_issue_427():
    """``\\/`` does not end the regex; the ``i`` modifier after it is plain text."""
    text = "\n".join([
        "rule R6 {",
        "  condition:",
        r"    filename matches /a\/{b/i and true",
        "}",
    ]) + "\n" + R2
    rules = split_rules(text)
    assert [r.name for r in rules] == ["R6", "R2"]
    assert rules[0].body.endswith("}")
    assert rules[1].body == R2


def test_division_in_condition_is_not_a_regex_issue_427():
    """Control: ``/`` after a number is division, so the rule is kept whole."""
    r7 = "\n".join([
        "rule R7 {",
        "  condition:",
        "    filesize / 2 > 10 and true",
        "}",
    ])
    rules = split_rules(r7 + "\n" + R2 + "\n")
    assert [r.name for r in rules] == ["R7", "R2"]
    assert rules[0].body == r7


def test_regex_in_strings_section_still_skipped_issue_427():
    """Control: a regex after ``=`` in ``strings:`` keeps working as before."""
    r8 = "\n".join([
        "rule R8 {",
        "  strings:",
        r"    $re = /a\{b/",
        r"    $ce = /\}x/",
        "  condition:",
        "    $re or $ce",
        "}",
    ])
    rules = split_rules(r8 + "\n" + R2 + "\n")
    assert [r.name for r in rules] == ["R8", "R2"]
    assert rules[0].body == r8
    assert [s[0] for s in rules[0].strings] == ["$re", "$ce"]
