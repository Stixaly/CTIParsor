"""Regression tests for issue #420: YARA dedup keys and the blanks in `condition:`.

The condition is normalized for blanks outside its literals only.  Two rules whose
conditions name different modules (`"kernel32  .dll"` vs `"kernel32 .dll"`) must
not share a key.  Comments are not removed: a comment only keeps two rules apart.
"""
from __future__ import annotations

from pipeline.detection.yara import YaraAdapter
from pipeline.detection.yara_atoms import split_rules


def _key(condition: str) -> str:
    text = (
        'rule R {\n  strings:\n    $a = "abcdef"\n  condition:\n    '
        + condition + "\n}\n"
    )
    return YaraAdapter()._dedup_key(split_rules(text)[0])


def test_blanks_inside_a_condition_literal_keep_rules_apart_issue_420():
    """`pe.imports("kernel32  .dll")` and `pe.imports("kernel32 .dll")` differ."""
    assert _key('pe.imports("kernel32  .dll") and $a') != _key(
        'pe.imports("kernel32 .dll") and $a')


def test_blanks_inside_a_matches_regex_keep_rules_apart_issue_420():
    """The blanks of a regex after `matches` are data too."""
    assert _key("filename matches /a  b/ and $a") != _key("filename matches /a b/ and $a")


def test_blanks_outside_literals_are_still_ignored_issue_420():
    """Control: runs of blanks between tokens do not change the key."""
    assert _key("$a  and\n\t$a") == _key("$a and $a")


def test_identical_conditions_still_share_a_key_issue_420():
    """Control: the same rule written twice keeps one key."""
    assert _key('pe.imports("kernel32.dll") and $a') == _key(
        'pe.imports("kernel32.dll")   and   $a')
