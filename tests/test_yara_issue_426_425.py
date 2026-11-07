"""Regression tests for YARA atoms: issues #426, #425 and the regex part of #427.

#426: a trailing dot is the FQDN form, and `www.` is not a label of its own.
#425: `meta:` and `strings:` are read from the comment-free rule, and the section
keywords are searched outside string and regex literals.
#427: a regex after `matches` is a regex for the comment stripper too.
"""
from __future__ import annotations

import pytest

from pipeline.detection.yara_atoms import _strip_comments, extract_atoms, split_rules


def _atoms(literal: str) -> list[tuple[str, str]]:
    text = 'rule D {\n  strings:\n    $a = "' + literal + '"\n  condition:\n    $a\n}\n'
    return extract_atoms(split_rules(text)[0])


# ---------------------------------------------------------------------------
# #426 — domains
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal, expected", [
    # Fixed: the trailing dot is the FQDN form, not a reason to reject the domain.
    ("evil.com.", ("domain", "evil.com")),
    # Fixed: `www.online` is the word `online` once `www.` goes; it is not a domain.
    ("www.online", ("strlit", "www.online")),
    # Controls: `www.` is still removed from a real domain, and a bare domain is kept.
    ("www.evil.com", ("domain", "evil.com")),
    ("example.online", ("domain", "example.online")),
])
def test_trailing_dot_and_bare_www_label_issue_426(literal, expected):
    """A FQDN with a final dot is a domain; a lone label after `www.` is not."""
    assert _atoms(literal) == [expected]


# ---------------------------------------------------------------------------
# #425 — commented lines and literals inside the rule
# ---------------------------------------------------------------------------

def test_a_commented_meta_line_is_not_metadata_issue_425():
    """`author = "evil"` inside a block comment in the rule is not a meta value."""
    text = (
        'rule M {\n  meta:\n    author = "real"\n  /*\n    author = "evil"\n  */\n'
        '  strings:\n    $s = "realstring.here"\n  condition:\n    $s\n}\n'
    )
    assert split_rules(text)[0].meta == {"author": "real"}


def test_a_line_commented_meta_line_is_not_metadata_issue_425():
    """The same holds for a `//` comment line in `meta:`."""
    text = (
        'rule M {\n  meta:\n    author = "real"\n    // author = "evil"\n'
        '  condition:\n    true\n}\n'
    )
    assert split_rules(text)[0].meta == {"author": "real"}


def test_a_commented_string_is_not_a_string_issue_425():
    """`$c` on its own line inside a block comment in `strings:` yields no atom."""
    text = (
        'rule M {\n  strings:\n    /*\n    $c = "commented.evil.example"\n    */\n'
        '    $s = "realstring.here"\n  condition:\n    $s\n}\n'
    )
    rule = split_rules(text)[0]
    assert rule.strings == [("$s", "text", "realstring.here")]
    assert [v for _, v in extract_atoms(rule)] == ["realstring.here"]


def test_condition_keyword_in_a_string_does_not_cut_the_strings_issue_425():
    """`"say condition: now"` is a literal: the strings section runs to the real
    `condition:`, so `$t` after it is still read."""
    text = (
        'rule T {\n  strings:\n    $s = "say condition: now"\n'
        '    $t = "tailstring.here"\n  condition:\n    $s and $t\n}\n'
    )
    assert split_rules(text)[0].strings == [
        ("$s", "text", "say condition: now"),
        ("$t", "text", "tailstring.here"),
    ]


def test_condition_keyword_in_a_regex_does_not_cut_the_strings_issue_425():
    """The same holds for a regex literal containing `condition:`."""
    text = (
        'rule T {\n  strings:\n    $r = /condition:/\n'
        '    $t = "tailstring.here"\n  condition:\n    $r and $t\n}\n'
    )
    assert split_rules(text)[0].strings == [
        ("$r", "regex", "condition:"),
        ("$t", "text", "tailstring.here"),
    ]


def test_strings_keyword_in_a_meta_value_does_not_cut_the_meta_issue_425():
    """`strings:` inside a meta string does not end `meta:` early."""
    text = (
        'rule T {\n  meta:\n    description = "see strings: below"\n'
        '    author = "real"\n  strings:\n    $s = "realstring.here"\n'
        '  condition:\n    $s\n}\n'
    )
    assert split_rules(text)[0].meta == {"description": "see strings: below", "author": "real"}


# ---------------------------------------------------------------------------
# #427 — comment stripping after `matches`
# ---------------------------------------------------------------------------

def test_a_regex_after_matches_holding_a_star_is_not_a_block_comment_issue_427():
    """`/a\\/*b/` after `matches` is a regex; its `/*` must not open a comment
    that swallows the rest of the file."""
    text = (
        'rule R1 {\n  condition:\n    filename matches /a\\/*b/ and true\n}\n'
        'rule R2 {\n  condition:\n    true\n}\n'
    )
    assert [r.name for r in split_rules(text)] == ["R1", "R2"]
    assert len(_strip_comments(text)) == len(text)


def test_a_comment_after_a_matches_regex_is_still_blanked_issue_427():
    """Control: a real `//` comment after a `matches` regex is still removed."""
    text = 'filename matches /x/ and true // gone\n$a = /y/ /* gone */ $b'
    assert _strip_comments(text).split() == [
        "filename", "matches", "/x/", "and", "true", "$a", "=", "/y/", "$b",
    ]
