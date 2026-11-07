"""Suricata atoms: `pkt_data` closes the sticky buffer, `content:` ends at its quote (issue #428).

Before the fix `pkt_data` left the buffer of the content before it in place, so a
raw-packet literal was classified by that buffer (`url`), and `_unquote` kept the
modifiers after the closing quote (`"/gate.php", fast_pattern` became the atom).
"""
from __future__ import annotations

from pipeline.detection.suricata_atoms import _unquote, extract_atoms

_HEAD = 'alert http any any -> any any (msg:"x"; flow:established; '


def test_pkt_data_closes_the_sticky_buffer_issue_428():
    rule = _HEAD + 'http.uri; content:"/a1.php"; pkt_data; content:"/b2-raw-path.php"; sid:1;)'
    atoms = extract_atoms(rule)
    assert ("url", "/a1.php") in atoms
    assert ("strlit", "/b2-raw-path.php") in atoms
    assert ("url", "/b2-raw-path.php") not in atoms


def test_pkt_data_alone_is_the_raw_packet_control_issue_428():
    rule = _HEAD + 'pkt_data; content:"/b2-raw-path.php"; sid:1;)'
    assert extract_atoms(rule) == [("strlit", "/b2-raw-path.php")]


def test_fast_pattern_is_not_part_of_the_literal_issue_428():
    rule = _HEAD + 'content:"/gate.php", fast_pattern; sid:2;)'
    assert extract_atoms(rule) == [("strlit", "/gate.php")]


def test_nocase_is_not_part_of_the_literal_issue_428():
    rule = _HEAD + 'content:"/gate.php", nocase; sid:3;)'
    assert extract_atoms(rule) == [("strlit", "/gate.php")]


def test_modifier_after_a_semicolon_form_is_still_ignored_issue_428():
    rule = _HEAD + 'content:"/gate.php"; fast_pattern; sid:4;)'
    assert extract_atoms(rule) == [("strlit", "/gate.php")]


def test_unquote_returns_only_the_quoted_text_issue_428():
    assert _unquote('"/gate.php", fast_pattern') == "/gate.php"
    assert _unquote('"/gate.php"') == "/gate.php"
    assert _unquote('"a \\" b", nocase') == 'a \\" b'
    assert _unquote('"a\\\\", nocase') == "a\\\\"


def test_unquote_leaves_an_unquoted_value_alone_issue_428():
    assert _unquote("|00 01|") == "|00 01|"
    assert _unquote('"never closed') == '"never closed'
