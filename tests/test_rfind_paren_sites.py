"""Rule bodies are cut at the `)` that closes the options, not the last `)` of
the line, wherever a Suricata rule line is read (issue #797, the sibling sites
that still used `rfind(")")`).

The first test fails on the code before its fix: the comment's `msg:` option
overwrote the rule's own title.
"""
from __future__ import annotations

from pipeline import stage4_stix_mapping as s4
from pipeline.detection.suricata_atoms import rule_body


def test_embedded_rule_title_ignores_options_in_a_trailing_comment():
    line = 'alert tcp any any -> any any (msg:"x"; sid:1;) # (note; msg:"spoof")'
    assert s4._find_embedded_net_rules(line) == [("suricata", line, "x")]


def test_embedded_rule_with_a_parenthesised_trailing_comment_keeps_its_title():
    line = 'alert tcp any any -> any any (msg:"x"; content:"a"; sid:1;) # (note evil.com)'
    assert s4._find_embedded_net_rules(line)[0][2] == "x"


def test_rule_body_stops_at_the_closing_paren_before_a_comment():
    line = 'alert tcp any any -> any any (msg:"x"; content:"a"; sid:1;) # (note evil.com)'
    assert rule_body(line) == 'msg:"x"; content:"a"; sid:1;'
