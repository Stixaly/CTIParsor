"""#790: the Snort option splitter ignores quotes and backslash escapes.

A `;` inside a quoted msg or pcre value used to cut the option in two, so a valid rule
was refused. A `\\;` outside quotes lost its semicolon. The splitter now follows the
quoted string and the escapes, as `_split_options` does in suricata_atoms.py.
"""
import collections

from pipeline.detection.opencti_snort import Parser


def test_a_semicolon_inside_a_msg_string_does_not_split_the_option_issue_790():
    """`msg:"foo; bar";` is one option, so the rule parses (#790)."""
    parsed = Parser('alert tcp any any -> any any (msg:"foo; bar"; sid:1;)')
    assert parsed.options == collections.OrderedDict(
        [(0, ("msg", ['"foo; bar"'])), (1, ("sid", ["1"]))]
    )


def test_a_semicolon_inside_a_pcre_string_does_not_split_the_option_issue_790():
    """`pcre:"/a;b/";` is one option, and its value stays a str (#790)."""
    parsed = Parser('alert tcp any any -> any any (pcre:"/a;b/"; sid:1;)')
    assert parsed.options == collections.OrderedDict(
        [(0, ("pcre", '"/a;b/"')), (1, ("sid", ["1"]))]
    )


def test_an_escaped_semicolon_keeps_its_semicolon_issue_790():
    """`content:"a\\;b";` keeps the `\\;` as written, with no semicolon lost (#790)."""
    parsed = Parser(r'alert tcp any any -> any any (content:"a\;b"; sid:1;)')
    assert parsed.options[0] == ("content", ['"a\\;b"'])


def test_two_normal_options_are_unchanged_issue_790():
    """Two plain options split as before, and their values split at commas (#790)."""
    parsed = Parser("alert tcp any any -> any any (flow:established,to_server; sid:1;)")
    assert parsed.options == collections.OrderedDict(
        [(0, ("flow", ["established", "to_server"])), (1, ("sid", ["1"]))]
    )


def test_an_escaped_quote_in_a_msg_does_not_close_the_string_issue_790():
    """`msg:"say \\"hi\\"; ok";` is one option: the `\\"` does not end the string (#790)."""
    parsed = Parser(r'alert tcp any any -> any any (msg:"say \"hi\"; ok"; sid:1;)')
    assert parsed.options == collections.OrderedDict(
        [(0, ("msg", [r'"say \"hi\"; ok"'])), (1, ("sid", ["1"]))]
    )


def test_a_comma_inside_a_quoted_value_does_not_split_it_issue_790():
    """A comma inside a quoted value is part of the value, not a list separator (#790)."""
    parsed = Parser('alert tcp any any -> any any (msg:"a,b"; sid:1;)')
    assert parsed.options[0] == ("msg", ['"a,b"'])
