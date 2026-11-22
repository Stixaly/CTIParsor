r"""#789: the address splitter of the copied Snort parser (snort_parser.py).

`Parser.__flatten_ip` split a bracketed list with `re.split(r",(!?\[.*\])")`, a greedy
pattern that needs a comma before each nested list. It failed when a nested list was
first, when it was followed by a plain item, or when two nested lists sat side by side.
The split now runs on the commas outside any bracket. Unbalanced brackets still raise
ValueError.
"""
import pytest

from pipeline.detection.opencti_snort import Parser

_OPTIONS = '(msg:"x"; sid:1; rev:1;)'


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "[$HOME_NET,[192.168.1.1],$EXTERNAL_NET]",
            (True, [(True, "$HOME_NET"), (True, [(True, "192.168.1.1")]), (True, "$EXTERNAL_NET")]),
        ),
        (
            "[[192.168.1.1],$HOME_NET]",
            (True, [(True, [(True, "192.168.1.1")]), (True, "$HOME_NET")]),
        ),
        (
            "[$HOME_NET,[192.168.1.1],[10.0.0.1]]",
            (True, [(True, "$HOME_NET"), (True, [(True, "192.168.1.1")]), (True, [(True, "10.0.0.1")])]),
        ),
    ],
)
def test_a_nested_list_anywhere_in_the_bracket_parses_issue_789(source, expected):
    """A `[...]` sub-list may come first, sit between plain items, or follow another one (#789)."""
    parsed = Parser(f"alert tcp {source} any -> any any {_OPTIONS}")
    assert parsed.header["source"] == expected


@pytest.mark.parametrize(
    "source",
    [
        "[192.168.1.1,[10.0.0.1]",
        "[[10.0.0.1],$HOME_NET",
        "[10.0.0.1],[192.168.1.1]]",
        "[$HOME_NET,[192.168.1.1]]]",
    ],
)
def test_unbalanced_brackets_are_still_refused_issue_789(source):
    """The new splitter must not accept an unclosed or extra `]` (#789)."""
    with pytest.raises(ValueError):
        Parser(f"alert tcp {source} any -> any any {_OPTIONS}")


def test_a_simple_comma_list_is_unchanged_issue_789():
    """A flat list without nested brackets parses as before (#789)."""
    parsed = Parser(f"alert tcp [10.0.0.1,!10.0.0.2] any -> any any {_OPTIONS}")
    assert parsed.header["source"] == (True, [(True, "10.0.0.1"), (False, "10.0.0.2")])
