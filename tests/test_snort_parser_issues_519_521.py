"""#519, #520, #521: three local fixes in the copied Snort parser (snort_parser.py).

#519: a single address or variable in brackets (`[$HOME_NET]`, `[192.168.1.1]`) is
valid Snort and parses as a list of one.  #520: the port checks were tautologies
(`if port:`), so an out-of-range or unknown port was never refused.  #521:
`Sanitizer.sanitize` never matched an option (it keyed on the option index), and
`Sanitizer.depth` read a `(name, value)` tuple as a dict.
"""
import pytest

from pipeline.detection.opencti_snort import Parser
from pipeline.detection.opencti_snort.snort_parser import Sanitizer
from pipeline.detection.pattern_check import ACCEPTED, REFUSED, check_pattern

_OPTIONS = '(msg:"x"; sid:1; rev:1;)'
_DEPTH_RULE = 'alert tcp any any -> any any (msg:"x"; depth:10; dsize:20; sid:1;)'


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("[$HOME_NET]", (True, [(True, "$HOME_NET")])),
        ("[192.168.1.1]", (True, [(True, "192.168.1.1")])),
        ("![192.168.1.1]", (False, [(True, "192.168.1.1")])),
        ("[any]", (True, [(True, "any")])),
    ],
)
def test_a_single_bracketed_address_or_variable_parses_issue_519(source, expected):
    """A one-element bracket list is valid Snort and must parse as a list of one (#519)."""
    parsed = Parser(f"alert tcp {source} any -> any any {_OPTIONS}")
    assert parsed.header["source"] == expected


def test_a_single_bracketed_destination_is_accepted_by_the_gate_issue_519():
    """The gate ships what Parser accepts: a bracketed one-address destination (#519)."""
    rule = f"alert tcp any any -> [$EXTERNAL_NET] 443 {_OPTIONS}"
    assert check_pattern("snort", rule) == (ACCEPTED, None)


def test_an_unclosed_bracket_is_still_refused_issue_519():
    """The bracket fix must not accept a malformed `[` with no closing `]` (#519)."""
    with pytest.raises(ValueError):
        Parser(f"alert tcp [192.168.1.1 any -> any any {_OPTIONS}")


@pytest.mark.parametrize(
    "header",
    [
        "alert tcp any 999999 -> any any",
        "alert tcp any any -> any -500",
        "alert tcp any [999999] -> any any",
        "alert tcp any [-500] -> any any",
        "alert tcp any invalid_port -> any any",
        "alert tcp any 80:70000 -> any any",
    ],
)
def test_an_out_of_range_or_unknown_port_is_refused_issue_520(header):
    """`if port:` accepted every non-empty string, so no port was range-checked (#520)."""
    rule = f"{header} {_OPTIONS}"
    with pytest.raises(ValueError):
        Parser(rule)
    status, error = check_pattern("snort", rule)
    assert status == REFUSED and error


@pytest.mark.parametrize(
    "port",
    [
        "any",
        "$HTTP_PORTS",
        "[$SSH_PORTS]",
        "[80,443,$HTTP_PORTS]",
        "!80",
        "0",
        "65535",
        "80:443",
        "1024:",
        ":1024",
        "[1:1024,!8080]",
        "[!80:443,8080]",
    ],
)
def test_a_valid_snort_port_stays_accepted_issue_520(port):
    """Every port Snort accepts must still parse, variables included (#520)."""
    rule = f"alert tcp any {port} -> any any {_OPTIONS}"
    assert check_pattern("snort", rule) == (ACCEPTED, None)


def test_depth_reads_the_option_value_issue_521():
    """`depth` read `options[idx].get(...)` on a tuple and raised AttributeError (#521)."""
    assert Sanitizer.depth(Parser(_DEPTH_RULE).options) == "20"


@pytest.mark.parametrize(
    ("depth", "dsize", "expected"),
    [
        ("10", ">20", "20"),
        ("30", ">20", "30"),
        ("10", "20", "20"),
    ],
)
def test_depth_compares_depth_with_dsize_issue_521(depth, dsize, expected):
    """The comparison is unchanged: the larger of depth and the dsize number (#521)."""
    rule = f'alert tcp any any -> any any (msg:"x"; depth:{depth}; dsize:{dsize}; sid:1;)'
    assert Sanitizer.depth(Parser(rule).options) == expected


def test_sanitize_applies_the_pcre_method_to_a_pcre_option_issue_521():
    """`methods` is keyed by option name, so sanitize must match the name, not the index (#521)."""
    parsed = Parser('alert tcp any any -> any any (msg:"x"; pcre:"abc"; sid:1;)')
    result = Sanitizer().sanitize(parsed.data)
    pcre_options = [value for value in result["options"].values() if value[0] == "pcre"]
    assert pcre_options == [("pcre", Sanitizer.pcre('"abc"'))]


def test_sanitize_leaves_the_other_options_alone_issue_521():
    """Only the options with a method are rewritten; `msg` keeps its tuple (#521)."""
    parsed = Parser('alert tcp any any -> any any (msg:"x"; pcre:"abc"; sid:1;)')
    before = list(parsed.options.values())
    result = Sanitizer().sanitize(parsed.data)
    assert [value for value in result["options"].values() if value[0] != "pcre"] == [
        value for value in before if value[0] != "pcre"
    ]


def test_sanitize_does_not_crash_on_a_depth_rule_issue_521():
    """A rule with depth and dsize goes through sanitize without an exception (#521)."""
    result = Sanitizer().sanitize(Parser(_DEPTH_RULE).data)
    assert result["options"] == Parser(_DEPTH_RULE).options
