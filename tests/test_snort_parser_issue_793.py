"""#793: the non-bracketed port range is checked like the bracketed one.

`Parser.port` accepted `443:80` (low above high) and `80:443:8080` (three bounds) because
the range branch never checked the bound count or the order, and its `lstrip("!")` was
not reassigned.
"""
import pytest

from pipeline.detection.opencti_snort.snort_parser import Parser


@pytest.mark.parametrize("port", ["443:80", "80:443:8080"])
def test_a_malformed_or_reversed_port_range_is_refused_issue_793(port):
    """A range needs exactly two bounds, low first (#793)."""
    with pytest.raises(ValueError):
        Parser.port(port)


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        ("80:443", (True, "80:443")),
        (":1024", (True, ":1024")),
        ("1024:", (True, "1024:")),
        ("!1:1024", (False, "1:1024")),
        ("any", (True, "any")),
        ("$HTTP_PORTS", (True, "$HTTP_PORTS")),
        ("[80,443]", (True, [(True, "80"), (True, "443")])),
    ],
)
def test_a_valid_port_still_parses_issue_793(port, expected):
    """Open ranges, variables, `any`, negation and lists keep parsing (#793)."""
    assert Parser.port(port) == expected
