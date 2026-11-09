"""#624: pcre options must survive parse -> serialize, and Sanitizer.pcre must accept str and list.

The parser stores a pcre option as a plain str, while msg/sid/rev are lists. Joining the str
with ',' inserted a comma between every character, and Sanitizer.pcre read value[0] (a quote)
and appended a spurious slash.
"""
import pytest

from pipeline.detection.opencti_snort import Parser
from pipeline.detection.opencti_snort.snort_parser import Sanitizer, SerializeRule


def _roundtrip(rule_text: str) -> str:
    return SerializeRule(Parser(rule_text).data).serialize_rule()


def test_pcre_with_flags_round_trips_unchanged_issue_624():
    """The pcre option is re-exported exactly as it was written (#624)."""
    rule = 'alert tcp any any -> any any (msg:"Test PCRE"; pcre:"/abc/i"; sid:1000001; rev:1;)'
    serialized = _roundtrip(rule)
    assert 'pcre:"/abc/i"' in serialized
    assert ",/,a,b,c" not in serialized
    assert serialized == 'alert tcp any any -> any any (msg:"Test PCRE"; pcre:"/abc/i"; sid:1000001; rev:1)'


def test_pcre_without_flags_round_trips_unchanged_issue_624():
    """A pcre with no trailing flags is kept as written (#624)."""
    rule = 'alert tcp any any -> any any (msg:"x"; pcre:"/abc/"; sid:1;)'
    assert 'pcre:"/abc/"' in _roundtrip(rule)


def test_list_option_values_are_still_joined_with_commas_issue_624():
    """Options whose value is a list keep the ',' join (#624)."""
    rule = 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)'
    assert _roundtrip(rule) == 'alert tcp any any -> any any (msg:"Test"; sid:1; rev:1)'


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ('"/abc/i"', '"/abc/i"'),
        ('"/abc/"', '"/abc/"'),
        ('"/abc"', '"/abc/"'),
        ('"abc"', '"/abc/"'),
        ("abc", '"/abc/"'),
    ],
)
def test_sanitizer_pcre_handles_a_str_issue_624(value, expected):
    """A str is normalised to a well-formed "/regex/flags" without a spurious slash (#624)."""
    assert Sanitizer.pcre(value) == expected


def test_sanitizer_pcre_handles_a_list_and_keeps_its_shape_issue_624():
    """A list is fixed on its first element and returned as a list of the same shape (#624)."""
    assert Sanitizer.pcre(['"/abc/i"']) == ['"/abc/i"']
    assert Sanitizer.pcre(['"abc"', "extra"]) == ['"/abc/"', "extra"]
    assert Sanitizer.pcre([]) == []


def test_sanitize_then_serialize_keeps_pcre_issue_624():
    """The sanitizer pass followed by serialization leaves a well-formed pcre option (#624)."""
    parsed = Parser('alert tcp any any -> any any (msg:"x"; pcre:"/abc/i"; sid:1;)')
    sanitized = Sanitizer().sanitize(parsed.data)
    assert 'pcre:"/abc/i"' in SerializeRule(sanitized).serialize_rule()
