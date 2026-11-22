"""#792: Sanitizer.pcre must strip surrounding spaces and keep the negation '!' outside the quotes.

Before the fix, a leading '!' or space hid the opening quote from the check, so the slash was
inserted in front of the '!' or the space and the quote was doubled around the corrupted value.
"""
from pipeline.detection.opencti_snort import Parser
from pipeline.detection.opencti_snort.snort_parser import Sanitizer, SerializeRule


def test_sanitizer_pcre_keeps_negation_issue_792():
    """A negated pcre keeps its '!' in front of the quoted regex (#792)."""
    assert Sanitizer.pcre('!"/foo/i"') == '!"/foo/i"'


def test_sanitizer_pcre_strips_leading_space_issue_792():
    """A leading space is dropped before the quoted regex is checked (#792)."""
    assert Sanitizer.pcre(' "/foo/i"') == '"/foo/i"'


def test_sanitizer_pcre_negated_without_quotes_issue_792():
    """A negated pcre without quotes is quoted, with the '!' kept in front (#792)."""
    assert Sanitizer.pcre("!foo") == '!"/foo/"'


def test_sanitizer_pcre_without_quotes_is_unchanged_issue_792():
    """A pcre without quotes or '!' keeps the behaviour it had before the fix (#792)."""
    assert Sanitizer.pcre("abc") == '"/abc/"'
    assert Sanitizer.pcre("/abc/i") == '"/abc/i"'


def test_negated_pcre_rule_is_not_corrupted_issue_792():
    """A rule with a negated pcre goes through the parser and the sanitizer without corruption (#792)."""
    rule = 'alert tcp any any -> any any (pcre:!"/foo/i"; sid:1;)'
    sanitized = Sanitizer().sanitize(Parser(rule).data)
    serialized = SerializeRule(sanitized).serialize_rule()
    assert 'pcre:!"/foo/i"' in serialized
    assert '"/!"' not in serialized
