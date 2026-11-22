"""#791: validate_options skipped the option-name check for a content-modifier value.

With a single value that Dicts counts as a content modifier (`nocase`), the loop
continued before looking at the option name, so `not_a_real_option:nocase` was
accepted. The name is now checked first. Real content modifiers written alone
(`nocase;`, `depth:4;`) must keep passing.
"""
import pytest

from pipeline.detection.opencti_snort import Parser


def test_an_unknown_option_with_a_content_modifier_value_is_refused_issue_791():
    """`not_a_real_option:nocase` used to pass because `nocase` was the value (#791)."""
    with pytest.raises(ValueError, match="unrecognized option: not_a_real_option"):
        Parser("alert tcp any any -> any any (not_a_real_option:nocase; sid:1;)")


def test_a_content_modifier_after_content_still_parses_issue_791():
    """Bare content modifiers and depth/offset keep passing after a content match (#791)."""
    rule = 'alert tcp any any -> any any (content:"abc"; nocase; depth:4; offset:2; sid:1;)'
    assert Parser(rule).options


def test_a_pcre_flag_option_still_parses_issue_791():
    """A pcre value with flags is not a content modifier and must keep parsing (#791)."""
    assert Parser('alert tcp any any -> any any (pcre:"/x/i"; sid:1;)').options
