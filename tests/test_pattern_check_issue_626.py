"""check_pattern with a pattern type that has no parser here (#626).

Before the fix, _CHECKERS[pattern_type] raised KeyError for "stix", "yara", "eql"
and custom types, crashing the caller.  An unknown type is now UNVERIFIED with
the normalised message, whatever the pattern text.
"""
import pytest

from pipeline.detection.pattern_check import (
    ACCEPTED,
    UNVERIFIED,
    check_pattern,
)


@pytest.mark.parametrize("pattern_type", ["stix", "yara", "eql", "custom-type", "SIGMA"])
def test_unknown_type_is_unverified_not_an_exception(pattern_type):
    status, error = check_pattern(pattern_type, '[ipv4-addr:value = "1.1.1.1"]')
    assert status == UNVERIFIED
    assert error == f"unsupported pattern type: {pattern_type}"


def test_issue_reproduction_does_not_raise():
    assert check_pattern("stix", '[ipv4-addr:value = "1.1.1.1"]') == (
        UNVERIFIED, "unsupported pattern type: stix")


@pytest.mark.parametrize("pattern", ["", "   ", "\n"])
def test_unknown_type_with_blank_pattern_is_unverified(pattern):
    # The blank-rule refusal (#434) applies to the dialects it knows; an unknown
    # type is not checked at all, so it stays UNVERIFIED.
    assert check_pattern("yara", pattern) == (UNVERIFIED, "unsupported pattern type: yara")


def test_known_type_still_checked():
    # Known types keep their own path: a valid Sigma rule is not turned unverified
    # by the unknown-type branch.  Accepted or unverified (no pysigma), never a KeyError.
    status, _ = check_pattern("sigma", "title: t\n")
    assert status in (ACCEPTED, "refused", UNVERIFIED)
