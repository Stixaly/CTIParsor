"""Issue #517: a blank YARA rule is refused, as #434 did for Sigma and Suricata.

`yara.compile("")` compiles an empty ruleset without error, so a blank rule used
to come out as "compiles" and would ship as an Indicator that OpenCTI takes for
a rule (ADR-0067, ADR-0070).
"""
import pytest

from pipeline.baseline_stix import _rule_verdict
from pipeline.detection.pattern_check import REFUSED
from pipeline.detection.yara_check import (
    COMPILES,
    DOES_NOT_COMPILE,
    compile_status,
    prepare_embedded_rule,
)

_BLANKS = ["", " ", "   \n", "\t\r\n "]


@pytest.mark.parametrize("blank", _BLANKS)
def test_a_blank_rule_does_not_compile_issue_517(blank):
    status, error = compile_status(blank)
    assert status == DOES_NOT_COMPILE
    assert error and "empty" in error


@pytest.mark.parametrize("blank", _BLANKS)
def test_a_blank_embedded_rule_is_refused_issue_517(blank):
    # The report's rule reaches the same check through prepare_embedded_rule.
    assert prepare_embedded_rule(blank).status == DOES_NOT_COMPILE


def test_a_blank_baseline_yara_object_is_refused_issue_517():
    assert _rule_verdict("yara", "  \n")[0] == REFUSED


def test_a_real_rule_still_compiles_issue_517():
    # Control: the blank check does not catch a rule with surrounding whitespace.
    pytest.importorskip("yara")
    assert compile_status("\n  rule ok { condition: true }\n") == (COMPILES, None)
