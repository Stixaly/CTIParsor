"""Issue #434: a blank rule is refused whatever its type, before the parser of
its dialect is asked about it.  The Sigma and Suricata parsers return an empty
result on "" without raising, so the empty pattern used to come out ACCEPTED
and would ship as an Indicator that OpenCTI takes for a rule (ADR-0070)."""
import pytest

from pipeline.baseline_stix import _rule_verdict
from pipeline.detection.pattern_check import (
    ACCEPTED,
    REFUSED,
    check_pattern,
    net_rule_dialect,
)

pytest.importorskip("sigma")
pytest.importorskip("parsuricata")

_BLANKS = ["", " ", "   \n", "\t\r\n "]

_ET_HTTP = ('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Test Checkin"; '
            'flow:established,to_server; http.method; content:"POST"; sid:2099999; rev:1;)')


@pytest.mark.parametrize("pattern_type", ["sigma", "suricata", "snort"])
@pytest.mark.parametrize("blank", _BLANKS)
def test_a_blank_rule_is_refused_for_every_type_issue_434(pattern_type, blank):
    status, error = check_pattern(pattern_type, blank)
    assert status == REFUSED
    assert error and "empty" in error


def test_a_blank_suricata_rule_is_not_retyped_to_suricata_issue_434():
    # Snort refused "" already, and Suricata accepted it: the dialect fix used to
    # turn a blank rule typed snort into an accepted suricata one.
    ptype, status, error, retyped = net_rule_dialect("snort", "")
    assert (ptype, status, retyped) == ("snort", REFUSED, None) and error


def test_a_blank_baseline_rule_is_refused_issue_434():
    # Baseline Indicators reach the same check through _rule_verdict.
    assert _rule_verdict("sigma", "")[0] == REFUSED
    assert _rule_verdict("suricata", "  ")[0] == REFUSED


def test_a_real_rule_is_still_accepted_issue_434():
    # Control: the blank check does not catch a rule with surrounding whitespace.
    assert check_pattern("suricata", "\n" + _ET_HTTP + "\n") == (ACCEPTED, None)
