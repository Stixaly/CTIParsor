"""ADR-0070: a Sigma, Suricata or Snort rule quoted in a report ships only if
the parser OpenCTI uses for its pattern_type accepts it."""
import sys

import pytest

from pipeline.bundle_ledger import MappingLedger
from pipeline.detection.pattern_check import (
    ACCEPTED,
    REFUSED,
    UNVERIFIED,
    check_pattern,
    net_rule_dialect,
)
from pipeline.stage3_llm import LLMEnrichmentResult
from pipeline.stage4_stix_mapping import build_stix_bundle

pytest.importorskip("sigma")
pytest.importorskip("parsuricata")

# From ET Open: Suricata syntax, an application-layer protocol Snort's parser
# does not know.
_ET_HTTP = ('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Test Checkin"; '
            'flow:established,to_server; http.method; content:"POST"; sid:2099999; rev:1;)')
# What a PDF layout leaves of it: the line wrapped, the finder kept the first part.
_ET_TRUNCATED = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE (Test) Checkin";'

_SIGMA = """title: Suspicious PowerShell Download
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: DownloadString
    condition: selection
level: high"""


def test_a_suricata_rule_is_accepted():
    assert check_pattern("suricata", _ET_HTTP) == (ACCEPTED, None)


def test_a_truncated_rule_is_refused_with_the_parsers_message():
    status, error = check_pattern("suricata", _ET_TRUNCATED)
    assert status == REFUSED and error


def test_a_suricata_rule_typed_snort_by_its_context_is_retyped():
    assert check_pattern("snort", _ET_HTTP)[0] == REFUSED     # OpenCTI's Snort parser
    assert net_rule_dialect("snort", _ET_HTTP) == ("suricata", ACCEPTED, None, "snort")


def test_a_rule_both_parsers_refuse_keeps_its_type_and_is_refused():
    ptype, status, error, retyped = net_rule_dialect("suricata", _ET_TRUNCATED)
    assert (ptype, status, retyped) == ("suricata", REFUSED, None) and error


def test_a_sigma_rule_without_a_condition_is_refused():
    assert check_pattern("sigma", _SIGMA)[0] == ACCEPTED
    no_condition = _SIGMA.replace("    condition: selection\n", "")
    assert check_pattern("sigma", no_condition)[0] == REFUSED


def test_a_very_long_line_is_refused_without_parsing():
    status, error = check_pattern("snort", "alert tcp any any -> any any (" + "a" * 20000 + ")")
    assert status == REFUSED and "longer than" in error


def test_without_the_parser_the_rule_is_unverified(monkeypatch):
    monkeypatch.setitem(sys.modules, "parsuricata", None)
    assert check_pattern("suricata", _ET_HTTP) == (UNVERIFIED, None)


def test_stage4_ships_the_retyped_rule_and_leaves_out_the_truncated_one():
    led = MappingLedger()
    text = f"Snort and Suricata signatures:\n\n{_ET_HTTP}\n\n{_ET_TRUNCATED}\n\nProse."
    bundle = build_stix_bundle([], LLMEnrichmentResult(), "r", report_text=text, ledger=led)

    shipped = [o for o in bundle.objects if o.get("type") == "indicator"]
    assert [(o.pattern_type, o.pattern) for o in shipped] == [("suricata", _ET_HTTP)]
    assert led.objects[shipped[0].id]["retyped_from"] == "snort"
    (removed,) = led.removed
    assert removed["reason"] == "rule_does_not_parse" and removed["error"]
