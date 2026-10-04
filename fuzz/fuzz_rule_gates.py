"""Fuzz the gates rules quoted in reports go through before OpenCTI (ADR-0081).

The first byte picks the gate, the rest is the rule:
  0 Sigma (pySigma, YAML), 1 Suricata (parsuricata), 2 Snort (OpenCTI's
  parser), 3 YARA (prepare_embedded_rule, which compiles with libyara, and
  split_rules), 4 a STIX pattern's literals (_pattern_strings).
A gate answers with a status — accepted, refused, unverified — and never
raises: a refusal must not take the rest of the bundle down.  libFuzzer
catches a crash of the native parsers (libyara), a hang (-timeout) and a
memory blow-up such as a YAML alias bomb (-rss_limit_mb).

    python fuzz/fuzz_rule_gates.py -max_total_time=60 -timeout=10 <corpus dir>
"""
import sys

import _harness  # noqa: F401  (path, quiet logs, no heavy models)
import atheris

with atheris.instrument_imports():
    from pipeline.detection import pattern_check, yara_check
    from pipeline.detection.yara_atoms import split_rules
    from pipeline.stage4_stix_mapping import _pattern_strings

GATE_STATUSES = {pattern_check.ACCEPTED, pattern_check.REFUSED, pattern_check.UNVERIFIED}
YARA_STATUSES = {yara_check.COMPILES, yara_check.DOES_NOT_COMPILE, yara_check.UNVERIFIED}
NET_AND_SIGMA = ("sigma", "suricata", "snort")


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    gate = data[0] % 5
    text = data[1:].decode("utf-8", errors="replace")
    if gate < 3:
        status, _ = pattern_check.check_pattern(NET_AND_SIGMA[gate], text)
        assert status in GATE_STATUSES, status
    elif gate == 3:
        assert yara_check.prepare_embedded_rule(text).status in YARA_STATUSES
        for rule in split_rules(text):
            assert rule.name
    else:
        for literal in _pattern_strings(text):
            assert literal in text


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
