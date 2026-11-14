"""Detection atom bugs: bracketed header lists, trailing comments, noise after
normalization (issues #796, #797, #799).

Each test fails on the code before its fix, except the ones that guard behaviour
the fix must keep (a `)` inside a quoted option, a non-noisy domain).
"""
from __future__ import annotations

from pathlib import Path

from pipeline.detection.suricata import SuricataAdapter
from pipeline.detection.suricata_atoms import _normalize as suricata_normalize
from pipeline.detection.suricata_atoms import (
    rule_header,
    rule_metadata,
    technique_ids,
)
from pipeline.detection.yara_atoms import _normalize as yara_normalize


def _rule(line: str):
    return SuricataAdapter()._to_rule(line, Path("test.rules"), 1, "et", "MIT")


# --- #796: a bracketed list with spaces is one header field -----------------

_BRACKETED_HEADER = 'alert tcp [1.2.3.4, 5.6.7.8] [80, 443] -> any any (msg:"Tor exit"; sid:1001;)'


def test_bracketed_header_lists_with_spaces_are_one_field_issue_796():
    assert rule_header(_BRACKETED_HEADER) == {
        "action": "alert",
        "proto": "tcp",
        "src_ip": "[1.2.3.4, 5.6.7.8]",
        "src_port": "[80, 443]",
        "direction": "->",
        "dst_ip": "any",
        "dst_port": "any",
    }


def test_bracketed_header_lists_yield_every_address_and_port_issue_796():
    atoms = _rule(_BRACKETED_HEADER).atoms
    assert ("ip", "1.2.3.4") in atoms
    assert ("ip", "5.6.7.8") in atoms
    assert ("port", "80") in atoms
    assert ("port", "443") in atoms


# --- #797: the rule body ends at the `)` that closes the options ------------

_TRAILING_COMMENT = 'alert tcp any any -> any any (msg:"Test"; sid:1003;) # ; content:"evil.com"; (note)'


def test_trailing_comment_does_not_leak_atoms_issue_797():
    assert _rule(_TRAILING_COMMENT).atoms == []


def test_trailing_comment_does_not_leak_metadata_issue_797():
    line = 'alert tcp any any -> any any (msg:"x"; sid:1;) # ; metadata:mitre_technique_id T1095; (x)'
    assert rule_metadata(line) == {}
    assert technique_ids(line) == []


def test_closing_paren_inside_quoted_option_keeps_whole_body_issue_797():
    line = 'alert tcp any any -> any any (msg:"a # (b)"; content:"evil.com"; sid:1;)'
    rule = _rule(line)
    assert rule.title == "a # (b)"
    assert ("domain", "evil.com") in rule.atoms


# --- #799: NOISE_LITERALS is checked after www. and trailing dot are removed --

def test_yara_noise_domain_is_dropped_after_normalization_issue_799():
    assert yara_normalize("domain", "www.example.com") == []
    assert yara_normalize("domain", "example.com.") == []


def test_suricata_noise_domain_is_dropped_after_normalization_issue_799():
    assert suricata_normalize("domain", "www.example.com") == []
    assert suricata_normalize("domain", "example.com.") == []


def test_non_noise_domain_is_still_normalized_issue_799():
    assert yara_normalize("domain", "www.evil-host.net.") == ["evil-host.net"]
    assert suricata_normalize("domain", "www.evil-host.net.") == ["evil-host.net"]
