"""Tests for the Suricata and YARA corpus adapters (ADR-0015 §1).

The atom extractors behind them are covered by test_multiformat_atoms.py; these
tests drive the adapters end to end over a corpus directory, the way
scripts/build_detection_index.py does.
"""
from __future__ import annotations

from models.detection import Severity
from pipeline.detection.suricata import SuricataAdapter
from pipeline.detection.yara import YaraAdapter
from pipeline.detection.yara_atoms import YaraRule

# ── Suricata ─────────────────────────────────────────────────────────────────

_TOR_RULE = (
    'alert tcp [185.220.101.45,10.0.0.1/8,$HOME_NET,999.1.1.1] any -> $HOME_NET [443,8443,0] '
    '(msg:"ET TOR Known Tor Exit Node Traffic group 1"; content:"evil-c2.example.com"; '
    "metadata:signature_severity Major, mitre_technique_id T1090; "
    "classtype:misc-attack; sid:2520000; rev:4;)"
)


def _suricata(tmp_path, *lines: str) -> list:
    (tmp_path / "sub").mkdir(exist_ok=True)
    (tmp_path / "sub" / "emerging.rules").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return list(SuricataAdapter().parse(tmp_path, corpus="et-open", license="MIT"))


def test_suricata_rule_is_parsed_into_a_detection_rule(tmp_path):
    (rule,) = _suricata(tmp_path, _TOR_RULE)

    assert rule.id == "et-open:2520000"
    assert rule.format == "suricata" and rule.corpus == "et-open" and rule.license == "MIT"
    assert rule.title == "ET TOR Known Tor Exit Node Traffic group 1"
    assert rule.technique_ids == ["T1090"]
    assert rule.severity == Severity.HIGH                 # signature_severity Major
    assert rule.data_sources == ["tcp"]
    assert rule.source_ref.endswith("emerging.rules:1")
    assert rule.raw == _TOR_RULE and len(rule.content_hash) == 64
    assert "signature_severity Major" in rule.description


def test_suricata_bracketed_header_lists_become_atoms(tmp_path):
    """Bracketed address lists are literals: unpacked, minus CIDRs, variables
    and out-of-range values."""
    (rule,) = _suricata(tmp_path, _TOR_RULE)

    assert ("ip", "185.220.101.45") in rule.atoms
    assert ("ip", "999.1.1.1") not in rule.atoms and ("ip", "10.0.0.1/8") not in rule.atoms
    assert ("port", "443") in rule.atoms and ("port", "8443") in rule.atoms
    assert ("port", "0") not in rule.atoms
    assert len(rule.atoms) == len(set(rule.atoms))       # header atoms are not repeated


def test_suricata_header_atoms_are_capped_per_field():
    ips = ",".join(f"10.0.{i // 256}.{i % 256}" for i in range(100))
    atoms = SuricataAdapter()._header_atoms({"src_ip": f"[{ips}]", "dst_ip": "any",
                                             "dst_port": "!80"}, max_ips=5)
    assert atoms == [("ip", f"10.0.0.{i}") for i in range(5)]


def test_suricata_skips_comments_blanks_and_non_rules(tmp_path):
    rules = _suricata(
        tmp_path,
        "",
        "# " + _TOR_RULE,                                  # disabled rule
        "var HOME_NET any",                                # not an action
        "alert tcp (msg:\"too short\"; sid:9;)",           # header too short
        "alert tcp any any -> any any no body here",       # no option body
        _TOR_RULE,
    )
    assert [r.id for r in rules] == ["et-open:2520000"]


def test_suricata_rule_without_sid_or_msg_falls_back_to_hash_and_line(tmp_path):
    line = 'drop udp any any -> 8.8.8.8 53 (content:"x"; metadata:signature_severity Critical;)'
    (rule,) = _suricata(tmp_path, "", line)

    assert rule.id == f"et-open:{rule.content_hash[:16]}"
    assert rule.title == "suricata rule 2"
    assert rule.severity == Severity.CRITICAL
    assert ("ip", "8.8.8.8") in rule.atoms and ("port", "53") in rule.atoms


def test_suricata_title_uses_the_sid_when_msg_is_missing(tmp_path):
    (rule,) = _suricata(tmp_path, 'alert http any any -> any any (content:"x"; sid:77;)')
    assert rule.title == "suricata sid 77" and rule.severity == Severity.UNKNOWN


def test_suricata_dedup_key_ignores_volatile_options_but_not_the_header():
    adapter = SuricataAdapter()
    header = {"proto": "tcp", "src_ip": "any", "src_port": "any", "direction": "->",
              "dst_ip": "1.2.3.4", "dst_port": "80"}
    a = adapter._dedup_key('msg:"a"; content:"x"; sid:1; rev:1;', header)
    b = adapter._dedup_key('msg:"b"; content:"x"; sid:2; rev:7; classtype:foo;', header)
    c = adapter._dedup_key('msg:"a"; content:"x"; sid:1;', {**header, "dst_ip": "5.6.7.8"})

    assert a == b                                           # only documentation changed
    assert a != c                                           # the header is detection logic
    assert adapter._dedup_key('msg:"only docs"; sid:1;', header) == ""


def test_suricata_rules_sharing_a_body_keep_distinct_dedup_keys(tmp_path):
    """ET's blocklists share one option body across rules that differ only in
    their header: they must not collapse into one dedup cluster."""
    body = '(msg:"ET TOR"; content:"x"; sid:{sid};)'
    rules = _suricata(
        tmp_path,
        "alert tcp 1.1.1.1 any -> any any " + body.format(sid=1),
        "alert tcp 2.2.2.2 any -> any any " + body.format(sid=2),
    )
    assert len({r.dedup_key for r in rules}) == 2


def test_suricata_unreadable_file_is_skipped(tmp_path, monkeypatch):
    from pathlib import Path

    (tmp_path / "a.rules").write_text(_TOR_RULE, encoding="utf-8")

    def boom(self, *a, **kw):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", boom)
    assert list(SuricataAdapter().parse(tmp_path, corpus="c")) == []


# ── YARA ─────────────────────────────────────────────────────────────────────

_YARA = """\
/* signature-base style header */
private rule IsPE { condition: uint16(0) == 0x5A4D }

rule APT_Sample_1 : apt windows
{
    meta:
        description = "Detects APT sample loader"
        mitre_attack = "T1055.001, t1027 and T1055.001 again"
        author = "someone"
        id = "shared-family-id"
    strings:
        $s1 = "evil-c2.example.com"
        $s2 = "LoaderMutex_42"
    condition:
        IsPE and all of them
}

rule APT_Sample_2
{
    meta:
        description = "Same strings, different order"
        id = "shared-family-id"
    strings:
        $b = "LoaderMutex_42"
        $a = "evil-c2.example.com"
    condition:
        any of them
}
"""


def _yara(tmp_path, text: str = _YARA, name: str = "apt.yar") -> list:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return list(YaraAdapter().parse(tmp_path, corpus="sigbase", license="DRL-1.1"))


def test_yara_rules_are_parsed_and_private_rules_skipped(tmp_path):
    rules = _yara(tmp_path)

    assert [r.title for r in rules] == ["APT_Sample_1", "APT_Sample_2"]
    first = rules[0]
    assert first.format == "yara" and first.corpus == "sigbase" and first.license == "DRL-1.1"
    assert first.description == "Detects APT sample loader"
    assert first.technique_ids == ["T1055.001", "T1027"]   # upper-cased, de-duplicated
    assert first.data_sources == ["file"] and first.severity == Severity.UNKNOWN
    assert first.source_ref.endswith("apt.yar")
    assert first.raw.startswith("rule APT_Sample_1")


def test_yara_rule_ids_come_from_the_body_not_meta_id(tmp_path):
    """Two rules sharing `meta.id` must not collide on detection_rules.id."""
    rules = _yara(tmp_path)
    assert len({r.id for r in rules}) == 2
    assert all(r.id == f"sigbase:{r.content_hash[:16]}" for r in rules)


def test_yara_dedup_key_is_order_independent_over_strings(tmp_path):
    first, second = _yara(tmp_path)
    assert first.dedup_key == second.dedup_key
    assert first.content_hash != second.content_hash


def test_yara_rule_without_strings_dedups_on_its_content_hash(tmp_path):
    (rule,) = _yara(tmp_path, "rule OnlyCondition { condition: filesize < 10 }", name="x.yara")
    assert rule.dedup_key == rule.content_hash


def _yara_rule(**kw) -> YaraRule:
    fields = {"name": "R", "tags": [], "meta": {}, "strings": [],
              "body": "rule R { condition: true }", "is_private": False}
    return YaraRule(**{**fields, **kw})


def test_yara_non_string_meta_and_unrelated_keys_carry_no_technique():
    rule = _yara_rule(meta={"technique": 5, "reference": "T1059", "ATTACK": "T1566"})
    assert YaraAdapter()._techniques(rule) == ["T1566"]


def test_yara_every_supported_extension_is_read(tmp_path):
    for i, ext in enumerate(("yar", "yara", "rule")):
        (tmp_path / f"r{i}.{ext}").write_text(f"rule R{i} {{ condition: true }}", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("rule Nope { condition: true }", encoding="utf-8")

    titles = sorted(r.title for r in YaraAdapter().parse(tmp_path, corpus="c"))
    assert titles == ["R0", "R1", "R2"]


def test_yara_unnamed_rule_is_dropped(tmp_path):
    assert YaraAdapter()._to_rule(_yara_rule(name=""), tmp_path, "c", "l") is None


def test_yara_unreadable_file_is_skipped(tmp_path, monkeypatch):
    from pathlib import Path

    (tmp_path / "a.yar").write_text("rule A { condition: true }", encoding="utf-8")

    def boom(self, *a, **kw):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", boom)
    assert list(YaraAdapter().parse(tmp_path, corpus="c")) == []
