"""Issues #478 and #479: the YARA body an export writes must compile on its own.

The export writes `DetectionRule.raw` as one file per rule. That body used to
lose the file's `import` lines and the `private` rules it references (#478),
and the `global` modifier (#479). Each test compiles the exported text with
yara-python, as an analyst would.
"""
import hashlib

import pytest

yara = pytest.importorskip(
    "yara", reason="yara-python is not installed: the compile check of an exported YARA body cannot run"
)

from pipeline.detection.yara import YaraAdapter  # noqa: E402
from pipeline.detection.yara_atoms import split_rules  # noqa: E402


def _export(tmp_path, text):
    (tmp_path / "rules.yar").write_text(text, encoding="utf-8")
    return list(YaraAdapter().parse(tmp_path, corpus="c"))


def test_the_import_a_rule_uses_is_kept_issue_478(tmp_path):
    [rule] = _export(tmp_path, 'import "pe"\nrule Detect { condition: pe.is_pe }\n')
    yara.compile(source=rule.raw)


def test_an_import_the_rule_does_not_use_is_left_out_issue_478(tmp_path):
    [rule] = _export(tmp_path, 'import "pe"\nrule Plain { condition: true }\n')
    assert rule.raw == "rule Plain { condition: true }"


def test_the_private_rule_a_rule_uses_is_kept_issue_478(tmp_path):
    [rule] = _export(tmp_path, "private rule Helper { condition: true }\nrule Detect { condition: Helper }\n")
    yara.compile(source=rule.raw)


def test_a_private_rule_used_through_another_private_rule_is_kept_issue_478(tmp_path):
    source = (
        "private rule A { condition: true }\n"
        "private rule B { condition: A }\n"
        "rule Detect { condition: B }\n"
    )
    [rule] = _export(tmp_path, source)
    yara.compile(source=rule.raw)


def test_a_private_rule_nobody_uses_is_left_out_issue_478(tmp_path):
    [rule] = _export(tmp_path, "private rule Unused { condition: true }\nrule Detect { condition: true }\n")
    assert "Unused" not in rule.raw


def test_the_global_modifier_is_kept_issue_479(tmp_path):
    source = (
        "global rule Gate { condition: false }\n"
        "rule Detect {\n"
        "  strings: $a = \"malicious_marker\"\n"
        "  condition: $a\n"
        "}\n"
    )
    gate, detect = _export(tmp_path, source)
    assert gate.raw.startswith("global rule Gate")
    assert detect.raw.startswith("rule Detect")


def test_the_exported_bodies_match_the_original_source_issue_479(tmp_path):
    """Compiled together, the exported bodies detect what the source detects."""
    source = (
        "global rule Gate { condition: false }\n"
        "rule Detect {\n"
        "  strings: $a = \"malicious_marker\"\n"
        "  condition: $a\n"
        "}\n"
    )
    data = b"malicious_marker"
    original = yara.compile(source=source)
    exported = yara.compile(source="\n".join(r.raw for r in _export(tmp_path, source)))
    assert [m.rule for m in exported.match(data=data)] == [m.rule for m in original.match(data=data)]
    assert original.match(data=data) == []      # the global gate is closed: no detection


def test_the_id_of_an_exported_rule_is_unchanged_issue_478_479(tmp_path):
    """The export text changes, the native key does not: stored ids and the
    analyst's promotions keep resolving."""
    source = 'import "pe"\nprivate rule H { condition: true }\nglobal rule G { condition: H and pe.is_pe }\n'
    (tmp_path / "rules.yar").write_text(source, encoding="utf-8")
    [rule] = list(YaraAdapter().parse(tmp_path, corpus="c"))
    [body] = [r.body for r in split_rules(source) if r.name == "G"]
    assert rule.id == f"c:{hashlib.sha256(body.encode()).hexdigest()[:16]}"
