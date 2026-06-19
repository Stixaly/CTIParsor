"""Tests for the Sigma corpus adapter (ADR-0006)."""
from models.detection import Severity
from pipeline.detection.registry import iter_rules, load_corpora
from pipeline.detection.sigma import SigmaAdapter

_SAMPLE = """\
title: Suspicious PowerShell Encoded Command
id: 11111111-2222-3333-4444-555555555555
status: experimental
description: Detects powershell -EncodedCommand usage.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1027
  - attack.g0016
"""


def test_sigma_adapter_parses_rule(tmp_path):
    (tmp_path / "rule.yml").write_text(_SAMPLE, encoding="utf-8")
    rules = list(SigmaAdapter().parse(tmp_path, corpus="test-corpus", license="proprietary"))
    assert len(rules) == 1
    r = rules[0]
    assert r.id == "test-corpus:11111111-2222-3333-4444-555555555555"
    assert r.corpus == "test-corpus"
    assert r.format == "sigma"
    assert set(r.technique_ids) == {"T1059.001", "T1027"}
    assert "execution" in r.tactic_shortnames
    # attack.g0016 (group) must NOT be treated as a tactic
    assert all(not t.startswith("g") or t == "execution" for t in r.tactic_shortnames)
    assert "g0016" not in r.tactic_shortnames
    assert r.severity == Severity.HIGH
    assert "process_creation" in r.data_sources
    assert r.license == "proprietary"
    assert r.content_hash and r.raw.startswith("title:")


def test_sigma_adapter_ignores_non_rule_yaml(tmp_path):
    (tmp_path / "notarule.yml").write_text("foo: bar\nbaz: 1\n", encoding="utf-8")
    assert list(SigmaAdapter().parse(tmp_path, corpus="c")) == []


def test_sigma_adapter_dedup_key_falls_back_to_hash(tmp_path):
    no_id = _SAMPLE.replace("id: 11111111-2222-3333-4444-555555555555\n", "")
    (tmp_path / "noid.yml").write_text(no_id, encoding="utf-8")
    rules = list(SigmaAdapter().parse(tmp_path, corpus="c"))
    assert len(rules) == 1
    assert rules[0].id.startswith("c:")  # hash-based key, no UUID present


def test_sigma_adapter_skips_malformed_yaml(tmp_path):
    (tmp_path / "bad.yml").write_text("title: x\n  : : bad\n", encoding="utf-8")
    # must not raise — malformed files are skipped
    assert list(SigmaAdapter().parse(tmp_path, corpus="c")) == []


def test_registry_loads_enabled_corpora_and_parses(tmp_path):
    # a corpus clone with one rule
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / "r.yml").write_text(_SAMPLE, encoding="utf-8")
    # a disabled corpus must be ignored
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(
        "corpora:\n"
        "  - name: live\n"
        "    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n"
        "    license: proprietary\n"
        "    enabled: true\n"
        "  - name: off\n"
        "    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    assert [c["name"] for c in load_corpora(cfg)] == ["live"]
    rules = list(iter_rules(cfg))
    assert len(rules) == 1 and rules[0].corpus == "live"


def test_registry_local_overlay_appends(tmp_path):
    (tmp_path / "detection_corpora.yaml").write_text(
        "corpora:\n  - name: sigmahq\n    adapter: sigma\n    path: ./x\n    enabled: true\n",
        encoding="utf-8",
    )
    (tmp_path / "detection_corpora.local.yaml").write_text(
        "corpora:\n  - name: priv\n    adapter: sigma\n    path: ./y\n    private: true\n    enabled: true\n",
        encoding="utf-8",
    )
    names = [c["name"] for c in load_corpora(tmp_path / "detection_corpora.yaml")]
    assert names == ["sigmahq", "priv"]   # committed first, overlay appended


def test_registry_local_overlay_overrides_by_name(tmp_path):
    (tmp_path / "detection_corpora.yaml").write_text(
        "corpora:\n  - name: sigmahq\n    adapter: sigma\n    path: ./x\n    license: DRL-1.1\n    enabled: true\n",
        encoding="utf-8",
    )
    # overlay disables the public corpus and adds a private one
    (tmp_path / "detection_corpora.local.yaml").write_text(
        "corpora:\n"
        "  - name: sigmahq\n    enabled: false\n"
        "  - name: priv\n    adapter: sigma\n    path: ./y\n    enabled: true\n",
        encoding="utf-8",
    )
    corpora = load_corpora(tmp_path / "detection_corpora.yaml")
    assert [c["name"] for c in corpora] == ["priv"]   # sigmahq disabled via overlay
