from __future__ import annotations

"""Tests for pipeline.detection.synth_sigma (ADR-0016)."""

import uuid

import pytest
import yaml

from pipeline.detection.observables import Observable
from pipeline.detection.synth_sigma import KIND_SPECS, synthesize_sigma


def _obs(cls: str, value: str, display: str | None = None) -> Observable:
    return Observable(cls, value, "test", display or value)


class TestGates:
    def test_domain_lookalike_filenames_rejected(self) -> None:
        """Reject domain observables that are actually filenames."""
        obs = [
            _obs("domain", "agent.ashx"),
            _obs("domain", "exfil.tar.zst"),
            _obs("domain", "psemhub.war"),
        ]
        assert synthesize_sigma(obs, job_id="j") == []

    def test_real_domain_accepted(self) -> None:
        """Accept a valid domain and produce a dns_query rule."""
        obs = [_obs("domain", "azurenetfiles.net")]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert rules[0].kind == "dns_query"

    def test_excluded_value_produces_no_rule(self) -> None:
        """Exclude values already covered by existing rules."""
        obs = [_obs("domain", "azurenetfiles.net")]
        assert synthesize_sigma(obs, job_id="j", exclude_values={"azurenetfiles.net"}) == []

    @pytest.mark.parametrize("cls", ["name", "user", "port", "cve"])
    def test_unsynthesizable_classes_ignored(self, cls: str) -> None:
        """Ignore observables of classes that cannot be synthesized."""
        obs = [_obs(cls, "something")]
        assert synthesize_sigma(obs, job_id="j") == []

    def test_executable_not_duplicated_as_file_event(self) -> None:
        """Prevent duplication of executable files as both image and file events."""
        obs = [
            _obs("image", "meshagent64-v2.exe"),
            _obs("file", "meshagent64-v2.exe"),
        ]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert rules[0].kind == "process_image"
        assert all(r.kind != "file_event" for r in rules)

    def test_non_executable_file_makes_file_event(self) -> None:
        """Produce a file_event rule for non-executable files."""
        obs = [_obs("file", "/tmp/notes.txt")]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert rules[0].kind == "file_event"

    def test_invalid_hash_length_rejected(self) -> None:
        """Reject hashes with invalid lengths."""
        obs = [_obs("hash", "abc123")]
        assert synthesize_sigma(obs, job_id="j") == []

    def test_valid_sha256_accepted_with_prefix(self) -> None:
        """Accept valid SHA256 hashes with proper prefix."""
        sha256 = "a" * 64
        obs = [_obs("hash", sha256)]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert rules[0].kind == "process_hash"
        assert rules[0].values[0].startswith("SHA256=")

    def test_md5_and_sha1_prefixes(self) -> None:
        """Apply correct prefixes for MD5 and SHA1 hashes."""
        md5 = "b" * 32
        sha1 = "c" * 40
        obs = [_obs("hash", md5), _obs("hash", sha1)]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert rules[0].kind == "process_hash"
        assert any(v.startswith("MD5=") for v in rules[0].values)
        assert any(v.startswith("SHA1=") for v in rules[0].values)

    def test_ipv6_rejected(self) -> None:
        """Reject IPv6 addresses."""
        obs = [_obs("ip", "2001:db8::1")]
        assert synthesize_sigma(obs, job_id="j") == []

    def test_octet_over_255_rejected(self) -> None:
        """Reject IPv4 addresses with octets over 255."""
        obs = [_obs("ip", "999.1.1.1")]
        assert synthesize_sigma(obs, job_id="j") == []


class TestGrouping:
    def test_one_rule_per_kind_not_per_observable(self) -> None:
        """Group multiple observables of the same kind into one rule."""
        obs = [
            _obs("domain", "a-one.com"),
            _obs("domain", "b-two.net"),
            _obs("domain", "c-three.org"),
            _obs("domain", "d-four.io"),
        ]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert len(rules[0].values) == 4

    def test_duplicate_values_deduplicated(self) -> None:
        """Deduplicate identical observable values."""
        obs = [
            _obs("domain", "example.com"),
            _obs("domain", "example.com"),
            _obs("domain", "example.com"),
        ]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1
        assert len(rules[0].values) == 1

    def test_max_values_per_rule_truncates(self) -> None:
        """Truncate values to max_values_per_rule limit."""
        obs = [_obs("domain", f"domain{i}.com") for i in range(10)]
        rules = synthesize_sigma(obs, job_id="j", max_values_per_rule=3)
        assert len(rules) == 1
        assert len(rules[0].values) == 3

    def test_output_order_follows_kind_specs(self) -> None:
        """Order rules according to KIND_SPECS key order."""
        obs = [
            _obs("hash", "a" * 64),
            _obs("domain", "example.com"),
            _obs("ip", "1.2.3.4"),
        ]
        rules = synthesize_sigma(obs, job_id="j")
        expected_order = [k for k in KIND_SPECS.keys() if k in {r.kind for r in rules}]
        actual_order = [r.kind for r in rules]
        assert actual_order == expected_order

    def test_empty_input_returns_empty(self) -> None:
        """Return empty list for empty input."""
        assert synthesize_sigma([], job_id="j") == []

    def test_non_observable_items_ignored(self) -> None:
        """Ignore non-Observable items in input list."""
        obs = [None, "str", 42, _obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        assert len(rules) == 1


class TestYamlOutput:
    def test_yaml_parses_and_has_required_keys(self) -> None:
        """Verify YAML output contains all required keys."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        doc = yaml.safe_load(rules[0].yaml_text)
        for key in ["title", "id", "status", "logsource", "detection", "level", "falsepositives"]:
            assert key in doc

    def test_status_is_experimental(self) -> None:
        """Verify status is set to experimental."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        doc = yaml.safe_load(rules[0].yaml_text)
        assert doc["status"] == "experimental"

    def test_condition_present_in_detection(self) -> None:
        """Verify detection condition is set to selection."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        doc = yaml.safe_load(rules[0].yaml_text)
        assert doc["detection"]["condition"] == "selection"

    def test_field_name_matches_kind_spec(self) -> None:
        """Verify field name matches KIND_SPECS definition."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        doc = yaml.safe_load(rules[0].yaml_text)
        expected_field = KIND_SPECS["dns_query"]["field"]
        assert expected_field in doc["detection"]["selection"]

    def test_values_always_a_list_even_when_single(self) -> None:
        """Ensure values are always a list, even for single value."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j")
        doc = yaml.safe_load(rules[0].yaml_text)
        field = KIND_SPECS["dns_query"]["field"]
        assert isinstance(doc["detection"]["selection"][field], list)
        assert len(doc["detection"]["selection"][field]) == 1

    def test_product_absent_when_platform_multi(self) -> None:
        """Omit product field when platform is multi."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j", platform="multi")
        doc = yaml.safe_load(rules[0].yaml_text)
        assert "product" not in doc["logsource"]

    def test_product_absent_when_platform_empty(self) -> None:
        """Omit product field when platform is empty."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j", platform="")
        doc = yaml.safe_load(rules[0].yaml_text)
        assert "product" not in doc["logsource"]

    def test_product_present_when_platform_windows(self) -> None:
        """Include product field when platform is windows."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j", platform="windows")
        doc = yaml.safe_load(rules[0].yaml_text)
        assert doc["logsource"]["product"] == "windows"

    def test_report_techniques_are_never_tagged(self) -> None:
        """The report's technique list must not be stamped onto a generated rule.

        Locks the ADR-0016 decision: an observable does not record which technique
        it served.  Tagging every rule with all of them produced, on a real report,
        a file_event rule carrying 34 techniques including an ICS one.
        """
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j", techniques=["T1059.001", "T1027"])
        doc = yaml.safe_load(rules[0].yaml_text)
        assert doc["tags"] == ["attack.command_and_control"]
        assert "attack.t1059.001" not in doc["tags"]
        # …but they are still recorded, on the object and in the description.
        assert rules[0].techniques == ("T1059.001", "T1027")
        assert "T1027" in doc["description"]

    def test_tactic_tag_present_even_without_techniques(self) -> None:
        """A kind with a well-founded tactic is tagged regardless of report TTPs."""
        obs = [_obs("domain", "example.com")]
        rules = synthesize_sigma(obs, job_id="j", techniques=())
        doc = yaml.safe_load(rules[0].yaml_text)
        assert doc["tags"] == ["attack.command_and_control"]

    def test_tags_omitted_where_tactic_not_determinable(self) -> None:
        """file_event/registry_set carry no tag rather than a guessed one."""
        obs = [_obs("registry", "software/microsoft/windows/currentversion/run")]
        rules = synthesize_sigma(obs, job_id="j", techniques=["T1547.001"])
        doc = yaml.safe_load(rules[0].yaml_text)
        assert "tags" not in doc

    def test_level_matches_kind(self) -> None:
        """Verify level matches kind specification."""
        obs_hash = [_obs("hash", "a" * 64)]
        rules_hash = synthesize_sigma(obs_hash, job_id="j")
        doc_hash = yaml.safe_load(rules_hash[0].yaml_text)
        assert doc_hash["level"] == "high"

        obs_file = [_obs("file", "/tmp/notes.txt")]
        rules_file = synthesize_sigma(obs_file, job_id="j")
        doc_file = yaml.safe_load(rules_file[0].yaml_text)
        assert doc_file["level"] == "low"


class TestEscapingAndPaths:
    def test_wildcards_escaped(self) -> None:
        """Escape wildcards in registry paths."""
        obs = [_obs("registry", r"software/test*key")]
        rules = synthesize_sigma(obs, job_id="j")
        assert r"\*" in rules[0].values[0]
        assert "*" not in rules[0].values[0].replace(r"\*", "")

    def test_backslash_escaped_before_wildcard(self) -> None:
        """Escape question marks in registry paths."""
        obs = [_obs("registry", r"software/a?b")]
        rules = synthesize_sigma(obs, job_id="j")
        assert r"\?" in rules[0].values[0]

    def test_registry_slashes_converted_to_backslashes(self) -> None:
        """Convert forward slashes to backslashes in registry paths."""
        obs = [_obs("registry", "software/microsoft/windows/currentversion/run")]
        rules = synthesize_sigma(obs, job_id="j")
        assert "\\" in rules[0].values[0]
        assert "/" not in rules[0].values[0]

    def test_image_basename_gets_leading_backslash(self) -> None:
        """Add leading backslash to image basenames for endswith matching."""
        obs = [_obs("image", "meshagent64-v2.exe")]
        rules = synthesize_sigma(obs, job_id="j")
        assert rules[0].values[0].startswith("\\")

    def test_image_full_path_converted(self) -> None:
        """Drive-letter paths become backslash paths, Sigma-escaped.

        Sigma encodes a literal backslash as `\\\\`, so the doubling in the stored
        value is correct and must survive: the rendered rule means
        `c:\\windows\\temp\\x.exe`.
        """
        obs = [_obs("image", "c:/windows/temp/x.exe")]
        rules = synthesize_sigma(obs, job_id="j")
        assert rules[0].values[0] == r"c:\\windows\\temp\\x.exe"
        assert "/" not in rules[0].values[0]

    @pytest.mark.parametrize("platform", ["", "multi", "windows", "linux"])
    def test_posix_path_keeps_forward_slashes(self, platform: str) -> None:
        """A POSIX path is never converted to Windows separators — on any platform.

        `platform="windows"` is the case that matters and the one a default-platform
        test cannot reach: a Windows-dominant report that also names a Linux path.
        Without the guard the value becomes `\\etc\\passwd`, which can never fire.
        """
        obs = [_obs("file", "/etc/passwd")]
        rules = synthesize_sigma(obs, job_id="j", platform=platform)
        assert rules[0].values[0] == "/etc/passwd"

    def test_path_env_fragment_rejected(self) -> None:
        """`/usr/bin:/bin` is a $PATH fragment, not a file — it makes no rule."""
        assert synthesize_sigma([_obs("file", "/usr/bin:/bin")], job_id="j") == []

    def test_generic_basename_rejected(self) -> None:
        """A bare extension-less basename like `hosts` is too generic to key on."""
        assert synthesize_sigma([_obs("file", "hosts")], job_id="j") == []


class TestDeterminism:
    def test_same_input_same_bytes(self) -> None:
        """Ensure identical inputs produce identical YAML output."""
        obs = [_obs("domain", "example.com")]
        rules1 = synthesize_sigma(obs, job_id="j")
        rules2 = synthesize_sigma(obs, job_id="j")
        assert rules1[0].yaml_text == rules2[0].yaml_text

    def test_rule_id_is_stable_uuid(self) -> None:
        """Ensure rule_id is a stable UUID across calls."""
        obs = [_obs("domain", "example.com")]
        rules1 = synthesize_sigma(obs, job_id="j")
        rules2 = synthesize_sigma(obs, job_id="j")
        assert rules1[0].rule_id == rules2[0].rule_id
        uuid.UUID(rules1[0].rule_id)

    def test_rule_id_differs_per_job(self) -> None:
        """Ensure rule_id differs for different job_ids."""
        obs = [_obs("domain", "example.com")]
        rules_a = synthesize_sigma(obs, job_id="a")
        rules_b = synthesize_sigma(obs, job_id="b")
        assert rules_a[0].rule_id != rules_b[0].rule_id

    def test_rule_id_differs_per_kind(self) -> None:
        """Ensure rule_id differs for different kinds."""
        obs = [_obs("domain", "example.com"), _obs("ip", "1.2.3.4")]
        rules = synthesize_sigma(obs, job_id="j")
        rule_ids = {r.rule_id for r in rules}
        assert len(rule_ids) == len(rules)
