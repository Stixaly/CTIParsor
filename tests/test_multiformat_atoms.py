"""Tests for CTIParsor multi-format atom extraction (ADR-0015)."""
from __future__ import annotations

import pytest

from pipeline.detection.suricata_atoms import (
    BUFFER_CLASSES,
    LEGACY_MODIFIER_CLASSES,
    extract_atoms,
    parse_options,
    rule_header,
    technique_ids,
)
from pipeline.detection.tlds import looks_like_domain
from pipeline.detection.yara_atoms import extract_atoms as yara_extract_atoms
from pipeline.detection.yara_atoms import (
    rule_hashes,
    rule_platform,
    split_rules,
)


def _sur(body: str) -> str:
    return f"alert tcp any any -> any any (msg:\"x\"; {body} sid:1;)"


def _yara(strings: list[str], meta: dict[str, str] | None = None) -> str:
    lines = ["rule R {"]
    if meta:
        lines.append("    meta:")
        for k, v in meta.items():
            lines.append(f'        {k} = "{v}"')
    if strings:
        lines.append("    strings:")
        for s in strings:
            lines.append(f"        {s}")
    lines.append("    condition:")
    lines.append("        true")
    lines.append("}")
    return "\n".join(lines)


class TestSuricataOptions:
    def test_split_ignores_semicolon_inside_quotes(self):
        """Semicolon inside quoted value must not split options."""
        result = parse_options('msg:"a;b"; sid:1;')
        assert result == [("msg", '"a;b"'), ("sid", "1")]

    def test_naked_option_yields_empty_value(self):
        """Naked option like nocase yields empty string value."""
        result = parse_options("nocase;")
        assert result == [("nocase", "")]

    def test_value_split_on_first_colon_only(self):
        """Value is split on first colon only, preserving subsequent colons."""
        result = parse_options("reference:url,http://x/y")
        assert result == [("reference", "url,http://x/y")]


class TestSuricataAtoms:
    def test_sticky_buffer_classifies_following_content(self):
        """Sticky buffer before content reclassifies it as domain."""
        rule = 'alert dns any any -> any any (msg:"x"; dns.query; content:"evil-c2.example.org"; sid:1;)'
        atoms = extract_atoms(rule)
        assert ("domain", "evil-c2.example.org") in atoms

    def test_legacy_modifier_reclassifies_preceding_content(self):
        """Legacy modifier after content reclassifies it as url."""
        rule = 'alert http any any -> any any (msg:"x"; content:"/gate.php"; nocase; http_uri; sid:1;)'
        atoms = extract_atoms(rule)
        assert ("url", "/gate.php") in atoms

    def test_buffer_and_legacy_tables_are_disjoint(self):
        """Buffer and legacy modifier keyword tables must be disjoint."""
        assert set(BUFFER_CLASSES) & set(LEGACY_MODIFIER_CLASSES) == set()

    def test_negated_content_is_never_indexed(self):
        """Negated content (content:!) must never appear in atoms."""
        rule = 'alert http any any -> any any (msg:"x"; http.host; content:!"101.ru"; sid:1;)'
        atoms = extract_atoms(rule)
        assert all("101.ru" not in v for _, v in atoms)

    def test_negated_content_in_strlit_buffer_is_never_indexed(self):
        """The negation skip must hold for `strlit` too — the path that actually broke.

        The `domain`-buffer case above passes even with the skip removed, because
        `!"101.ru"` fails the domain shape anyway.  A negated literal in a plain
        buffer has no such second line of defence: without the skip it is indexed
        verbatim, brace and all, which is where ET Open's 1,992 `!" referer "`
        atoms came from.
        """
        rule = ('alert http any any -> any any '
                '(msg:"x"; content:!"unique-negated-marker"; sid:1;)')
        atoms = extract_atoms(rule)
        assert atoms == [], f"negated content leaked into atoms: {atoms}"

    def test_hex_segments_are_stripped_from_content(self):
        """Hex segments in content must be stripped from atom value."""
        rule = _sur('content:"Sta|2a 28|tus"')
        atoms = extract_atoms(rule)
        for _, v in atoms:
            assert "|" not in v
            assert "2a" not in v

    def test_sql_keyword_in_uri_buffer_is_dropped(self):
        """SQL keyword without slash in uri buffer is not a URL and is dropped."""
        rule = 'alert http any any -> any any (msg:"x"; http.uri; content:"select"; sid:1;)'
        atoms = extract_atoms(rule)
        assert atoms == []

    def test_activex_progid_is_not_a_domain(self):
        """ActiveX ProgID like aventail.epinstaller is not a domain."""
        rule = 'alert tcp any any -> any any (msg:"x"; content:"aventail.epinstaller"; sid:1;)'
        atoms = extract_atoms(rule)
        assert all(c != "domain" for c, _ in atoms)

    def test_max_atoms_stops_early(self):
        """max_atoms parameter limits the number of returned atoms."""
        contents = "; ".join(f'content:"value{i:04d}";' for i in range(30))
        rule = _sur(contents)
        atoms = extract_atoms(rule, max_atoms=5)
        assert len(atoms) == 5

    def test_malformed_rule_returns_empty_not_raises(self):
        """Malformed inputs return empty list without raising."""
        for bad in ["", "alert tcp", "(", 123, None]:
            assert extract_atoms(bad) == []


class TestSuricataHeaderAndMeta:
    def test_rule_header_seven_fields(self):
        """Rule header parses proto, dst_port, and direction correctly."""
        rule = "alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:\"x\"; sid:1;)"
        header = rule_header(rule)
        assert header["proto"] == "tcp"
        assert header["dst_port"] == "443"
        assert header["direction"] == "->"

    def test_rule_header_too_short_returns_empty(self):
        """Rule header with too few fields returns empty dict."""
        rule = "alert tcp (msg:\"x\";)"
        assert rule_header(rule) == {}

    def test_technique_ids_from_metadata(self):
        """MITRE technique IDs are extracted from metadata."""
        rule = (
            'alert tcp any any -> any any (msg:"x"; '
            "metadata:created_at 2020_01_01, mitre_technique_id T1071, "
            "signature_severity Major; sid:1;)"
        )
        assert technique_ids(rule) == ["T1071"]

    def test_technique_ids_absent_returns_empty(self):
        """Missing metadata returns empty list of technique IDs."""
        rule = 'alert tcp any any -> any any (msg:"x"; sid:1;)'
        assert technique_ids(rule) == []


class TestYaraSplit:
    def test_split_two_rules(self):
        """Two rules in text are split into two YaraRule objects."""
        text = "rule A { condition: true }\nrule B { condition: true }"
        rules = split_rules(text)
        assert len(rules) == 2
        assert [r.name for r in rules] == ["A", "B"]

    def test_nested_braces_in_condition(self):
        """Nested braces in condition do not break rule splitting."""
        text = "rule N { condition: { 4D 5A } }"
        rules = split_rules(text)
        assert len(rules) == 1
        assert rules[0].body.endswith("}")

    def test_block_comment_does_not_shift_body(self):
        """Block comment removal preserves offsets so body starts correctly."""
        text = "/* licence header */\nrule Foo { condition: true }"
        rules = split_rules(text)
        assert len(rules) == 1
        assert rules[0].body.startswith("rule Foo")

    def test_private_rule_flagged(self):
        """Private rule is flagged with is_private True."""
        text = "private rule P { condition: true }"
        rules = split_rules(text)
        assert len(rules) == 1
        assert rules[0].is_private is True

    def test_tags_parsed(self):
        """Rule tags are parsed into the tags list."""
        text = "rule R : alpha beta { condition: true }"
        rules = split_rules(text)
        assert len(rules) == 1
        assert rules[0].tags == ["alpha", "beta"]

    def test_non_string_input_returns_empty(self):
        """Non-string input to split_rules returns empty list."""
        assert split_rules(None) == []


class TestYaraStrings:
    def test_modifiers_are_stripped_from_text_string(self):
        """String modifiers like ascii wide are stripped from atom value."""
        text = _yara(['$s = "AssemblyTitle" ascii wide'])
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        values = [v.lower() for _, v in atoms]
        assert "assemblytitle" in values
        for _, v in atoms:
            assert "ascii" not in v.lower()
            assert '"' not in v

    def test_escaped_backslash_decoded_once(self):
        """Double backslash in YARA source decodes to single backslash then slash."""
        text = _yara([r'$r = "Software\\Microsoft\\Windows"'])
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert ("registry", "software/microsoft/windows") in atoms

    def test_hex_and_regex_strings_are_not_indexed(self):
        """Hex and regex strings produce no atoms."""
        text = _yara(["$h = { 4D 5A 90 00 }", r"$re = /https?:\/\/evil/"])
        rules = split_rules(text)
        assert yara_extract_atoms(rules[0]) == []

    def test_anonymous_string_identifier(self):
        """Anonymous string identifier $ is parsed and produces an atom."""
        text = _yara(['$ = "anonymousvalue"'])
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert len(atoms) >= 1


class TestYaraAtoms:
    def test_meta_hashes_extracted_first(self):
        """Metadata hashes are extracted as the first atom."""
        sha = "a" * 64
        text = _yara(['$s = "one"', '$s2 = "two"', '$s3 = "three"'], {"hash1": sha})
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert atoms[0][0] == "hash"

    def test_invalid_hash_in_meta_ignored(self):
        """Invalid hash in metadata is ignored, no hash atom produced."""
        text = _yara(['$s = "one"'], {"hash1": "not-a-hash"})
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert all(c != "hash" for c, _ in atoms)

    def test_dll_is_file_not_domain(self):
        """DLL filename is classified as file, not domain."""
        text = _yara(['$s = "kernel32.dll"'])
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert all(c != "domain" for c, _ in atoms)

    def test_windows_path_classified_as_file_with_basename(self):
        """Windows path is classified as file with basename preserved."""
        text = _yara([r'$s = "C:\\Windows\\Temp\\dropper.exe"'])
        rules = split_rules(text)
        atoms = yara_extract_atoms(rules[0])
        assert any(c == "file" and v.endswith("dropper.exe") for c, v in atoms)

    def test_platform_from_os_meta(self):
        """Platform is derived from os metadata field."""
        text = _yara(['$s = "x"'], {"os": "linux"})
        rules = split_rules(text)
        assert rule_platform(rules[0]) == "linux"

    def test_platform_from_file_level_import(self):
        """File-level import pe maps to windows platform."""
        text = 'import "pe"\nrule R { condition: true }'
        rules = split_rules(text)
        assert rule_platform(rules[0]) == "windows"

    def test_platform_unknown_is_empty_string(self):
        """Unknown platform returns empty string."""
        text = _yara(['$s = "x"'])
        rules = split_rules(text)
        assert rule_platform(rules[0]) == ""

    def test_rule_hashes_deduplicated_lowercase(self):
        """Duplicate hashes in different cases are deduplicated to lowercase."""
        sha = "a" * 64
        text = _yara(['$s = "x"'], {"hash1": sha, "hash2": sha.upper()})
        rules = split_rules(text)
        hashes = rule_hashes(rules[0])
        assert len(hashes) == 1
        assert hashes[0] == sha.lower()


class TestLooksLikeDomain:
    @pytest.mark.parametrize(
        "domain",
        ["evil-c2.example.org", "barjuok.ryongnamsan.edu.kp", "101.ru", "a.co"],
    )
    def test_accepts_real_domains(self, domain: str):
        """Valid domains are accepted by looks_like_domain."""
        assert looks_like_domain(domain) is True

    @pytest.mark.parametrize(
        "lookalike",
        [
            "aventail.epinstaller",
            "keyhelp.keyscript",
            "kernel32.dll",
            "qexplain2.explainplandisplayx",
            "notadomain",
            "",
            "1.2.3.4",
        ],
    )
    def test_rejects_lookalikes(self, lookalike: str):
        """Domain lookalikes are rejected by looks_like_domain."""
        assert looks_like_domain(lookalike) is False

    def test_non_string_returns_false(self):
        """Non-string input returns False from looks_like_domain."""
        assert looks_like_domain(None) is False
