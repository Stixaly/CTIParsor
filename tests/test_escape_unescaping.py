"""
Regression tests for the escape-decoding order in the YARA and Suricata parsers.
"""
from pipeline.detection.suricata_atoms import _unescape_content
from pipeline.detection.yara_atoms import _unescape_literal, split_rules


def test_yara_doubled_backslash_before_n_is_not_a_newline():
    # taken from corpora/elastic-artifacts/yara/rules/Windows_Hacktool_NetFilter.yar
    assert _unescape_literal(r"\\netfilterdrv.pdb") == "\\netfilterdrv.pdb"
    assert "\n" not in _unescape_literal(r"\\netfilterdrv.pdb")

def test_yara_doubled_backslash_before_t_is_not_a_tab():
    # taken from corpora/elastic-artifacts/yara/rules/Windows_Exploit_Generic.yar
    assert _unescape_literal(r"X:\\tools\\0day\\") == "X:\\tools\\0day\\"
    assert "\t" not in _unescape_literal(r"X:\\tools\\0day\\")

def test_yara_windows_path_survives():
    assert _unescape_literal(r"C:\\Windows\\notepad.exe") == "C:\\Windows\\notepad.exe"
    assert _unescape_literal(r"M:\\sc\\p\\testbuild.pdb") == "M:\\sc\\p\\testbuild.pdb"

def test_yara_registry_path_survives():
    assert (_unescape_literal(r"SYSTEM\\CurrentControlSet\\Services\\Tcpip")
            == "SYSTEM\\CurrentControlSet\\Services\\Tcpip")

def test_yara_single_escapes_still_decode():
    # a SINGLE backslash-n is a real newline in YARA and must stay one.
    assert _unescape_literal(r"Selected IP: %s\n") == "Selected IP: %s\n"
    assert _unescape_literal(r"a\tb") == "a\tb"
    assert _unescape_literal(r"a\rb") == "a\rb"
    assert _unescape_literal(r"say \"hi\"") == 'say "hi"'

def test_yara_undefined_escape_is_preserved():
    assert _unescape_literal(r"\x41") == r"\x41"
    assert _unescape_literal(r"a\qb") == r"a\qb"

def test_yara_trailing_lone_backslash_is_kept():
    assert _unescape_literal("abc\\") == "abc\\"

def test_yara_non_string_and_empty_are_safe():
    assert _unescape_literal("") == ""
    assert _unescape_literal(None) == ""
    assert _unescape_literal(123) == ""

def test_yara_parser_end_to_end_keeps_the_file_path():
    # this is the test that fails if the replace-chain is reintroduced.
    src = r'''
rule probe {
    strings:
        $s1 = "C:\\Windows\\notepad.exe"
        $s2 = "\\netfilterdrv.pdb"
    condition:
        any of them
}
'''
    rules = split_rules(src)
    assert len(rules) == 1
    values = {ident: value for ident, kind, value in rules[0].strings if kind == "text"}
    assert values["$s1"] == "C:\\Windows\\notepad.exe"
    assert values["$s2"] == "\\netfilterdrv.pdb"

def test_suricata_doubled_backslash_before_colon_stays_escaped():
    assert _unescape_content(r"a\\:b") == "a\\:b"
    assert _unescape_content(r"a\\;b") == "a\\;b"

def test_suricata_single_escapes_still_decode():
    assert _unescape_content(r"a\;b") == "a;b"
    assert _unescape_content(r"a\:b") == "a:b"
    assert _unescape_content(r"a\\b") == "a\\b"
    assert _unescape_content(r'say \"hi\"') == 'say "hi"'

def test_suricata_undefined_escape_and_edges():
    assert _unescape_content(r"a\qb") == r"a\qb"
    assert _unescape_content("abc\\") == "abc\\"
    assert _unescape_content("") == ""
    assert _unescape_content(None) == ""
