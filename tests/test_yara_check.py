"""ADR-0067: a YARA rule quoted in a report ships only if it compiles."""
import sys

import pytest

from pipeline.detection import yara_check
from pipeline.detection.yara_check import (
    COMPILES,
    DOES_NOT_COMPILE,
    UNVERIFIED,
    prepare_embedded_rule,
    rejoin_wrapped_meta_strings,
    with_declared_imports,
)

# Verbatim from the report text of the Mandiant INDUSTROYER.V2 post printed to
# PDF (job 29fdabdd): the print layout wrapped the `description` line, and the
# text extraction put a blank line after every line.  OpenCTI refused it with
# "indicator of type yara is not correctly formatted".
WRAPPED_RULE = (
    'rule MTI_Hunting_INDUSTROYERv2_Bytes {\n\n'
    '    meta:\n\n'
    '        author = "Mandiant"\n\n'
    '        date = "04-09-2022"\n\n'
    '        description = "Searching for executables containing\n\n'
    'bytecode associated with the INDUSTROYER.V2 malware family."\n\n'
    '    strings:\n\n'
    '        $bytes = {8B [2] 89 [2] 8B 0D [4] 89 [2] 8B 15 [4] 89 [2]\n\n'
    'A1 [4] 89 [2] 8B 0D [4] 89 [2] 8A 15 [4] 88 [2] 8D [2] 5? 8B [2]\n\n'
    'E8}\n\n'
    '    condition:\n\n'
    '        filesize < 3MB and\n\n'
    '        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550\n\n'
    'and\n\n'
    '        $bytes\n\n'
    '}'
)

VALID_RULE = 'rule ok {\n  meta:\n    author = "x"\n  strings:\n    $s = "foo"\n  condition:\n    $s\n}'


def test_a_wrapped_meta_string_is_joined_back_with_one_space():
    body, joined = rejoin_wrapped_meta_strings(WRAPPED_RULE)
    assert joined == 1
    assert ('        description = "Searching for executables containing bytecode '
            'associated with the INDUSTROYER.V2 malware family."') in body.split("\n")
    # The hex string and the condition wrap are valid YARA: untouched.
    assert "89 [2]\n\nA1 [4]" in body
    assert "0x00004550\n\nand" in body


def test_a_rule_that_compiles_is_not_changed():
    assert rejoin_wrapped_meta_strings(VALID_RULE) == (VALID_RULE, 0)
    assert with_declared_imports(VALID_RULE, ["pe"]) == (VALID_RULE, ())


def test_an_escaped_quote_does_not_close_the_string():
    body = 'rule r {\n meta:\n  d = "say \\"hi\n there"\n condition:\n  true\n}'
    out, joined = rejoin_wrapped_meta_strings(body)
    assert joined == 1
    assert '  d = "say \\"hi there"' in out.split("\n")


def test_a_cut_text_string_under_strings_is_left_alone():
    # Space or nothing at the break changes what the rule matches.
    body = 'rule r {\n strings:\n  $a = "abc\ndef"\n condition:\n  $a\n}'
    assert rejoin_wrapped_meta_strings(body) == (body, 0)


def test_a_string_that_never_closes_does_not_swallow_the_next_section():
    body = 'rule r {\n meta:\n  d = "open\n  more\n strings:\n  $a = "x"\n condition:\n  $a\n}'
    assert rejoin_wrapped_meta_strings(body) == (body, 0)


def test_a_declared_import_is_added_when_the_rule_uses_it():
    body = 'rule r {\n condition:\n  pe.number_of_sections > 2\n}'
    out, added = with_declared_imports(body, ["pe", "math"])
    assert added == ("pe",)
    assert out.startswith('import "pe"\n')


def test_an_undeclared_module_is_never_imported():
    body = 'rule r {\n condition:\n  pe.number_of_sections > 2\n}'
    assert with_declared_imports(body, []) == (body, ())


def test_without_yara_python_the_rule_is_unverified_not_valid(monkeypatch):
    monkeypatch.setitem(sys.modules, "yara", None)   # import yara -> ImportError
    prepared = prepare_embedded_rule(WRAPPED_RULE)
    assert prepared.status == UNVERIFIED
    assert prepared.ledger_info() == {"rejoined_lines": 1, "pattern_check": UNVERIFIED}


def test_opencti_check_refuses_the_quoted_rule_and_accepts_the_repaired_one():
    yara = pytest.importorskip("yara")
    with pytest.raises(yara.SyntaxError):
        yara.compile(source=WRAPPED_RULE)
    prepared = prepare_embedded_rule(WRAPPED_RULE)
    assert prepared.status == COMPILES
    yara.compile(source=prepared.pattern)


def test_a_rule_the_repairs_cannot_fix_does_not_compile():
    pytest.importorskip("yara")
    body = 'rule r {\n strings:\n  $a = "abc\ndef"\n condition:\n  $a\n}'
    prepared = prepare_embedded_rule(body)
    assert prepared.status == DOES_NOT_COMPILE
    assert prepared.error


def test_compile_status_mirrors_opencti_any_exception_is_a_refusal(monkeypatch):
    class _Yara:
        @staticmethod
        def compile(source):
            raise RuntimeError("boom")
    monkeypatch.setitem(sys.modules, "yara", _Yara)
    assert yara_check.compile_status("rule r { condition: true }") == (DOES_NOT_COMPILE, "boom")
