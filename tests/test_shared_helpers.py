"""Behaviour locks for the helpers extracted from duplicated code."""
from __future__ import annotations

import pytest

from pipeline.detection.textutil import unescape
from pipeline.env_flags import env_bool
from pipeline.llm_parse import parse_numbered_claims
from pipeline.stix_access import field


def test_env_bool_absent_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_FLAG", raising=False)
    assert env_bool("TEST_FLAG", default=True) is True
    assert env_bool("TEST_FLAG", default=False) is False


@pytest.mark.parametrize("val", ["1", "true", "TRUE", " yes ", "on"])
def test_env_bool_truthy_vocabulary(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv("TEST_FLAG", val)
    assert env_bool("TEST_FLAG", default=False) is True


@pytest.mark.parametrize("val", ["0", "false", "FALSE", " no ", "off"])
def test_env_bool_falsy_vocabulary(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv("TEST_FLAG", val)
    assert env_bool("TEST_FLAG", default=True) is False


@pytest.mark.parametrize("val", ["maybe", ""])
def test_env_bool_unrecognised_falls_back_to_default(monkeypatch: pytest.MonkeyPatch, val: str) -> None:
    monkeypatch.setenv("TEST_FLAG", val)
    assert env_bool("TEST_FLAG", default=True) is True
    assert env_bool("TEST_FLAG", default=False) is False


def test_parse_numbered_claims_extracts_array() -> None:
    raw = 'noise [{"n": 1, "verified": true, "quote": "q"}] trailing'
    result = parse_numbered_claims(raw, count=2)
    assert result is not None
    assert 1 in result
    assert result[1]["verified"] is True


def test_parse_numbered_claims_accepts_whole_float_index() -> None:
    raw = '[{"n": 2.0, "verified": true}]'
    result = parse_numbered_claims(raw, count=2)
    assert result is not None
    assert 2 in result


def test_parse_numbered_claims_rejects_bool_index() -> None:
    raw = '[{"n": true, "verified": true}]'
    result = parse_numbered_claims(raw, count=2)
    assert result is None


def test_parse_numbered_claims_rejects_out_of_range() -> None:
    raw = '[{"n": 7, "verified": true}]'
    result = parse_numbered_claims(raw, count=2)
    assert result is None


def test_parse_numbered_claims_returns_none_without_array() -> None:
    raw = "pas de tableau ici"
    result = parse_numbered_claims(raw, count=2)
    assert result is None


def test_parse_numbered_claims_ignores_non_finite() -> None:
    raw = '[{"n": NaN, "verified": true}]'
    result = parse_numbered_claims(raw, count=2)
    assert result is None


def test_field_reads_mapping() -> None:
    assert field({"type": "malware"}, "type") == "malware"


def test_field_reads_attribute() -> None:
    class Obj:
        type = "malware"
    assert field(Obj(), "type") == "malware"


def test_field_missing_returns_none() -> None:
    assert field({"other": "x"}, "type") is None
    class Obj:
        pass
    assert field(Obj(), "type") is None


def test_unescape_single_pass_does_not_reread_backslash() -> None:
    table = {";": ";", '"': '"', "\\": "\\", ":": ":"}
    # Input: a, \, \, :, b
    assert unescape("a\\\\:b", table) == "a\\:b"


def test_unescape_keeps_unknown_escape_verbatim() -> None:
    table = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
    assert unescape("\\x", table) == "\\x"


def test_unescape_decodes_table_entries() -> None:
    table = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "r": "\r"}
    assert unescape("\\n", table) == "\n"
    assert unescape("\\t", table) == "\t"


def test_unescape_non_string_returns_empty() -> None:
    assert unescape(None, {}) == ""  # type: ignore[arg-type]
    assert unescape(123, {}) == ""  # type: ignore[arg-type]


def test_unescape_trailing_backslash_is_kept() -> None:
    table = {";": ";"}
    assert unescape("a\\", table) == "a\\"
