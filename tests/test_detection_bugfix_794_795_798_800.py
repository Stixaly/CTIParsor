"""Regression tests for issues #794, #795, #798 and #800 (detection corpora).

- #794: a download cut off mid-stream raises http.client.IncompleteRead, which is an
  HTTPException and not an OSError: it must be a failed sync, not an exception.
- #795: a PAX member name that carries a NUL byte is refused as unsafe, not sent to
  is_contained, which raises ValueError on it.
- #798: YARA dedup keys look for `strings:` and `condition:` without the comments.
- #800: a module named by a YARA string or comment is not an import the rule uses.

No network: the download is monkeypatched and DNS is fixed to a public address.
"""
from __future__ import annotations

import http.client
import io
import tarfile
from pathlib import Path

import pytest

import pipeline.detection.sync as sync_mod
from pipeline import web_capture
from pipeline.detection.sync import fetch_tarball, sync_corpus
from pipeline.detection.yara import YaraAdapter
from pipeline.detection.yara_atoms import split_rules
from pipeline.detection.yara_check import with_declared_imports

_PUBLIC_IP = "93.184.216.34"
_URL = "https://example.com/corpus.tar"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    """validate_url resolves the tarball host: every host is public, offline."""
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: [_PUBLIC_IP])


def _pax_archive(path: Path) -> Path:
    """A PAX tar with two members: `rule\\x00.yml` (its PAX `path` carries a NUL,
    which tarfile's writer would truncate, so the header is set by hand) and a
    valid `ok/rule.yml`."""
    archive = path / "pax.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as tar:
        for name, data, pax in (
            ("placeholder", b"x", {"path": "rule\x00.yml"}),
            ("ok/rule.yml", b"rule a { condition: true }", {}),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.pax_headers = pax
            tar.addfile(info, io.BytesIO(data))
    return archive


# --- #794 -------------------------------------------------------------------------

def test_a_download_cut_off_mid_stream_is_a_failed_sync_issue_794(tmp_path: Path, monkeypatch) -> None:
    """IncompleteRead from the download answers (False, "download failed ...")."""
    def cut_off(url: str, dest: Path, *, timeout: int) -> int:
        raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(sync_mod, "_download", cut_off)
    corpus = {"name": "t", "tarball": _URL, "path": str(tmp_path / "corpus")}
    ok, detail = fetch_tarball(corpus)
    assert ok is False
    assert detail.startswith("download failed")
    assert not (tmp_path / "corpus").exists()


def test_a_cut_off_download_reaches_the_settings_route_as_a_result_issue_794(
        tmp_path: Path, monkeypatch) -> None:
    """sync_corpus, the call the settings route makes, returns the failure too."""
    def cut_off(url: str, dest: Path, *, timeout: int) -> int:
        raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(sync_mod, "_download", cut_off)
    ok, detail = sync_corpus({"name": "t", "tarball": _URL, "path": str(tmp_path / "corpus")})
    assert ok is False
    assert detail.startswith("download failed")


def test_a_cut_off_sidecar_is_no_checksum_issue_794(tmp_path: Path, monkeypatch) -> None:
    """A sidecar cut off mid-read is None, as any other sidecar failure: the sync goes on."""
    class CutOff:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, n: int = -1) -> bytes:
            raise http.client.IncompleteRead(b"")

    monkeypatch.setattr(sync_mod._SAFE_OPENER, "open", lambda req, timeout: CutOff())
    assert sync_mod._fetch_text(f"{_URL}.md5", timeout=5) is None


# --- #795 -------------------------------------------------------------------------

def test_a_member_name_with_a_nul_is_skipped_not_raised_issue_795(tmp_path: Path, monkeypatch) -> None:
    """The NUL member is counted as skipped; the valid member is extracted."""
    archive = _pax_archive(tmp_path)

    def fake_download(url: str, dest: Path, *, timeout: int) -> int:
        dest.write_bytes(archive.read_bytes())
        return archive.stat().st_size

    monkeypatch.setattr(sync_mod, "_download", fake_download)
    monkeypatch.setattr(sync_mod, "_fetch_text", lambda url, timeout: None)
    path = tmp_path / "corpus"
    ok, detail = fetch_tarball({"name": "t", "tarball": _URL, "path": str(path)})
    assert ok is True, detail
    assert "1 unsafe members skipped" in detail
    assert (path / "ok" / "rule.yml").read_bytes() == b"rule a { condition: true }"


# --- #798 -------------------------------------------------------------------------

def _key(text: str) -> str:
    return YaraAdapter()._dedup_key(split_rules(text)[0])


_PLAIN = 'rule R {\n  strings:\n    $a = "abcdef"\n  condition:\n    $a\n}\n'
_WITH_COMMENT = ('rule R {\n  /*\n  strings:\n    $old = "old.example.org"\n  */\n'
                 '  strings:\n    $a = "abcdef"\n  condition:\n    $a\n}\n')


def test_a_comment_naming_strings_does_not_change_the_dedup_key_issue_798() -> None:
    """A `/* strings: */` block before the real section is not a section."""
    assert _key(_WITH_COMMENT) == _key(_PLAIN)
    assert _key(_PLAIN) != ""


def test_a_comment_naming_condition_does_not_change_the_dedup_key_issue_798() -> None:
    """Control on the other keyword: a `/* condition: */` block before the real one."""
    with_comment = _PLAIN.replace("  strings:", "  /* condition: $z */\n  strings:")
    assert _key(with_comment) == _key(_PLAIN)


def test_a_different_string_still_changes_the_dedup_key_issue_798() -> None:
    """Control: stripping comments does not merge rules that differ in a string."""
    other = _PLAIN.replace("abcdef", "ghijkl")
    assert _key(other) != _key(_PLAIN)


# --- #800 -------------------------------------------------------------------------

def test_a_module_named_in_a_string_gets_no_import_issue_800() -> None:
    """`"cuckoo.exe"` in a string is not a use of the `cuckoo` module."""
    body = 'rule R { strings: $a = "cuckoo.exe" condition: $a }'
    assert with_declared_imports(body, ("cuckoo",)) == (body, ())


def test_a_module_named_in_a_comment_gets_no_import_issue_800() -> None:
    """A comment is not code either."""
    body = 'rule R { /* cuckoo.foo */ condition: true }'
    assert with_declared_imports(body, ("cuckoo",)) == (body, ())


def test_a_module_used_in_the_condition_keeps_its_import_issue_800() -> None:
    """Control: `cuckoo.foo` in the condition is a use, so the import is added."""
    body = "rule R { condition: cuckoo.foo }"
    out, added = with_declared_imports(body, ("cuckoo",))
    assert added == ("cuckoo",)
    assert out == 'import "cuckoo"\n\n' + body
