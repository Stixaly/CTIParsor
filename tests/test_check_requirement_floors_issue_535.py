"""scripts/check_requirement_floors.py (issue #535): an OSV advisory may list an `affected`
entry with no `package` (a range of fixing git commits). It must be read, not a KeyError.

The OSV API is stubbed: the floors, the batch query and the advisory are given."""
from __future__ import annotations

from scripts import check_requirement_floors as crf

# One entry is a git-commit range with no package; the other names the package.
ADVISORY = {"affected": [
    {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "3f2a9c1"}]}]},
    {"package": {"name": "python-multipart", "ecosystem": "PyPI"},
     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.0.18"}]}]},
]}


def _stub(monkeypatch, advisory):
    monkeypatch.setattr(crf, "floors", lambda directory: {"python-multipart": ("0.0.9", "requirements.txt")})
    monkeypatch.setattr(crf, "_post", lambda path, payload: {"results": [{"vulns": [{"id": "OSV-1"}]}]})
    monkeypatch.setattr(crf, "_get", lambda path: advisory)


def test_an_affected_entry_without_a_package_is_skipped_and_the_fix_is_still_named(monkeypatch, capsys):  # (#535)
    """The package entry is matched and its release reported; the git-only entry does not crash."""
    _stub(monkeypatch, ADVISORY)

    assert crf.main() == 1

    out = capsys.readouterr().out
    assert "python-multipart 0.0.9 (requirements.txt): 1 advisories, fixed in 0.0.18" in out
    assert "1 of 1 floors are vulnerable versions" in out


def test_an_advisory_whose_entries_all_lack_a_package_is_still_a_vulnerable_floor(monkeypatch, capsys):  # (#535)
    """No release is named, but the floor is counted as vulnerable and the run does not stop on a KeyError."""
    _stub(monkeypatch, {"affected": [{"ranges": [{"type": "GIT", "events": [{"fixed": "3f2a9c1"}]}]}]})

    assert crf.main() == 1

    assert "1 of 1 floors are vulnerable versions" in capsys.readouterr().out
