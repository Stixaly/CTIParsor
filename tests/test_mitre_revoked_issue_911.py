"""pipeline/mitre_db.py: a malformed attack_revoked.json reads as no revocation (#911).

The file is written to a temporary directory: no track and no index are needed.
"""
import json

import pytest

from pipeline import mitre_db


@pytest.fixture()
def revoked_file(tmp_path, monkeypatch):
    path = tmp_path / "attack_revoked.json"
    monkeypatch.setattr(mitre_db, "_REVOKED_PATH", path)
    monkeypatch.setattr(mitre_db.attack_data, "resolve", lambda p: p)
    mitre_db._revoked.cache_clear()
    yield path
    mitre_db._revoked.cache_clear()


@pytest.mark.parametrize("content", [
    [],                                                  # a JSON list, not an object
    "T0001",                                             # a JSON string
    {"revoked_by": ["T0001"], "names": {}},              # revoked_by is not a mapping
    {"revoked_by": {}, "names": "impair defenses"},      # names is not a mapping
])
def test_a_malformed_revoked_file_replaces_nothing_issue_911(revoked_file, content):
    revoked_file.write_text(json.dumps(content), encoding="utf-8")
    assert mitre_db.replacement_for("T0001") is None
    assert mitre_db.revoked_names() == {}


def test_a_well_formed_revoked_file_still_replaces_issue_911(revoked_file):
    revoked_file.write_text(json.dumps({"revoked_by": {"T0001": "T9999"},
                                        "names": {"old name": "T9999"}}), encoding="utf-8")
    assert mitre_db.replacement_for("t0001") == "T9999"
    assert mitre_db.revoked_names() == {"old name": "T9999"}
