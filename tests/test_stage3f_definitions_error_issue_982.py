"""Issue #982 point 5: a failed load of the ATT&CK definitions is not cached.

Stage 3f offers the candidates of a selection prompt with their definitions.
A load that raised used to be cached as {} for the whole process, with the
candidates offered without a word about it.  Now the next call loads again,
and `definitions_error()` says why the last load failed.

Every call is a fake, or reads the committed ATT&CK index; no model is needed.
"""
from __future__ import annotations

import pytest

from pipeline import attack_data, mitre_db
from pipeline import stage3f_ttp_select as s3f


@pytest.fixture(autouse=True)
def fresh_definitions():
    s3f._forget_definitions()
    yield
    s3f._forget_definitions()


def test_a_failed_load_returns_nothing_and_says_why(monkeypatch):
    def unreadable():
        raise RuntimeError("index cut in half")

    monkeypatch.setattr(mitre_db, "get_techniques", unreadable)
    assert s3f._definitions() == {}
    assert s3f.definitions_error() == "ATT&CK definitions unreadable: RuntimeError: index cut in half"


def test_the_call_after_a_failed_load_loads_again(monkeypatch):
    def unreadable():
        raise RuntimeError("index cut in half")

    monkeypatch.setattr(mitre_db, "get_techniques", unreadable)
    assert s3f._definitions() == {}
    monkeypatch.undo()

    defs = s3f._definitions()
    assert defs
    assert set(defs) == {t["id"].upper() for t in mitre_db.get_techniques()}
    assert s3f.definitions_error() is None


def test_a_success_is_kept_without_loading_again(monkeypatch):
    defs = s3f._definitions()
    assert defs and s3f.definitions_error() is None

    def unreadable():
        raise RuntimeError("index cut in half")

    monkeypatch.setattr(mitre_db, "get_techniques", unreadable)
    assert s3f._definitions() is defs
    assert s3f.definitions_error() is None


def test_no_error_before_any_load():
    assert s3f.definitions_error() is None


def test_an_unknown_release_still_reaches_the_caller(monkeypatch):
    def unknown():
        raise attack_data.UnknownAttackRelease("no such ATT&CK release here")

    monkeypatch.setattr(mitre_db, "get_techniques", unknown)
    with pytest.raises(attack_data.UnknownAttackRelease):
        s3f._definitions()
    assert s3f.definitions_error() is None


def test_cache_clear_still_forgets_a_success(monkeypatch):
    s3f._definitions()
    s3f._definitions.cache_clear()

    def unreadable():
        raise RuntimeError("index cut in half")

    monkeypatch.setattr(mitre_db, "get_techniques", unreadable)
    assert s3f._definitions() == {}
    assert s3f.definitions_error() is not None
