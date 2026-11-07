"""pipeline/attack_data.py — issue #405: available() lists only the releases release() accepts."""
from __future__ import annotations

import json

import pytest

from pipeline import attack_data

_DEFAULT = "19.2"          # the release the committed pipeline/data/ files match


@pytest.fixture()
def tracks(tmp_path, monkeypatch):
    """An empty TRACKS_DIR; the release a process fixed is forgotten around the test."""
    root = tmp_path / "attack"
    root.mkdir()
    monkeypatch.setattr(attack_data, "TRACKS_DIR", root)
    attack_data.reset()
    yield root
    attack_data.reset()


def _track(root, version: str, manifest: str) -> None:
    (root / version).mkdir(parents=True, exist_ok=True)
    (root / version / attack_data.MANIFEST_NAME).write_text(manifest, encoding="utf-8")


def test_a_track_with_an_empty_manifest_is_not_listed(tracks):
    """Issue #405: `{}` was listed, and release('16.1') then raised UnknownAttackRelease."""
    _track(tracks, "16.1", "{}")
    assert attack_data.available() == [_DEFAULT]
    with pytest.raises(attack_data.UnknownAttackRelease, match="names no release"):
        attack_data.release("16.1")


@pytest.mark.parametrize("manifest", ["not json", '{"release": ""}', "[]"])
def test_a_track_with_an_unusable_manifest_is_not_listed(tracks, manifest):
    _track(tracks, "16.1", manifest)
    assert attack_data.available() == [_DEFAULT]


def test_a_track_whose_manifest_names_another_release_is_not_listed(tracks):
    _track(tracks, "16.1", json.dumps({"release": "16.2"}))
    assert attack_data.available() == [_DEFAULT]
    with pytest.raises(attack_data.UnknownAttackRelease, match="says release '16.2'"):
        attack_data.release("16.1")


def test_a_track_named_like_the_default_is_listed_once(tracks):
    """Issue #405: ['19.2', '16.1', '19.2'] — release('19.2') is the default anyway."""
    _track(tracks, "16.1", json.dumps({"release": "16.1"}))
    _track(tracks, _DEFAULT, json.dumps({"release": _DEFAULT}))
    assert attack_data.available() == [_DEFAULT, "16.1"]
    assert attack_data.release(_DEFAULT).default is True


def test_control_valid_tracks_are_listed_in_version_order(tracks):
    """Control: well-formed tracks are still listed, after the default, in version order."""
    _track(tracks, "20.0", json.dumps({"release": "20.0"}))
    _track(tracks, "9.1", json.dumps({"release": "9.1"}))
    _track(tracks, "10.0", "{}")
    assert attack_data.available() == [_DEFAULT, "9.1", "20.0"]


def test_every_listed_release_resolves(tracks):
    """What available() lists is what release() accepts, with no duplicate."""
    _track(tracks, "16.1", "{}")
    _track(tracks, "20.0", json.dumps({"release": "20.0"}))
    _track(tracks, _DEFAULT, json.dumps({"release": _DEFAULT}))
    listed = attack_data.available()
    assert len(listed) == len(set(listed))
    assert [attack_data.release(v).version for v in listed] == listed
