"""GET /api/attack/index — the interface's ATT&CK index follows ATTACK_RELEASE (ADR-0087).

The API fixes its release when it starts (the lifespan calls
`attack_data.current()`), so each test sets ATTACK_RELEASE before it opens its
client.  The two committed tracks are read as they are: the default (19.2) in
pipeline/data/, 20.0 in pipeline/data/attack/20.0/.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from hashlib import sha256
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import api.main
from pipeline import attack_data

_DEFAULT_FILE = attack_data.DATA_DIR / "mitre_index.json"
_V20_FILE = attack_data.DATA_DIR / "attack" / "20.0" / "mitre_index.json"


@contextmanager
def _client(monkeypatch, release: str | None = None):
    """A client of an API started on `release` (None: ATTACK_RELEASE unset), with
    the database, the orphan requeue and the queue loop left out."""
    if release is not None:
        monkeypatch.setenv("ATTACK_RELEASE", release)
    with patch("api.main.init_db"), patch("api.queue_loop.requeue_orphans"), \
            patch("api.queue_loop.start_embedded"):
        with TestClient(api.main.app, raise_server_exceptions=True) as client:
            yield client


def _ids(body: dict) -> set[str]:
    return {t["id"] for t in body["techniques"]}


@pytest.mark.parametrize("release, path, version, has_t1698", [
    (None, _DEFAULT_FILE, "19.2", False),
    ("20.0", _V20_FILE, "20.0", True),
])
def test_serves_the_selected_track_as_it_is(monkeypatch, release, path, version, has_t1698):
    if not path.is_file():
        pytest.skip(f"{path} not built")
    with _client(monkeypatch, release) as client:
        resp = client.get("/api/attack/index")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["x-attack-release"] == version
    assert resp.content == path.read_bytes()
    body = resp.json()
    # Both tracks carry the 41 tactics; the static copy the interface used to
    # read had 39 (TA0038 and TA0039, two mobile tactics, were missing).
    assert len(body["tactics"]) == 41
    assert {"TA0038", "TA0039"} <= {t["id"] for t in body["tactics"]}
    assert ("T1698" in _ids(body)) is has_t1698


def test_the_etag_is_the_file_hash_and_a_matching_one_gets_a_304(monkeypatch):
    if not _DEFAULT_FILE.is_file():
        pytest.skip("pipeline/data/mitre_index.json not built")
    etag = f'"{sha256(_DEFAULT_FILE.read_bytes()).hexdigest()}"'
    with _client(monkeypatch) as client:
        first = client.get("/api/attack/index")
        assert first.headers["etag"] == etag
        assert first.headers["cache-control"] == "no-cache"

        for header in (etag, f"W/{etag}", f'"other", {etag}', "*"):
            again = client.get("/api/attack/index", headers={"If-None-Match": header})
            assert again.status_code == 304, header
            assert again.content == b""
            assert again.headers["x-attack-release"] == "19.2"
            assert again.headers["etag"] == etag

        other = client.get("/api/attack/index", headers={"If-None-Match": '"another-track"'})
    assert other.status_code == 200
    assert other.content == _DEFAULT_FILE.read_bytes()


def test_after_a_restart_on_another_track_the_cached_etag_gets_the_new_index(monkeypatch):
    """A browser holding the 19.2 index asks an API now on 20.0: it gets 20.0."""
    if not (_DEFAULT_FILE.is_file() and _V20_FILE.is_file()):
        pytest.skip("an ATT&CK track is not built")
    etag_19_2 = f'"{sha256(_DEFAULT_FILE.read_bytes()).hexdigest()}"'
    with _client(monkeypatch, "20.0") as client:
        resp = client.get("/api/attack/index", headers={"If-None-Match": etag_19_2})
    assert resp.status_code == 200
    assert resp.headers["x-attack-release"] == "20.0"
    assert resp.headers["etag"] != etag_19_2
    assert resp.content == _V20_FILE.read_bytes()


def test_a_track_without_an_index_is_a_404_not_the_default_one(tmp_path, monkeypatch):
    track = tmp_path / "attack" / "20.0"
    track.mkdir(parents=True)
    (track / attack_data.MANIFEST_NAME).write_text(json.dumps({"release": "20.0", "files": {}}))
    monkeypatch.setattr(attack_data, "TRACKS_DIR", tmp_path / "attack")
    with _client(monkeypatch, "20.0") as client:
        resp = client.get("/api/attack/index")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "ATT&CK 20.0 has no mitre_index.json"}
    assert "x-attack-release" not in resp.headers
