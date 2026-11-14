"""POST /api/settings/corpora: input that cannot be parsed or stored is a 4xx, never a 500 (#760, #761, #762)."""
import pytest

import api.routes.settings as settings_mod


def _setup(tmp_path, monkeypatch):
    """A committed registry with one corpus 'demo' pointing at a local clone."""
    clone = tmp_path / "corpora" / "demo"
    clone.mkdir(parents=True)
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(
        "corpora:\n  - name: demo\n    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n    license: DRL-1.1\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)
    return cfg


def _overlay(cfg):
    """The gitignored overlay's text, or None when no overlay has been written."""
    path = cfg.parent / "detection_corpora.local.yaml"
    return path.read_text(encoding="utf-8") if path.exists() else None


def test_a_git_remote_with_unbalanced_ipv6_brackets_is_a_400(temp_db, temp_db_client, tmp_path, monkeypatch):
    """#760: urlsplit("https://[::1") raised ValueError, so the request was a 500."""
    cfg = _setup(tmp_path, monkeypatch)
    before = _overlay(cfg)
    r = temp_db_client.post("/api/settings/corpora", json={"name": "testcorpus", "git": "https://[::1"})
    assert r.status_code == 400, r.text
    assert _overlay(cfg) == before


@pytest.mark.parametrize("body", [
    {"name": "testcorpus", "path": "./corpora/test\u0000"},   # #761: NUL in path
    {"name": "testcorpus", "path": "./corpora/demo", "subdir": "sub\u0000"},   # #761: NUL in subdir
])
def test_a_nul_byte_in_path_or_subdir_is_a_4xx_and_writes_nothing(temp_db, temp_db_client, tmp_path, monkeypatch, body):
    """#761: Path.resolve() raised 'embedded null' on the path, so the request was a 500."""
    cfg = _setup(tmp_path, monkeypatch)
    before = _overlay(cfg)
    r = temp_db_client.post("/api/settings/corpora", json=body)
    assert 400 <= r.status_code < 500, r.text
    assert _overlay(cfg) == before


def test_a_lone_surrogate_in_a_text_field_is_a_422_and_writes_nothing(temp_db, temp_db_client, tmp_path, monkeypatch):
    """#762: the overlay was written, then the response failed to encode as UTF-8 (a 500)."""
    cfg = _setup(tmp_path, monkeypatch)
    before = _overlay(cfg)
    # Sent as a JSON escape: httpx would refuse to encode the raw surrogate itself.
    r = temp_db_client.post("/api/settings/corpora", content=b'{"name": "testcorpus", "license": "\\ud800"}',
                            headers={"content-type": "application/json"})
    assert r.status_code == 422, r.text
    assert _overlay(cfg) == before
