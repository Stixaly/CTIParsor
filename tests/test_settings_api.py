"""Tests for the settings / corpora-management API (ADR-0007 Slice 1)."""
import api.routes.settings as settings_mod

_RULE = """\
title: PowerShell Encoded Command
id: aaaa1111-bbbb-2222-cccc-333333333333
detection:
  selection:
    Image|endswith: '\\powershell.exe'
  condition: selection
level: high
logsource:
  category: process_creation
tags:
  - attack.t1059.001
"""


def _setup(tmp_path, monkeypatch):
    """A committed registry with one corpus 'demo' pointing at a local clone."""
    clone = tmp_path / "corpora" / "demo"
    clone.mkdir(parents=True)
    (clone / "r.yml").write_text(_RULE, encoding="utf-8")
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(
        "corpora:\n  - name: demo\n    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n    license: DRL-1.1\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)
    return cfg


def test_list_corpora(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    body = temp_db_client.get("/api/settings/corpora").json()
    assert [c["name"] for c in body["corpora"]] == ["demo"]
    assert body["corpora"][0]["rules"] == 0          # not ingested yet
    assert body["corpora"][0]["enabled"] is True


def test_add_corpus_writes_overlay(temp_db, temp_db_client, tmp_path, monkeypatch):
    cfg = _setup(tmp_path, monkeypatch)
    r = temp_db_client.post("/api/settings/corpora", json={
        "name": "extra", "git": "https://github.com/org/extra.git", "license": "Apache-2.0"})
    assert r.status_code == 200, r.text
    names = [c["name"] for c in r.json()["corpora"]]
    assert names == ["demo", "extra"]
    extra = next(c for c in r.json()["corpora"] if c["name"] == "extra")
    assert extra["path"] == "./corpora/extra"          # path defaulted from name
    # the committed file is untouched; the addition lives in the gitignored overlay
    assert "extra" not in cfg.read_text(encoding="utf-8")
    assert (cfg.parent / "detection_corpora.local.yaml").exists()


def test_remove_committed_corpus_disables_via_overlay(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    r = temp_db_client.delete("/api/settings/corpora/demo")
    assert r.status_code == 200
    demo = next(c for c in r.json()["corpora"] if c["name"] == "demo")
    assert demo["enabled"] is False                    # disabled, not deleted from committed


def test_rebuild_ingests_local_clone(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    summary = temp_db_client.post("/api/settings/corpora/rebuild").json()
    assert summary["total"] == 1 and summary["written"]["demo"] == 1
    body = temp_db_client.get("/api/settings/corpora").json()
    assert body["corpora"][0]["rules"] == 1            # count reflects ingest


def test_add_rejects_non_sigma_adapter(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    r = temp_db_client.post("/api/settings/corpora", json={"name": "x", "adapter": "elastic"})
    assert r.status_code == 400
