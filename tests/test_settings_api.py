"""Tests for the settings / corpora-management API (ADR-0007 Slice 1)."""
import pytest
from fastapi import HTTPException

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


# ── path containment (a corpus's local clone must stay under corpora/) ────────
#
# `_validate_corpus_path`/`_validate_remote` are exercised directly rather than
# through the API: `_CORPORA_ROOT` is resolved once at import time against the
# real repository root, not against `_setup()`'s `tmp_path` registry, so the
# meaningful boundary to test is the function's own logic, not a monkeypatched
# app. `test_create_corpus_rejects_a_path_escaping_corpora` below still goes
# through the API once, to lock that create_corpus actually calls it.

def test_path_inside_corpora_root_is_accepted():
    settings_mod._validate_corpus_path("./corpora/some-new-corpus", None)  # must not raise


@pytest.mark.parametrize("bad_path", [
    "../../../../etc/cron.d/evil",
    "/etc/cron.d/evil",
    "./corpora/../../etc/passwd",
])
def test_path_escaping_corpora_root_is_rejected(bad_path):
    with pytest.raises(HTTPException) as exc:
        settings_mod._validate_corpus_path(bad_path, None)
    assert exc.value.status_code == 400
    assert "path" in str(exc.value.detail)


def test_subdir_escaping_corpora_root_is_rejected_even_with_a_contained_path():
    """`corpus_root()` joins `path` and `subdir` — a contained `path` is not
    enough if `subdir` walks back out of it."""
    with pytest.raises(HTTPException) as exc:
        settings_mod._validate_corpus_path("./corpora/demo", "../../../../etc")
    assert exc.value.status_code == 400
    assert "subdir" in str(exc.value.detail)


def test_subdir_staying_inside_the_clone_is_accepted():
    settings_mod._validate_corpus_path("./corpora/demo", "sigma")  # must not raise


@pytest.mark.parametrize("bad_remote", [
    "--upload-pack=touch /tmp/pwned",
    "-oProxyCommand=touch /tmp/pwned",
    "ext::sh -c touch /tmp/pwned",
    "fd::0",
])
def test_remote_shaped_as_a_flag_or_transport_helper_is_rejected(bad_remote):
    with pytest.raises(HTTPException) as exc:
        settings_mod._validate_remote(bad_remote, "git")
    assert exc.value.status_code == 400


@pytest.mark.parametrize("good_remote", [
    "https://github.com/SigmaHQ/sigma.git",
    "git@github.com:your-org/private-sigma.git",   # scp-shorthand, used for private corpora
    "ssh://git@example.com/org/repo.git",
])
def test_ordinary_remotes_are_accepted(good_remote):
    settings_mod._validate_remote(good_remote, "git")  # must not raise


def test_create_corpus_rejects_a_path_escaping_corpora(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    r = temp_db_client.post("/api/settings/corpora", json={
        "name": "evil", "git": "https://github.com/org/evil.git",
        "path": "../../../../tmp/evil-corpus",
    })
    assert r.status_code == 400
    assert "path" in r.json()["detail"]
    # nothing was written to the overlay
    names = [c["name"] for c in temp_db_client.get("/api/settings/corpora").json()["corpora"]]
    assert "evil" not in names


def test_create_corpus_rejects_an_upload_pack_flag_as_the_git_remote(temp_db, temp_db_client, tmp_path, monkeypatch):
    """
    Locks the argument-injection guard: `git clone <remote> <path>` runs the
    attacker's `remote` as argv, not through a shell, but a value shaped like
    `--upload-pack=<command>` is still parsed by git itself as an option
    rather than a URL (GitHub Security Lab, "Wagging the Dog") — the app must
    refuse it before it ever reaches `git_command()`.
    """
    _setup(tmp_path, monkeypatch)
    r = temp_db_client.post("/api/settings/corpora", json={
        "name": "evil", "git": "--upload-pack=touch /tmp/pwned",
    })
    assert r.status_code == 400
