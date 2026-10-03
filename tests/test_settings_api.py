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
    # A git remote is checked like a tarball URL (public host, resolved
    # addresses).  The GitHub remotes these tests post must not need DNS; every
    # other URL still meets the real policy (a file:// or loopback tarball
    # is refused on its scheme and address, before any lookup).
    real_validate_url = settings_mod.validate_url
    monkeypatch.setattr(settings_mod, "validate_url",
                        lambda url: url if url.startswith("https://github.com/") else real_validate_url(url))
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
    "HTTPS://gitlab.example.org/org/repo",
])
def test_https_remotes_on_a_public_host_are_accepted(good_remote, monkeypatch):
    monkeypatch.setattr(settings_mod, "validate_url", lambda url: url)
    settings_mod._validate_remote(good_remote, "git")  # must not raise


@pytest.mark.parametrize("bad_remote", [
    "git@github.com:your-org/private-sigma.git",   # scp-shorthand: ssh
    "ssh://git@internal.corp/org/repo.git",
    "git://example.com/repo.git",
    "file:///etc",
    "http://169.254.169.254/latest/meta-data/",
    "http://github.com/SigmaHQ/sigma.git",         # plain http: no
])
def test_remotes_that_are_not_https_are_refused(bad_remote, monkeypatch):
    """`git clone` runs on the server with its network (audit B 8.2.2): only an
    https:// remote on a public host, exactly like a tarball URL.  A private
    corpus over SSH is cloned by hand and registered with its `path`."""
    monkeypatch.setattr(settings_mod, "validate_url", lambda url: url)
    with pytest.raises(HTTPException) as exc:
        settings_mod._validate_remote(bad_remote, "git")
    assert exc.value.status_code == 400
    assert "https" in str(exc.value.detail)


def test_an_https_remote_on_a_private_host_is_refused(monkeypatch):
    from pipeline.web_capture import CaptureError

    def refuse(url):
        raise CaptureError("Host 'intranet' resolves to a non-public address")
    monkeypatch.setattr(settings_mod, "validate_url", refuse)
    with pytest.raises(HTTPException) as exc:
        settings_mod._validate_remote("https://intranet/repo.git", "git")
    assert exc.value.status_code == 400
    assert "non-public" in str(exc.value.detail)


def test_tarball_remotes_keep_their_own_policy(monkeypatch):
    """The https rule is the git remote's; a tarball is checked by validate_url
    at creation (below) and at fetch time, as before."""
    settings_mod._validate_remote("https://example.org/rules.tar.gz", "tarball")


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


# ── Formats, validation, enable/disable and per-corpus sync ─────────────────

def test_formats_list_every_known_format_with_its_counts(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    temp_db_client.post("/api/settings/corpora/rebuild")
    temp_db_client.post("/api/settings/corpora", json={"name": "et", "adapter": "suricata"})

    formats = {f["format"]: f for f in temp_db_client.get("/api/settings/formats").json()["formats"]}

    assert set(formats) >= {"sigma", "suricata", "yara"}
    assert formats["sigma"] == {"format": "sigma", "available": True, "corpora": 1, "rules": 1}
    assert formats["suricata"]["corpora"] == 1 and formats["yara"]["corpora"] == 0


def test_a_configured_format_without_a_parser_stays_visible(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(settings_mod, "_ADAPTERS", {"sigma": object()})

    r = temp_db_client.post("/api/settings/corpora", json={"name": "sig-base", "adapter": "YARA"})
    assert "no parser in this build" in r.json()["warning"] and "Available now: sigma" in r.json()["warning"]
    formats = {f["format"]: f for f in temp_db_client.get("/api/settings/formats").json()["formats"]}
    assert formats["yara"]["available"] is False and formats["yara"]["corpora"] == 1


@pytest.mark.parametrize("body,message", [
    ({"name": "   "}, "name is required"),
    ({"name": "x", "git": "https://h/x.git", "tarball": "https://h/x.tgz"}, "not both"),
    ({"name": "x", "tarball": "file:///etc/passwd"}, "not a safe URL"),
    ({"name": "x", "tarball": "http://127.0.0.1/rules.tgz"}, "not a safe URL"),
])
def test_create_refuses_an_incomplete_or_unsafe_corpus(temp_db, temp_db_client, tmp_path, monkeypatch,
                                                       body, message):
    _setup(tmp_path, monkeypatch)
    r = temp_db_client.post("/api/settings/corpora", json=body)
    assert r.status_code == 400 and message in r.json()["detail"]


def test_a_corpus_can_be_disabled_and_enabled_again(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)

    off = temp_db_client.patch("/api/settings/corpora/demo", json={"enabled": False}).json()
    assert off["corpora"][0]["enabled"] is False
    on = temp_db_client.patch("/api/settings/corpora/demo", json={"enabled": True}).json()
    assert on["corpora"][0]["enabled"] is True and on["corpora"][0]["license"] == "DRL-1.1"
    assert temp_db_client.patch("/api/settings/corpora/nope", json={"enabled": True}).status_code == 404


def _registry(tmp_path, monkeypatch, entry: str):
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text("corpora:\n" + entry, encoding="utf-8")
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)


@pytest.mark.parametrize("entry,status,message", [
    ("  - name: manual\n    path: ./corpora/manual\n", 400, "managed manually"),
    ("  - name: secret\n    git: git@github.com:org/secret.git\n    path: ./corpora/secret\n"
     "    private: true\n", 400, "is private"),
])
def test_sync_refuses_manual_and_private_corpora(temp_db, temp_db_client, tmp_path, monkeypatch,
                                                 entry, status, message):
    _registry(tmp_path, monkeypatch, entry)
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda c: pytest.fail("must not fetch"))
    name = entry.split("name: ")[1].split("\n")[0]
    r = temp_db_client.post(f"/api/settings/corpora/{name}/sync")
    assert r.status_code == status and message in r.json()["detail"]
    assert temp_db_client.post("/api/settings/corpora/nope/sync").status_code == 404


def test_a_failed_sync_is_a_502(temp_db, temp_db_client, tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch, "  - name: pub\n    git: https://h/pub.git\n    path: ./corpora/pub\n")
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda c: (False, "fatal: repository not found"))
    r = temp_db_client.post("/api/settings/corpora/pub/sync")
    assert r.status_code == 502 and "repository not found" in r.json()["detail"]


def test_a_successful_sync_reingests_the_store(temp_db, temp_db_client, tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    cfg = settings_mod._CONFIG
    cfg.write_text(cfg.read_text(encoding="utf-8") + "    git: https://h/demo.git\n", encoding="utf-8")
    synced = []
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda c: synced.append(c["name"]) or (True, "up to date"))

    r = temp_db_client.post("/api/settings/corpora/demo/sync").json()

    assert synced == ["demo"] and r["detail"] == "up to date"
    assert r["corpora"][0]["rules"] == 1                # rebuilt from the local clone
