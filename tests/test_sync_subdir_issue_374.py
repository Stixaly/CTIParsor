"""A sync whose `subdir` is missing says so instead of reporting success (#374).

The Git fetch succeeds, then the builder skips a corpus whose `subdir` does not
exist and writes none of its rules. The sync route used to throw that bilan away
and answer `ok: true`. It now answers 422 naming the missing folder and keeps the
index that was there before. A corpus that was imported answers 200 with its rule
count and the files the adapter could not read (`file_errors`).
"""
import api.routes.settings as settings_mod
from pipeline.detection.builder import rebuild_store

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


def _registry(tmp_path, monkeypatch, subdir: str):
    """A public git corpus whose clone keeps its rules under `rules/`."""
    clone = tmp_path / "corpora" / "demo"
    (clone / "rules").mkdir(parents=True)
    (clone / "rules" / "r.yml").write_text(_RULE, encoding="utf-8")
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(
        "corpora:\n  - name: demo\n    adapter: sigma\n"
        f"    git: https://h/demo.git\n    path: {clone.as_posix()}\n    subdir: {subdir}\n"
        "    license: DRL-1.1\n    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda c: (True, "up to date"))
    # The clone is a plain copy, not a git checkout: the clone check (#367) has its own tests.
    monkeypatch.setattr(settings_mod, "clone_mismatch", lambda c: None)
    return cfg


def test_a_missing_subdir_is_a_422_that_names_it_issue_374(temp_db, temp_db_client, tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch, "rulez")
    r = temp_db_client.post("/api/settings/corpora/demo/sync")
    assert r.status_code == 422
    assert "rulez" in r.json()["detail"] and "not re-imported" in r.json()["detail"]
    assert temp_db_client.get("/api/settings/corpora").json()["corpora"][0]["rules"] == 0


def test_a_refused_sync_keeps_the_rules_indexed_before_issue_374(temp_db, temp_db_client, tmp_path, monkeypatch):
    cfg = _registry(tmp_path, monkeypatch, "rules")
    assert temp_db_client.post("/api/settings/corpora/demo/sync").status_code == 200
    cfg.write_text(cfg.read_text(encoding="utf-8").replace("subdir: rules", "subdir: rulez"), encoding="utf-8")

    assert temp_db_client.post("/api/settings/corpora/demo/sync").status_code == 422
    assert temp_db_client.get("/api/settings/corpora").json()["corpora"][0]["rules"] == 1


def test_a_correct_subdir_is_a_200_with_its_rules_and_no_file_errors_issue_374(
    temp_db, temp_db_client, tmp_path, monkeypatch,
):
    _registry(tmp_path, monkeypatch, "rules")
    r = temp_db_client.post("/api/settings/corpora/demo/sync")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["detail"] == "up to date"
    assert body["rules"] == 1 and body["file_errors"] == []


def test_a_file_that_cannot_be_read_is_listed_in_the_200_issue_374(temp_db, temp_db_client, tmp_path, monkeypatch):
    _registry(tmp_path, monkeypatch, "rules")
    (tmp_path / "corpora" / "demo" / "rules" / "bad.yml").write_bytes(b"\xff")
    r = temp_db_client.post("/api/settings/corpora/demo/sync")
    assert r.status_code == 200, r.text
    assert r.json()["rules"] == 1
    assert [e["path"] for e in r.json()["file_errors"]] == ["bad.yml"]


# ── the builder says why it skipped a corpus ─────────────────────────────────

def test_skip_reasons_tell_a_missing_subdir_from_a_missing_path_issue_374(temp_db, tmp_path):
    clone = tmp_path / "clone"
    clone.mkdir()
    config = tmp_path / "detection_corpora.yaml"
    config.write_text(
        "corpora:\n"
        "  - name: wrong-subdir\n"
        "    adapter: sigma\n"
        f"    path: {clone.as_posix()}\n"
        "    subdir: rulez\n"
        "    license: unknown\n"
        "    enabled: true\n"
        "  - name: not-downloaded\n"
        "    adapter: sigma\n"
        f"    path: {(tmp_path / 'nowhere').as_posix()}\n"
        "    subdir: rules\n"
        "    license: unknown\n"
        "    enabled: true\n"
        "  - name: unknown-adapter\n"
        "    adapter: elastic\n"
        f"    path: {clone.as_posix()}\n"
        "    license: unknown\n"
        "    enabled: true\n"
        "  - name: no-path\n"
        "    adapter: sigma\n"
        "    license: unknown\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    conn = temp_db.get_rule_conn()

    summary = rebuild_store(conn, config)

    assert summary["skipped"] == ["wrong-subdir", "not-downloaded", "unknown-adapter", "no-path"]
    reasons = summary["skip_reasons"]
    assert set(reasons) == set(summary["skipped"])
    assert reasons["wrong-subdir"] == f"subdir 'rulez' not found under {clone.as_posix()}"
    assert reasons["not-downloaded"] == f"{(tmp_path / 'nowhere').as_posix()} does not exist (not downloaded yet)"
    assert reasons["unknown-adapter"] == "unknown adapter 'elastic'"
    assert reasons["no-path"] == "no path configured in the registry"
