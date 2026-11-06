"""scripts/sync_corpora.py: the exit status says whether every corpus that had to be
fetched was fetched.  The air-gapped packager (package_offline_corpora.sh) and
`bootstrap --strict` rely on it.

The registry, git and the tarball fetch are replaced by fakes: no test reaches
the network.
"""
from __future__ import annotations

import sys

from pipeline import web_capture
from scripts import sync_corpora as sc

LAST = "Now run: python scripts/build_detection_index.py"


def git_corpus(name: str) -> dict:
    return {"name": name, "git": f"https://example.org/{name}.git", "path": f"/corpora/{name}"}


def tarball_corpus(name: str) -> dict:
    return {"name": name, "tarball": f"https://example.org/{name}.tar.gz", "path": f"/corpora/{name}"}


def sync(monkeypatch, capsys, corpora, *, command=lambda corpus: ["git", "clone", corpus["name"]],
         run=lambda cmd: True, tarball=lambda corpus: (True, "fetched")):
    """main() on `corpora` with every fetch replaced; returns (exit status, output).
    A git remote's host resolves to a public address, without the network."""
    monkeypatch.setattr(sys, "argv", ["sync_corpora.py"])
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(sc, "load_corpora", lambda config_path: corpora)
    monkeypatch.setattr(sc, "git_command", command)
    monkeypatch.setattr(sc, "_run", run)
    monkeypatch.setattr(sc, "fetch_tarball", tarball)
    status = sc.main()
    return status, capsys.readouterr().out


def test_every_corpus_synced_exits_0(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [git_corpus("a"), tarball_corpus("b")])

    assert status == 0
    assert out.splitlines()[-1] == f"[sync] 2/2 corpora synced, 0 failed. {LAST}"


def test_a_clone_that_fails_exits_1(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [git_corpus("ok"), git_corpus("broken")],
                       run=lambda cmd: cmd[-1] != "broken")

    assert status == 1
    assert out.splitlines()[-1] == f"[sync] 1/2 corpora synced, 1 failed. {LAST}"


def test_a_tarball_that_fails_exits_1_and_prints_the_bang_line_the_packager_greps(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [tarball_corpus("b")],
                       tarball=lambda corpus: (False, "download failed (details in the server log)"))

    assert status == 1
    assert "  ! download failed (details in the server log)" in out.splitlines()
    assert out.splitlines()[-1] == f"[sync] 0/1 corpora synced, 1 failed. {LAST}"


def test_a_corpus_managed_by_hand_is_skipped_and_is_not_a_failure(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [git_corpus("manual")], command=lambda corpus: None)

    assert status == 0
    assert "managed manually — skipped" in out
    assert out.splitlines()[-1] == f"[sync] 0/1 corpora synced, 0 failed. {LAST}"


def test_a_corpus_git_cannot_describe_is_skipped_and_is_not_a_failure(monkeypatch, capsys):
    def command(corpus):
        raise ValueError("no path configured")

    status, out = sync(monkeypatch, capsys, [git_corpus("nopath")], command=command)

    assert status == 0
    assert "no path configured — skipped" in out
    assert out.splitlines()[-1] == f"[sync] 0/1 corpora synced, 0 failed. {LAST}"


def test_a_remote_that_is_not_https_fails_before_git_runs(monkeypatch, capsys, tmp_path):
    """The https check runs before git: the corpus fails with the API's message,
    git never receives its command, the other corpora still sync, and the exit
    code says one failed (package_offline_corpora.sh reads it)."""
    ran: list = []
    monkeypatch.setattr(sc.subprocess, "run", lambda cmd, **kwargs: ran.append(cmd))
    ssh = {"name": "ssh", "git": "ssh://git@example.org/x.git", "path": str(tmp_path / "ssh")}
    good = {"name": "good", "git": "https://example.org/good.git", "path": str(tmp_path / "good")}

    status, out = sync(monkeypatch, capsys, [ssh, good], command=sc.git_command, run=sc._run)

    assert status == 1
    assert "! ssh: git remote refused: only https:// remotes are fetched ('ssh://git@example.org/x.git')" in out
    assert [cmd[-1] for cmd in ran] == [str(tmp_path / "good")]
    assert out.splitlines()[-1] == f"[sync] 1/2 corpora synced, 1 failed. {LAST}"


def test_a_remote_on_a_private_host_fails_before_git_runs(monkeypatch, capsys, tmp_path):
    """#274: a registry entry pointed at the cloud metadata service is refused
    like a non-https one: git never sees it, and the exit code says it failed."""
    ran: list = []
    monkeypatch.setattr(sc.subprocess, "run", lambda cmd, **kwargs: ran.append(cmd))
    metadata = {"name": "internal", "git": "https://169.254.169.254/latest/meta-data/x.git",
                "path": str(tmp_path / "internal")}
    good = {"name": "good", "git": "https://example.org/good.git", "path": str(tmp_path / "good")}

    status, out = sync(monkeypatch, capsys, [metadata, good], command=sc.git_command, run=sc._run)

    assert status == 1
    assert "! internal: git remote refused: not a safe remote to fetch (details in the server log)" in out
    assert [cmd[-1] for cmd in ran] == [str(tmp_path / "good")]
    assert out.splitlines()[-1] == f"[sync] 1/2 corpora synced, 1 failed. {LAST}"


def test_a_folder_that_is_not_its_remotes_clone_fails_before_git_runs_issue_367(monkeypatch, capsys, tmp_path):
    """#367: a plain folder where the corpus should be cloned is refused before git
    runs, the reason is printed, and the other corpora still sync."""
    ran: list = []
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "notes.txt").write_text("", encoding="utf-8")   # not empty: an empty folder is cloned (#367)
    stray ={"name": "stray", "git": "https://example.org/stray.git", "path": str(plain)}
    good = {"name": "good", "git": "https://example.org/good.git", "path": str(tmp_path / "good")}

    status, out = sync(monkeypatch, capsys, [stray, good], command=lambda corpus: ["git", "pull", corpus["name"]],
                       run=lambda cmd: ran.append(cmd) or True)

    assert status == 1
    assert f"! stray: {plain} exists but is not a git clone of its own" in out
    assert ran == [["git", "pull", "good"]]
    assert out.splitlines()[-1] == f"[sync] 1/2 corpora synced, 1 failed. {LAST}"


def test_no_corpus_at_all_exits_0(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [])

    assert status == 0
    assert "no enabled corpora" in out
