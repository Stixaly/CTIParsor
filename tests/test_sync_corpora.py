"""scripts/sync_corpora.py: the exit status says whether every corpus that had to be
fetched was fetched.  The air-gapped packager (package_offline_corpora.sh) and
`bootstrap --strict` rely on it.

The registry, git and the tarball fetch are replaced by fakes: no test reaches
the network.
"""
from __future__ import annotations

import sys

from scripts import sync_corpora as sc

LAST = "Now run: python scripts/build_detection_index.py"


def git_corpus(name: str) -> dict:
    return {"name": name, "git": f"https://example.org/{name}.git", "path": f"/corpora/{name}"}


def tarball_corpus(name: str) -> dict:
    return {"name": name, "tarball": f"https://example.org/{name}.tar.gz", "path": f"/corpora/{name}"}


def sync(monkeypatch, capsys, corpora, *, command=lambda corpus: ["git", "clone", corpus["name"]],
         run=lambda cmd: True, tarball=lambda corpus: (True, "fetched")):
    """main() on `corpora` with every fetch replaced; returns (exit status, output)."""
    monkeypatch.setattr(sys, "argv", ["sync_corpora.py"])
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


def test_no_corpus_at_all_exits_0(monkeypatch, capsys):
    status, out = sync(monkeypatch, capsys, [])

    assert status == 0
    assert "no enabled corpora" in out
