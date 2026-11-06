"""Issue #367: a Redownload must not pull into a folder that is not the clone of the
configured remote. Real throwaway git repositories in tmp_path; the only network
step (the `pull` itself) is recorded, never run, and the DNS lookup of
validate_url is replaced, so nothing leaves the machine."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import api.routes.settings as settings_mod
import pipeline.detection.sync as sync_mod
from pipeline import web_capture
from pipeline.detection.sync import clone_mismatch, git_command, sync_corpus

ORIGIN_A = "https://example.invalid/a.git"
REMOTE_B = "https://example.invalid/b.git"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch):
    monkeypatch.setattr(web_capture, "_resolve_all", lambda host: ["93.184.216.34"])


def _git(cwd: Path, *args: str) -> str:
    """A plain git call to build the fixtures (not the code under test)."""
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True,
                          text=True).stdout


def _clone_of(tmp_path: Path, origin: str) -> Path:
    """A repository whose `origin` is `origin`: a folder that git recognises as a clone."""
    repo = tmp_path / "clone"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", origin)
    return repo


def _record_git(monkeypatch) -> list[list[str]]:
    """Record every git command the code runs; the real one still runs, so the queries
    answer for real, but no `pull` or `clone` is ever allowed to reach the network."""
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spy(cmd, **kwargs):
        calls.append(list(cmd))
        if "pull" in cmd or "clone" in cmd:
            raise AssertionError(f"a fetch must not run here: {cmd}")
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(sync_mod.subprocess, "run", spy)
    return calls


def test_a_clone_of_another_remote_is_refused_before_any_pull_issue_367(tmp_path, monkeypatch):
    """The reproduction: the folder is the clone of A, the corpus now says B. The
    refusal names both remotes, and git never runs a pull (it would contact A)."""
    path = _clone_of(tmp_path, ORIGIN_A)
    corpus = {"name": "b", "path": str(path), "git": REMOTE_B}
    calls = _record_git(monkeypatch)

    message = clone_mismatch(corpus)

    assert message == (f"{path} is a clone of {ORIGIN_A} but the corpus is configured for {REMOTE_B} "
                       "— remove the folder to clone the new remote")
    assert not any("pull" in cmd for cmd in calls)

    assert sync_corpus(corpus) == (False, message)
    assert not any("pull" in cmd or "clone" in cmd for cmd in calls)


def test_the_remote_is_compared_without_its_credentials_issue_367(tmp_path):
    """A token in the origin of an old clone must not reach the message."""
    path = _clone_of(tmp_path, "https://user:s3cr3t@example.invalid/a.git")
    message = clone_mismatch({"name": "b", "path": str(path), "git": REMOTE_B})

    assert message is not None
    assert "s3cr3t" not in message
    assert "https://example.invalid/a.git" in message


def test_a_plain_folder_inside_another_checkout_is_not_a_clone_issue_367(tmp_path):
    """`git -C folder pull` would act on the parent checkout: the folder is refused
    even though the parent's origin matches the configured remote."""
    parent = _clone_of(tmp_path, ORIGIN_A)
    folder = parent / "corpus"
    folder.mkdir()
    corpus = {"name": "a", "path": str(folder), "git": ORIGIN_A}

    message = clone_mismatch(corpus)

    assert message is not None and "is not a git clone of its own" in message
    assert message.endswith("— remove it or choose another path, then Redownload")
    assert sync_corpus(corpus) == (False, message)


def test_an_extracted_archive_is_not_a_clone_issue_367(tmp_path):
    """A tarball corpus left behind (no .git): the pull used to fail obscurely."""
    folder = tmp_path / "et"
    folder.mkdir()
    (folder / ".sync.json").write_text("{}", encoding="utf-8")

    message = clone_mismatch({"name": "et", "path": str(folder), "git": ORIGIN_A})

    assert message is not None and "is not a git clone of its own" in message


@pytest.mark.parametrize("configured", [
    "https://example.invalid/a.git",
    "https://example.invalid/a",             # without .git
    "https://example.invalid/a.git/",        # trailing slash
    "https://EXAMPLE.invalid/a.git",         # host in capitals
])
def test_the_same_remote_in_another_spelling_is_allowed_issue_367(tmp_path, configured):
    """Control: the clone's origin is the configured remote. No refusal, and the pull
    is the command git_command returns."""
    path = _clone_of(tmp_path, ORIGIN_A)
    corpus = {"name": "a", "path": str(path), "git": configured}

    assert clone_mismatch(corpus) is None
    assert git_command(corpus)[-4:] == ["-C", str(path), "pull", "--ff-only"]


def test_a_missing_path_is_cloned_not_checked_issue_367(tmp_path, monkeypatch):
    """Control: nothing exists yet, so there is no clone to compare; git runs nothing here."""
    calls = _record_git(monkeypatch)
    corpus = {"name": "b", "path": str(tmp_path / "new"), "git": REMOTE_B}

    assert clone_mismatch(corpus) is None
    assert calls == []
    assert git_command(corpus)[-5:] == ["clone", "--depth", "1", REMOTE_B, str(tmp_path / "new")]


def test_a_tarball_corpus_has_no_clone_to_check_issue_367(tmp_path):
    folder = tmp_path / "et"
    folder.mkdir()
    assert clone_mismatch({"name": "et", "path": str(folder), "tarball": "https://h/e.tgz"}) is None


def test_a_clone_without_origin_is_refused_issue_367(tmp_path):
    repo = tmp_path / "bare"
    repo.mkdir()
    _git(repo, "init", "-q")

    message = clone_mismatch({"name": "b", "path": str(repo), "git": REMOTE_B})

    assert message is not None and "no origin remote" in message


def test_the_api_answers_409_and_never_fetches_issue_367(temp_db, temp_db_client, tmp_path, monkeypatch):
    path = _clone_of(tmp_path, ORIGIN_A)
    cfg = tmp_path / "detection_corpora.yaml"
    cfg.write_text(f"corpora:\n  - name: b\n    git: {REMOTE_B}\n    path: {path.as_posix()}\n",
                   encoding="utf-8")
    monkeypatch.setattr(settings_mod, "_CONFIG", cfg)
    monkeypatch.setattr(settings_mod, "sync_corpus", lambda c: pytest.fail("must not fetch"))

    r = temp_db_client.post("/api/settings/corpora/b/sync")

    assert r.status_code == 409
    assert ORIGIN_A in r.json()["detail"] and REMOTE_B in r.json()["detail"]
