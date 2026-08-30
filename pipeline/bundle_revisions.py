# pipeline/bundle_revisions.py
import json
import sqlite3
import subprocess
from pathlib import Path

#: Revisions after which Stage 4/5 can emit different objects for the same input.
#:
#: A bundle whose recorded `git_rev` is an ANCESTOR of one of these entries was
#: built by a pipeline that lacked the fix, and is stale with respect to it.
#:
#: Append one entry per output-affecting fix (CONTRIBUTING.md carries the rule).
#: Do NOT add commits that only touch the frontend, tests, docs or tooling:
#: comparing against HEAD instead was rejected in ADR-0035 precisely because it
#: marks every commit as invalidating and so never returns to green.
BUNDLE_AFFECTING: tuple[tuple[str, str, str], ...] = (
    ("eaee534", "2026-08-28",
     "Stage 4 no longer emits a relationship whose endpoints resolve to the same object"),
)


def git_rev_of(run_config_json: str | None) -> str | None:
    """Extract git_rev from a run_config_json string, returning None on any failure."""
    if run_config_json is None or run_config_json == "":
        return None
    try:
        data = json.loads(run_config_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    rev = data.get("git_rev")
    if isinstance(rev, str) and rev.strip():
        # Stripped: a padded rev reaches `git merge-base` as an unknown object,
        # which returns "undecidable" rather than the true answer we have.
        return rev.strip()
    return None


def is_ancestor(rev: str, descendant: str, repo_root: Path | None = None) -> bool | None:
    """Check if rev is an ancestor of descendant using git merge-base."""
    cwd = repo_root or Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", rev, descendant],
            cwd=cwd,
            timeout=10,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True
        elif result.returncode == 1:
            return False
        else:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def stale_entries(rev: str | None, repo_root: Path | None = None) -> list[tuple[str, str, str]]:
    """Return list of BUNDLE_AFFECTING entries for which rev is an ancestor."""
    if rev is None:
        return []
    stale = []
    for entry in BUNDLE_AFFECTING:
        entry_sha = entry[0]
        if is_ancestor(rev, entry_sha, repo_root) is True:
            stale.append(entry)
    return stale


def audit_staleness(conn: sqlite3.Connection, repo_root: Path | None = None) -> list[dict]:
    """Audit all jobs for bundle staleness, returning a list of status dicts."""
    cursor = conn.execute("SELECT id, run_config_json FROM jobs ORDER BY id")
    results = []
    for row in cursor:
        job_id = row[0]
        run_config_json = row[1]
        git_rev = git_rev_of(run_config_json)
        stale = stale_entries(git_rev, repo_root)
        unknown = git_rev is None
        results.append({
            "job_id": job_id,
            "git_rev": git_rev,
            "stale": stale,
            "unknown": unknown
        })
    return results
