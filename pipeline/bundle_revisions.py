# pipeline/bundle_revisions.py
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # the job-store connection type (ADR-0045); annotation only
    from api.db_backend import DBConnection

#: Revisions after which Stage 4/5 can emit different objects for the same input.
#:
#: A bundle built at a revision that is an ANCESTOR of one of these entries was
#: built by a pipeline that lacked the fix, and is stale with respect to it.
#:
#: Append one entry per output-affecting fix (CONTRIBUTING.md carries the rule).
#: Do NOT add commits that only touch the frontend, tests, docs or tooling:
#: comparing against HEAD instead was rejected in ADR-0035 precisely because it
#: marks every commit as invalidating and so never returns to green.
#:
#: The fourth field is the fix's scope, which decides whose revision is judged
#: (ADR-0086).  "mapping": the fix changes Stages 4/5 only, so a finalize at a
#: revision that has it rebuilds the bundle with it; the revision that built
#: the stored bundle counts, not the run's.  "extraction": the fix changes
#: Stages 1-3, maybe 4 too; a finalize rereads the rows a run wrote and cannot
#: add what the run never extracted, so both the run's revision and the
#: build's must have it, and only a new run clears it.  When in doubt, pick
#: "extraction": it never claims a rebuild fixed what it cannot.
BUNDLE_AFFECTING: tuple[tuple[str, str, str, str], ...] = (
    ("eaee534", "2026-08-28",
     "Stage 4 no longer emits a relationship whose endpoints resolve to the same object",
     "mapping"),
    ("3a25f45", "2026-09-29",
     "Relationship dates keep their precision: month/year dates move from start_time/stop_time "
     "to x_temporal_assertions (ADR-0063)",
     "extraction"),
    ("51539c2", "2026-10-18",
     "A CyNER threat actor written as ordinary language is dropped, and a spaCy location must be "
     "able to be a place name: \"the United States\" now ships as United States (ADR-0088)",
     "extraction"),
    ("f64452d", "2026-10-18",
     "Under RE2 a no-break or thin space is whitespace too: ASNs, spaced defangs, Windows paths, alias "
     "lists, list items, Stage 3f quotes, YARA imports and Sigma rule boundaries next to one (ADR-0049)",
     "extraction"),
    ("8c61bd9", "2026-10-18",
     "RE2 and re read \\d, \\w and \\b alike: no address, ASN, Windows path or port cut out of a word "
     "(o@evil.com out of joão@evil.com); alias names, version filters and YARA rule names read every "
     "script (ADR-0049)",
     "extraction"),
    ("b4ed740", "2026-10-20",
     "A Stage 3f selection answer cut off at the output-token limit keeps its complete, checked "
     "choices instead of sending every candidate of the chunk to review (ADR-0072)",
     "extraction"),
    ("0177c07", "2026-10-24",
     "A quoted YARA rule with an include directive is refused without the server reading the file; "
     "it used to compile when the file existed",
     "mapping"),
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


_SHA = re.compile(r"[0-9a-f]{7,40}")


def is_ancestor(rev: str, descendant: str, repo_root: Path | None = None) -> bool | None:
    """Check if rev is an ancestor of descendant using git merge-base.

    Both must be commit ids: a stored revision is data, and one starting with
    `-` would reach git as an option.  Anything else is "unknown" (None).
    """
    if not (_SHA.fullmatch(rev or "") and _SHA.fullmatch(descendant or "")):
        return None
    cwd = repo_root or Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(  # noqa: S603 — two commit ids checked above
            ["git", "merge-base", "--is-ancestor", rev, descendant],  # noqa: S607 — git from PATH
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


def resolve_commit(sha: str, repo_root: Path | None = None) -> str | None:
    """The full id of the commit `sha` names, or None when git cannot say.

    Same guard as `is_ancestor`: `sha` must be a commit id.  A short and a long
    id of one commit resolve to the same string.
    """
    if not _SHA.fullmatch(sha or ""):
        return None
    cwd = repo_root or Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(  # noqa: S603 — a commit id checked above
            ["git", "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"],  # noqa: S607 — git from PATH
            cwd=cwd,
            timeout=10,
            capture_output=True,
            text=True
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _predates(rev: str | None, entry_sha: str, repo_root: Path | None) -> bool:
    """Is `rev` a strict ancestor of the entry's commit?

    A strict ancestor: `git merge-base --is-ancestor X X` succeeds, but a bundle
    built at the entry's own commit already has its fix.  When either id cannot
    be resolved, the ancestor verdict stands.  A None revision judges nothing.
    """
    if rev is None or is_ancestor(rev, entry_sha, repo_root) is not True:
        return False
    resolved = resolve_commit(rev, repo_root)
    return resolved is None or resolved != resolve_commit(entry_sha, repo_root)


def stale_entries(rev: str | None, repo_root: Path | None = None, *,
                  build_rev: str | None = None) -> list[tuple[str, str, str, str]]:
    """Return the BUNDLE_AFFECTING entries the stored bundle lacks.

    `rev` is the run's revision, `build_rev` the revision that built the stored
    bundle (None: the run's own).  A "mapping" entry is judged on `build_rev`
    only; an "extraction" entry on both (stale when either predates it).
    """
    built = rev if build_rev is None else build_rev
    stale = []
    for entry in BUNDLE_AFFECTING:
        entry_sha, scope = entry[0], entry[3]
        judged = (built,) if scope == "mapping" else (rev, built)
        if any(_predates(r, entry_sha, repo_root) for r in dict.fromkeys(judged)):
            stale.append(entry)
    return stale


def audit_staleness(conn: DBConnection, repo_root: Path | None = None) -> list[dict]:
    """Audit all jobs for bundle staleness, returning a list of status dicts.

    `git_rev` is the run's revision, `build_rev` the revision that built the
    stored bundle (None when no build record was stored); `unknown` is True
    only when neither is known."""
    cursor = conn.execute("SELECT id, run_config_json, bundle_build_json FROM jobs ORDER BY id")
    results = []
    for row in cursor:
        job_id = row[0]
        git_rev = git_rev_of(row[1])
        build_rev = git_rev_of(row[2])
        stale = stale_entries(git_rev, repo_root, build_rev=build_rev)
        unknown = git_rev is None and build_rev is None
        results.append({
            "job_id": job_id,
            "git_rev": git_rev,
            "build_rev": build_rev,
            "stale": stale,
            "unknown": unknown
        })
    return results
