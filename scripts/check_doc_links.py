"""Relative links in the Markdown documentation resolve.

`make check-docs` runs this next to scripts/check_doc_claims.py, and CI runs
it in the fast-tests job.  It reads every Markdown file the repository tracks
(`git ls-files`; when git cannot list the files, every file under the root
except the directories in SKIP_DIRS) and checks each relative link
`[text](target)`, `![alt](target)` and `[text](target#anchor)`:

- the target must be a tracked file, or a directory that holds tracked files;
- an anchor must match a heading of the target file, using GitHub's slug
  rules (lower case, punctuation dropped, spaces to hyphens, a repeated
  heading gets `-1`, `-2`, ...), or an `<a id=...>` / `<a name=...>` tag;
- a target under `data/` is local data that is not in the repository. It is
  reported, except from the files in LOCAL_DATA_ALLOWED.

Links inside fenced code blocks and inline code are not links and are ignored.
Scheme links (`https:`, `mailto:`) are not checked.

Usage:
    python scripts/check_doc_links.py            # the repository this file is in
    python scripts/check_doc_links.py <root>     # another tree (tests use this)

Exit codes:
    0  every relative link resolves
    1  at least one link is broken; one line per link, `file:line: [target] reason`
"""
from __future__ import annotations

import os
import posixpath
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent

# Files whose links into data/ are accepted. data/ holds the local AnnoCTR
# clone, which is not in the repository. docs/gazetteer-ordinary-words.md
# links 86 files there; the whole file is hashed as the gazetteer policy
# version, so its links cannot be edited without changing that version.
LOCAL_DATA_ALLOWED = {
    "docs/gazetteer-ordinary-words.md",
}

# Directories the fallback walk does not enter. Git's own listing never
# reaches them: they are untracked or ignored. `data` is skipped only at the
# root (the local corpora); pipeline/data/ is tracked and is walked.
SKIP_DIRS = {".git", ".venv", "node_modules", ".secrets", "__pycache__"}
#: Markdown kept as test data, not documentation: copies of the repository's files as they
#: stood at a recorded date (tests/fixtures/release_dossier/repo/SECURITY.md), whose relative
#: links point at files beside the original, not beside the copy.
DATA_PREFIXES = ("tests/fixtures/",)
ROOT_ONLY_SKIP_DIRS = {"data"}

FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(`+).+?\1")
LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]*)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
HEADING_RE = re.compile(r"^ {0,3}#{1,6}[ \t]+(.*?)(?:[ \t]+#+)?[ \t]*$")
ANCHOR_TAG_RE = re.compile(r"""<a\s[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
MARKDOWN_LINK_IN_HEADING_RE = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")


def slugify(heading: str) -> str:
    """The anchor GitHub gives a heading, before the duplicate numbering."""
    text = heading.replace("`", "")
    text = MARKDOWN_LINK_IN_HEADING_RE.sub(r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text.strip().lower())
    return text.replace(" ", "-")


def anchors_of(text: str) -> set[str]:
    """Every anchor a Markdown file offers: its headings and its HTML anchor tags."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    fence = ""
    for line in text.splitlines():
        match = FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            if not fence:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and set(line.strip()) == {fence[0]}:
                fence = ""
            continue
        if fence:
            continue
        heading = HEADING_RE.match(line)
        if heading:
            base = slugify(heading.group(1))
            count = seen.get(base, 0)
            anchors.add(base if count == 0 else f"{base}-{count}")
            seen[base] = count + 1
        anchors.update(ANCHOR_TAG_RE.findall(line))
    return anchors


def tracked_files(root: Path) -> set[str]:
    """Repository-relative POSIX paths of the files Git tracks, or of every file
    under `root` outside SKIP_DIRS when `root` is not a Git checkout or git fails."""
    if (root / ".git").exists():
        try:
            listed = subprocess.run(
                ["git", "-C", str(root), "ls-files", "-z"],
                capture_output=True, check=True, encoding="utf-8",
            )
            return {name for name in listed.stdout.split("\0") if name}
        except (OSError, subprocess.CalledProcessError):
            pass
    print("git cannot list the tracked files here: checking every file under the root", file=sys.stderr)
    files: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        at_root = Path(dirpath) == root
        dirnames[:] = [
            name for name in dirnames
            if name not in SKIP_DIRS and not (at_root and name in ROOT_ONLY_SKIP_DIRS)
        ]
        for name in filenames:
            files.add(Path(dirpath, name).relative_to(root).as_posix())
    return files


def _outside_code(text: str):
    """Yield (line number, line) for each line outside fenced code, with inline code blanked."""
    fence = ""
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            if not fence:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence) and set(line.strip()) == {fence[0]}:
                fence = ""
            continue
        if not fence:
            yield number, INLINE_CODE_RE.sub("", line)


def _destination(source: str, path_part: str) -> str:
    """The repository-relative path a link names, normalised; '..' is kept when it leaves the tree."""
    if path_part.startswith("/"):
        joined = path_part.lstrip("/")
    else:
        joined = posixpath.join(posixpath.dirname(source), path_part)
    return posixpath.normpath(joined)


def check_text(source: str, text: str, tracked: set[str], root: Path,
               cache: dict[str, set[str]] | None = None) -> tuple[int, list[tuple[int, str, str]]]:
    """Check the links of one Markdown file.

    Returns the number of relative links seen and the problems as
    (line number, target, reason) tuples.
    """
    if cache is None:
        cache = {}
    links = 0
    problems: list[tuple[int, str, str]] = []

    def anchors(path: str) -> set[str]:
        if path not in cache:
            body = text if path == source else (root / path).read_text(encoding="utf-8", errors="replace")
            cache[path] = anchors_of(body)
        return cache[path]

    for number, line in _outside_code(text):
        for match in LINK_RE.finditer(line):
            target = match.group(1)
            if not target or SCHEME_RE.match(target):
                continue
            links += 1
            path_part, has_anchor, anchor = target.partition("#")
            path_part = unquote(path_part)
            anchor = unquote(anchor)
            if not path_part:
                dest = source
            else:
                dest = _destination(source, path_part)
            if dest == ".." or dest.startswith("../"):
                problems.append((number, target, "points outside the repository"))
                continue
            if dest == "data" or dest.startswith("data/"):
                if source in LOCAL_DATA_ALLOWED:
                    continue
                if dest not in tracked:
                    problems.append((number, target, "local data, not in the repository"))
                    continue
            if dest not in tracked:
                if not any(name.startswith(dest + "/") for name in tracked):
                    problems.append((number, target, "no such tracked file"))
                    continue
                continue
            if has_anchor and anchor and dest.endswith(".md"):
                if anchor not in anchors(dest):
                    problems.append((number, target, f"no heading or anchor '#{anchor}' in {dest}"))
    return links, problems


def main(argv: list[str] | None = None) -> int:
    """Check every tracked Markdown file under the root (argv[0], or this repository)."""
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]).resolve() if args else ROOT
    tracked = tracked_files(root)
    cache: dict[str, set[str]] = {}
    files = 0
    links = 0
    broken: list[str] = []
    for name in sorted(tracked):
        if not name.endswith(".md") or name.startswith(DATA_PREFIXES) or not (root / name).is_file():
            continue
        files += 1
        text = (root / name).read_text(encoding="utf-8", errors="replace")
        count, problems = check_text(name, text, tracked, root, cache)
        links += count
        for number, target, reason in problems:
            broken.append(f"{name}:{number}: [{target}] {reason}")
    for line in broken:
        print(line)
    if broken:
        print(f"{len(broken)} broken link(s) in {files} Markdown files ({links} relative links checked)")
        return 1
    print(f"all {links} relative links in {files} Markdown files resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
