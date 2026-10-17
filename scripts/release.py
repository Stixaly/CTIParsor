#!/usr/bin/env python3
"""Release process: the one version, the changelog, the release notes.

``pipeline.__version__`` is CTIParsor's version; the frontend's package.json
and package-lock.json carry the same number, and a release is the tag ``vX.Y.Z``
(docs/releasing.md).  This script reads those files as text and imports nothing
but the standard library: the release workflow runs it on the runner's own
Python, before anything is installed.

Usage:
    python scripts/release.py [--root DIR] version [--next {major,minor,patch}]
    python scripts/release.py [--root DIR] check TAG
    python scripts/release.py [--root DIR] notes VERSION [--image REF] [--repo OWNER/NAME] [--max-chars N]
    python scripts/release.py [--root DIR] unreleased
    python scripts/release.py [--root DIR] prepare VERSION [--date YYYY-MM-DD]
    python scripts/release.py predicate VERIFY_JSON --type URI

Exit codes:
    0  done; the result is on stdout
    1  refused or failed; the reasons are on stderr, nothing was written
    2  usage error
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "Stixaly/CTIParsor"
#: GitHub refuses a release body above 125 000 characters; the rest is margin
#: for the annex and for how the limit is counted.
DEFAULT_MAX_CHARS = 100_000

VERSION_FILE = "pipeline/__init__.py"
CHANGELOG_FILE = "CHANGELOG.md"
#: The frontend files that carry the version, and the key paths holding it.
_JSON_VERSIONS: dict[str, tuple[tuple[str, ...], ...]] = {
    "frontend/package.json": (("version",),),
    "frontend/package-lock.json": (("version",), ("packages", "", "version")),
}

_SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
_VERSION_LINE = re.compile(r'^__version__ = "(\d+\.\d+\.\d+)"$', re.MULTILINE | re.ASCII)
#: ``## [X.Y.Z] - date`` and ``## [Unreleased]``: the version (or word) and the date.
_HEADING = re.compile(r"## \[([^\]]*)\](?: - (.*))?")
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
#: ``name@sha256:<hex>``, the form `gh attestation verify oci://` takes.
_IMAGE_REF = re.compile(r"[^@\s]+@sha256:[0-9a-f]+")

_IMAGE_ANNEX = (
    "## Container image\n\n"
    "`{name}:{version}` is the image main's CI built and tested from this commit, "
    "given the version as a second name; nothing was rebuilt.\n\n"
    "```\n"
    "docker pull {ref}\n"
    "gh attestation verify oci://{ref} -R {repo} "
    "--signer-workflow {repo}/.github/workflows/ci.yml --source-ref refs/heads/main\n"
    "```\n\n"
    "## Files\n\n"
    "`SHA256SUMS` lists the source archive and the image's SBOM. "
    "`ctiparsor-{version}.intoto.jsonl` is their SLSA build provenance, "
    "signed by the workflow run that published it. "
    "`ctiparsor-{version}-image.cdx.json` is the image's SBOM, "
    "as attested when main's CI built it.\n\n"
    "```\n"
    "sha256sum -c SHA256SUMS\n"
    "gh attestation verify ctiparsor-{version}.tar.gz -R {repo} "
    "--signer-workflow {repo}/.github/workflows/release.yml --source-ref refs/tags/v{version}\n"
    "```"
)

_SUMMARY_INTRO = (
    "The notes for {version} are longer than a GitHub release allows. Every change is described in "
    "[CHANGELOG.md](https://github.com/{repo}/blob/v{version}/CHANGELOG.md); its entries:"
)


class ReleaseError(Exception):
    """A refusal, with the reason a human reads on stderr."""


# --- Files ------------------------------------------------------------------

def _read(root: Path, rel: str) -> str:
    try:
        return (root / rel).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseError(f"{rel}: cannot read it: {exc}") from exc


def _write(root: Path, rel: str, text: str) -> None:
    # Bytes, not write_text: no newline translation on any platform.
    (root / rel).write_bytes(text.encode("utf-8"))


def _load_json(root: Path, rel: str) -> Any:
    try:
        return json.loads(_read(root, rel))
    except json.JSONDecodeError as exc:
        raise ReleaseError(f"{rel}: not valid JSON: {exc}") from exc


def _dump_json(data: Any) -> str:
    """The format npm writes, so that setting a version reformats nothing."""
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _key_label(keys: tuple[str, ...]) -> str:
    return ".".join(key or '""' for key in keys)


def _json_get(data: Any, keys: tuple[str, ...], rel: str) -> str:
    node = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            raise ReleaseError(f"{rel}: no {_key_label(keys)}")
        node = node[key]
    if not isinstance(node, str):
        raise ReleaseError(f"{rel}: {_key_label(keys)} is not a string")
    return node


# --- Versions ---------------------------------------------------------------

def read_version(root: Path) -> str:
    """``__version__`` of ``pipeline/__init__.py``."""
    match = _VERSION_LINE.search(_read(root, VERSION_FILE))
    if match is None or not _SEMVER.fullmatch(match.group(1)):
        raise ReleaseError(f'{VERSION_FILE}: no `__version__ = "X.Y.Z"` line (SemVer)')
    return match.group(1)


def _json_version(root: Path, rel: str, keys: tuple[str, ...]) -> str:
    return _json_get(_load_json(root, rel), keys, rel)


def _json_set(data: Any, keys: tuple[str, ...], value: str, rel: str) -> None:
    _json_get(data, keys, rel)  # the key exists: setting it adds none
    node = data
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = value


def _sources(root: Path) -> dict[str, Callable[[], str]]:
    """Every place that states the version, by label."""
    sources: dict[str, Callable[[], str]] = {f"{VERSION_FILE} __version__": partial(read_version, root)}
    for rel, paths in _JSON_VERSIONS.items():
        for keys in paths:
            sources[f"{rel} {_key_label(keys)}"] = partial(_json_version, root, rel, keys)
    return sources


def declared_versions(root: Path) -> dict[str, str]:
    """The version each place states, by label; they are equal in a consistent tree."""
    return {label: read() for label, read in _sources(root).items()}


def _key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def next_version(current: str, level: str) -> str:
    """``current`` raised at ``level`` (major, minor or patch); the lower parts go to 0."""
    major, minor, patch = _key(current)
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    if level == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError(f"unknown level {level!r}: expected major, minor or patch")


def _iso_date(text: str) -> datetime.date | None:
    if not _ISO_DATE.fullmatch(text):
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


# --- Changelog --------------------------------------------------------------

@dataclass(frozen=True)
class Section:
    """A ``## `` section of the changelog."""
    title: str  # the heading line, "## [0.1.0] - 2026-10-17"
    line: int  # its index among the file's lines
    body: str  # up to the next heading (the last section: the footer), blank edges removed


def _in_code(lines: list[str]) -> list[bool]:
    """Per line: is it a code fence, or inside a fenced block?  A heading there is text.

    A block opens with ``` or ~~~ and closes with the same one; the other is text inside it.
    """
    flags = []
    fence: str | None = None  # what opened the block we are in
    for line in lines:
        mark = line.lstrip()[:3]
        is_fence = mark in ("```", "~~~") and (fence is None or mark == fence)
        flags.append(fence is not None or is_fence)
        if is_fence:
            fence = None if fence else mark
    return flags


def _parse_changelog(text: str) -> list[Section]:
    """The ``## `` sections.  The footer is the last "---" outside code after the last heading:
    the last section stops there and nothing after it is a note.  Any other "---" is text.
    """
    lines = [line.rstrip("\r") for line in text.split("\n")]
    code = _in_code(lines)
    starts = [i for i, line in enumerate(lines) if not code[i] and line.startswith("## ")]
    if not starts:
        return []
    footer = next((i for i in range(len(lines) - 1, starts[-1], -1) if not code[i] and lines[i] == "---"),
                  len(lines))
    sections = []
    for start, end in zip(starts, [*starts[1:], footer], strict=True):
        body = lines[start + 1:end]
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        sections.append(Section(lines[start], start, "\n".join(body)))
    return sections


def changelog_sections(root: Path) -> list[Section]:
    """The ``## `` sections of CHANGELOG.md, in file order."""
    return _parse_changelog(_read(root, CHANGELOG_FILE))


def _version_section(sections: list[Section], version: str) -> Section | None:
    for section in sections:
        match = _HEADING.fullmatch(section.title)
        if match and match.group(1) == version:
            return section
    return None


def _unreleased(sections: list[Section]) -> Section:
    section = next((s for s in sections if s.title == "## [Unreleased]"), None)
    if section is None:
        raise ReleaseError(f"{CHANGELOG_FILE} has no '## [Unreleased]' section")
    return section


def unreleased_body(root: Path) -> str:
    """What ``## [Unreleased]`` holds, which is what the next release would ship; empty if nothing."""
    return _unreleased(changelog_sections(root)).body


def _summary(body: str, version: str, repo: str) -> str:
    """For a body too long to ship: the text that opens it, then its entries (``####`` titles) by ``###`` group.

    The opening text is the summary a maintainer writes above the first heading (docs/releasing.md).
    A group the changelog names twice ("### Added" recurs between older entries) is listed once, where
    it first appears; a group with no ``####`` entry (older entries are plain bullets) is left out.
    """
    lines = body.split("\n")
    code = _in_code(lines)
    first = next((i for i, line in enumerate(lines) if not code[i] and line.startswith("###")), len(lines))
    groups: dict[str | None, list[str]] = {}  # heading -> bullets; entries before any group have no heading
    heading: str | None = None
    for i in range(first, len(lines)):
        if code[i]:
            continue
        if lines[i].startswith("### "):
            heading = lines[i]
        elif lines[i].startswith("#### "):
            groups.setdefault(heading, []).append(f"- {lines[i][5:]}")
    opening = "\n".join(lines[:first]).strip()
    blocks = [part for part in (opening, _SUMMARY_INTRO.format(version=version, repo=repo)) if part]
    blocks += ["\n\n".join(part for part in (heading, "\n".join(bullets)) if part)
               for heading, bullets in groups.items()]
    return "\n\n".join(blocks)


def _image_annex(image: str, version: str, repo: str) -> str:
    if not _IMAGE_REF.fullmatch(image):
        raise ReleaseError(f"{image!r} is not an image reference with a digest (name@sha256:<hex>)")
    return _IMAGE_ANNEX.format(name=image.partition("@")[0], ref=image, version=version, repo=repo)


def release_notes(root: Path, version: str, image: str | None = None, repo: str = DEFAULT_REPO,
                  max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """The notes of release ``version``: its changelog section, then the image annex if ``image`` is given.

    Past ``max_chars`` the section is replaced by the list of its entries; the annex stays.
    """
    if not _SEMVER.fullmatch(version):
        raise ReleaseError(f"{version!r} is not a version X.Y.Z (no prefix, no pre-release)")
    section = _version_section(changelog_sections(root), version)
    if section is None:
        raise ReleaseError(f"{CHANGELOG_FILE} has no '## [{version}] - YYYY-MM-DD' section")
    annex = _image_annex(image, version, repo) if image else ""

    def assemble(body: str) -> str:
        return "\n\n".join(part for part in (body, annex) if part) + "\n"

    text = assemble(section.body)
    if len(text) > max_chars:
        text = assemble(_summary(section.body, version, repo))
        if len(text) > max_chars:
            raise ReleaseError(f"the notes of {version} are {len(text)} characters even as a list of entries; "
                               f"the limit is {max_chars}")
    return text


def _changelog_problems(root: Path, version: str) -> list[str]:
    try:
        section = _version_section(changelog_sections(root), version)
    except ReleaseError as exc:
        return [str(exc)]
    if section is None:
        return [f"{CHANGELOG_FILE} has no '## [{version}] - YYYY-MM-DD' section"]
    problems = []
    match = _HEADING.fullmatch(section.title)
    date = match.group(2) if match else None
    if date is None or _iso_date(date) is None:
        problems.append(f"{CHANGELOG_FILE}: {section.title!r} has no valid date "
                        f"(expected '## [{version}] - YYYY-MM-DD')")
    if not section.body:
        problems.append(f"{CHANGELOG_FILE}: the section {section.title!r} is empty")
    return problems


# --- Commands ---------------------------------------------------------------

def check(root: Path, tag: str) -> list[str]:
    """Every reason the tree cannot be released as ``tag``; empty when it can."""
    if not tag.startswith("v") or not _SEMVER.fullmatch(tag[1:]):
        return [f"{tag!r} is not a release tag: expected vX.Y.Z (SemVer, no pre-release)"]
    version = tag[1:]
    problems = []
    for label, read in _sources(root).items():
        try:
            found = read()
        except ReleaseError as exc:
            problems.append(str(exc))
            continue
        if found != version:
            problems.append(f"{label} is {found}, the tag says {version}")
    return problems + _changelog_problems(root, version)


def prepare(root: Path, version: str, date: datetime.date) -> list[str]:
    """Release ``version``: its entries leave ``[Unreleased]`` and every version is set.

    Returns the files written, relative to ``root``.  Everything is read and checked first;
    a refusal leaves the tree as it was.
    """
    if not _SEMVER.fullmatch(version):
        raise ReleaseError(f"{version!r} is not a version X.Y.Z (no prefix, no pre-release)")
    current = read_version(root)
    if _key(version) <= _key(current):
        raise ReleaseError(f"{version} is not above the current version {current}")
    changelog = _read(root, CHANGELOG_FILE)
    sections = _parse_changelog(changelog)
    unreleased = _unreleased(sections)
    if not unreleased.body:
        raise ReleaseError(f"the [Unreleased] section of {CHANGELOG_FILE} is empty: nothing to release")
    if _version_section(sections, version) is not None:
        raise ReleaseError(f"{CHANGELOG_FILE} already has a '## [{version}]' section")

    lines = changelog.split("\n")
    lines[unreleased.line] = f"## [Unreleased]\n\n## [{version}] - {date.isoformat()}"
    written = {
        CHANGELOG_FILE: "\n".join(lines),
        VERSION_FILE: _VERSION_LINE.sub(f'__version__ = "{version}"', _read(root, VERSION_FILE), count=1),
    }
    for rel, paths in _JSON_VERSIONS.items():
        data = _load_json(root, rel)
        for keys in paths:
            _json_set(data, keys, version, rel)
        written[rel] = _dump_json(data)
    for rel, text in written.items():
        _write(root, rel, text)
    return list(written)


def predicate(verify_json: Path, predicate_type: str) -> str:
    """The predicate of the first attestation of ``predicate_type`` in `gh attestation verify --format json`."""
    try:
        entries = json.loads(verify_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{verify_json}: not a JSON file: {exc}") from exc
    for entry in entries if isinstance(entries, list) else []:
        result = entry.get("verificationResult") if isinstance(entry, dict) else None
        statement = result.get("statement") if isinstance(result, dict) else None
        if (isinstance(statement, dict) and statement.get("predicateType") == predicate_type
                and "predicate" in statement):
            return json.dumps(statement["predicate"], ensure_ascii=False) + "\n"
    raise ReleaseError(f"{verify_json}: no attestation with predicate type {predicate_type}")


# --- Command line -----------------------------------------------------------

def _cmd_version(args: argparse.Namespace) -> int:
    current = read_version(args.root)
    print(next_version(current, args.next) if args.next else current)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    problems = check(args.root, args.tag)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(args.tag[1:])
    return 0


def _cmd_notes(args: argparse.Namespace) -> int:
    print(release_notes(args.root, args.version, args.image, args.repo, args.max_chars), end="")
    return 0


def _cmd_unreleased(args: argparse.Namespace) -> int:
    body = unreleased_body(args.root)
    if body:
        print(body)
    return 0


def _cmd_prepare(args: argparse.Namespace) -> int:
    for rel in prepare(args.root, args.version, args.date or datetime.date.today()):
        print(rel)
    return 0


def _cmd_predicate(args: argparse.Namespace) -> int:
    print(predicate(args.verify_json, args.type), end="")
    return 0


def _date(text: str) -> datetime.date:
    date = _iso_date(text)
    if date is None:
        raise argparse.ArgumentTypeError(f"{text!r} is not a date YYYY-MM-DD")
    return date


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    parser.add_argument("--root", type=Path, default=ROOT, help="the repository root (default: this checkout)")
    commands = parser.add_subparsers(dest="command", required=True)

    cmd = commands.add_parser("version", help="print the current version, or the next one")
    cmd.add_argument("--next", choices=("major", "minor", "patch"), help="print the version after this bump")
    cmd.set_defaults(run=_cmd_version)

    cmd = commands.add_parser("check", help="check that the tree can be released as TAG; print X.Y.Z if so",
                              description="Every discrepancy is reported on stderr, one line each (exit 1).")
    cmd.add_argument("tag", help="vX.Y.Z")
    cmd.set_defaults(run=_cmd_check)

    cmd = commands.add_parser("notes", help="print the release notes of VERSION")
    cmd.add_argument("version", help="X.Y.Z")
    cmd.add_argument("--image", help="ghcr.io/OWNER/NAME@sha256:<hex>: append the container image and files annex")
    cmd.add_argument("--repo", default=DEFAULT_REPO, help="OWNER/NAME of the GitHub repository (default: %(default)s)")
    cmd.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS,
                     help="past this many characters the changelog section becomes a list of its entries "
                          "(default: %(default)s)")
    cmd.set_defaults(run=_cmd_notes)

    cmd = commands.add_parser("unreleased", help="print what [Unreleased] holds (what the next release would ship)",
                              description="Prints nothing, and exits 0, when [Unreleased] is empty; "
                                          "exits 1 if the changelog has no [Unreleased] section.")
    cmd.set_defaults(run=_cmd_unreleased)

    cmd = commands.add_parser("prepare", help="release VERSION: move [Unreleased] under it and set every version",
                              description="Refuses, and writes nothing, if VERSION is not above the current version, "
                                          "if [Unreleased] is missing or empty, or if VERSION already has a section.")
    cmd.add_argument("version", help="X.Y.Z")
    cmd.add_argument("--date", type=_date, default=None, help="release date YYYY-MM-DD (default: today)")
    cmd.set_defaults(run=_cmd_prepare)

    cmd = commands.add_parser("predicate", help="print the predicate of one attestation of a verification output",
                              description="VERIFY_JSON is the output of `gh attestation verify ... --format json`.")
    cmd.add_argument("verify_json", type=Path)
    cmd.add_argument("--type", required=True, help="predicate type URI to select")
    cmd.set_defaults(run=_cmd_predicate)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # The changelog has "—" and "é"; a Windows console would refuse them in cp1252.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            reconfigure(encoding="utf-8")
    args = _parser().parse_args(argv)
    try:
        return args.run(args)
    except ReleaseError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
