"""Which ATT&CK release the pipeline reads (ADR-0087).

Every file `scripts/build_indexes.py` builds from MITRE's ATT&CK bundles
(`ATTACK_FILES`) belongs to one *release track*:

* the default track is the set committed in pipeline/data/; its
  `attack_manifest.json` names the release it matches (19.2) and the files
  that were built from another one;
* any other track is a directory pipeline/data/attack/<version>/ holding the
  same files built from that release, with its own `attack_manifest.json`
  (source bundles and their sha256, sha256 of every file).

`ATTACK_RELEASE` selects one track per process.  Unset or empty is the
default track, and so is the default's own version; any other value must be
a track directory.  An unknown value raises `UnknownAttackRelease`: a run is
never quietly given another release than the one it asked for (ADR-0073's
rule for a TLP level).  Like TTP_EMBEDDING_MODEL, it is set before the
process starts: the loaders cache what they read, so the first call of
`current()` that resolves fixes the release for the process, and a later one
that resolves another raises.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
TRACKS_DIR = DATA_DIR / "attack"
MANIFEST_NAME = "attack_manifest.json"

# What a track holds: every file built from the ATT&CK bundles.
ATTACK_FILES = frozenset({
    "mitre_index.json", "gazetteer.json", "attack_relationships.json", "attack_revoked.json",
    "mitre_embeddings.npy", "mitre_embeddings_meta.json", "mitre_embeddings_manifest.json",
    "attack_retrieval_corpus.json", "attack_retrieval_embeddings.npy",
})

# A track is named by its ATT&CK version and nothing else: the value becomes
# a directory name, so "../" or a path never reaches the filesystem.  ASCII
# digits only: \d would take any Unicode digit.
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,2}")
_TAGGED = re.compile(r"[vV][0-9]")      # "v20.0" is "20.0"; "v" and "vdefault" are not versions

# The version this process resolved first (None before): see current().
_fixed: str | None = None


class UnknownAttackRelease(ValueError):
    """ATTACK_RELEASE names no track this installation has."""


@dataclass(frozen=True)
class Release:
    version: str                       # "19.2", "20.0"
    directory: Path
    default: bool
    manifest: dict = field(compare=False, hash=False, repr=False)


def requested() -> str:
    """The raw ATTACK_RELEASE value, stripped ("" when unset)."""
    return os.getenv("ATTACK_RELEASE", "").strip()


def _read_manifest(directory: Path) -> dict:
    path = directory / MANIFEST_NAME
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UnknownAttackRelease(f"{path} unreadable: {type(exc).__name__}: {exc}") from exc
    if not isinstance(data, dict) or not str(data.get("release") or ""):
        raise UnknownAttackRelease(f"{path} names no release")
    return data


def available() -> list[str]:
    """The releases this installation can run: the default first."""
    out = []
    try:
        out.append(str(_read_manifest(DATA_DIR)["release"]))
    except UnknownAttackRelease:
        pass
    if TRACKS_DIR.is_dir():
        out += sorted((p.name for p in TRACKS_DIR.iterdir()
                       if _VERSION.fullmatch(p.name) and (p / MANIFEST_NAME).is_file()),
                      key=lambda v: tuple(int(x) for x in v.split(".")))
    return out


def is_version(value: str) -> bool:
    """Whether `value` is spelled as an ATT&CK version (19.2, 20.0, 20), with no "v"."""
    return _VERSION.fullmatch(value) is not None


@functools.lru_cache(maxsize=8)
def _release(value: str) -> Release:
    default = _read_manifest(DATA_DIR)
    default_version = str(default["release"])
    name = value[1:] if _TAGGED.match(value) else value
    if name in ("", "default", default_version):
        return Release(default_version, DATA_DIR, True, default)
    if not is_version(name) or not (TRACKS_DIR / name / MANIFEST_NAME).is_file():
        raise UnknownAttackRelease(
            f"ATTACK_RELEASE={value!r}: no such ATT&CK release here; available: "
            f"{', '.join(available()) or 'none'} (unset = the default, {default_version})")
    manifest = _read_manifest(TRACKS_DIR / name)
    if str(manifest["release"]) != name:
        raise UnknownAttackRelease(
            f"{TRACKS_DIR / name / MANIFEST_NAME} says release {manifest['release']!r}, "
            f"not {name!r}")
    return Release(name, TRACKS_DIR / name, False, manifest)


def release(value: str) -> Release:
    """The release `value` names, spelled as ATTACK_RELEASE is ("" the default
    track).  Raises UnknownAttackRelease.  It does not touch the release the
    process fixed: this is how a tool asks about another one."""
    return _release(value.strip())


def current() -> Release:
    """The release ATTACK_RELEASE selects.  Raises UnknownAttackRelease.

    The first call that resolves fixes the release (its version) for the
    process: .env is loaded when stage3_llm or api.db is imported, so a
    process could otherwise read the default track for Stage 2b and 2c and
    ATTACK_RELEASE's after that import.  A later call that resolves another
    version raises; the same version spelled differently ("v19.2", "") does not.
    """
    global _fixed
    rel = release(requested())
    if _fixed is None:
        _fixed = rel.version
    elif rel.version != _fixed:
        raise UnknownAttackRelease(
            f"ATTACK_RELEASE changed from {_fixed} to {rel.version} in this process; "
            "set it before the process starts")
    return rel


def reset() -> None:
    """Forget the release the process fixed and what was resolved.  For tests."""
    global _fixed
    _fixed = None
    _release.cache_clear()


def resolve(path: Path | str) -> Path:
    """`path` as the selected release has it.

    A default-track ATT&CK file (pipeline/data/<one of ATTACK_FILES>, or the
    manifest) becomes the selected track's file of that name; every other
    path — the warning lists, a test's temporary file — is returned
    unchanged, so the loaders' module constants keep naming the default file
    and can still be pinned.
    """
    p = Path(path)
    if (p.name not in ATTACK_FILES and p.name != MANIFEST_NAME) \
            or os.path.abspath(p.parent) != os.path.abspath(DATA_DIR):
        return p
    rel = current()
    return p if rel.default else rel.directory / p.name


@functools.lru_cache(maxsize=64)
def _sha256_of(path: str, mtime_ns: int, size: int) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sha256(path: Path) -> str | None:
    """Content hash, cached on (path, mtime, size); None for a missing file."""
    try:
        st = path.stat()
    except OSError:
        return None
    return _sha256_of(str(path), st.st_mtime_ns, st.st_size)


def modified_files(rel: Release | None = None) -> list[str]:
    """Files of the release whose content is no longer the one its manifest
    recorded (a local rebuild): the version it claims is then not proven.

    A file of ATTACK_FILES that sits in the track's directory without being in
    the manifest is listed too, as "<name> (not in the manifest)": a local
    mitre_embeddings_manifest.json would change Stage 2c's model and thresholds
    unnoticed.  The mention keeps the result a flat list of strings, as the run
    manifest carries it.
    """
    rel = rel or current()
    recorded = rel.manifest.get("files") or {}
    changed = [name for name, digest in recorded.items() if sha256(rel.directory / name) != digest]
    added = [f"{name} (not in the manifest)" for name in ATTACK_FILES
             if name not in recorded and (rel.directory / name).is_file()]
    return sorted(changed + added)


def describe() -> dict:
    """The ATT&CK block of a run manifest (api.run_config.build_manifest).
    Raises UnknownAttackRelease, like the loaders."""
    rel = current()
    try:
        directory = rel.directory.relative_to(DATA_DIR.parent.parent).as_posix()
    except ValueError:
        directory = str(rel.directory)
    return {
        "release": rel.version,
        "default": rel.default,
        "requested": requested() or None,
        "directory": directory,
        "manifest_sha256": (sha256(rel.directory / MANIFEST_NAME) or "")[:16] or None,
        "built_with": rel.manifest.get("built_with"),
        "sources": {s.get("domain", "?"): (s.get("sha256") or "")[:16] or None
                    for s in rel.manifest.get("sources") or []},
        "exceptions": sorted((rel.manifest.get("exceptions") or {}).keys()),
        "modified_files": modified_files(rel),
    }
