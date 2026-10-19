#!/usr/bin/env python3
"""
Build the release track of one ATT&CK version: pipeline/data/attack/<X.Y>/
(ADR-0087), selected at run time with ATTACK_RELEASE=<X.Y>.

Usage:
    python scripts/download_attack.py --release 20.0
    python scripts/build_attack_release.py --release 20.0 \\
        [--stix-dir data/attack-stix/v20.0] [--out-dir pipeline/data/attack/20.0] \\
        [--capec-index pipeline/data/mitre_index.json] [--force]

The bundles in --stix-dir are checked first: each against the sha256 GitHub
published for it (the release.json download_attack.py wrote beside them), and
the version of its x-mitre-collection against --release.  The track is built
in a neighbouring directory, with the builders of scripts/build_indexes.py,
and renamed once complete, so a failure never leaves a track attack_data would
accept.  Like the default track, mitre_index.json, the gazetteer, the curated
relationships and the embeddings cover Enterprise, Mobile and ICS, while the
revoked-technique table and the retrieval corpus cover Enterprise only; the
CAPEC entries of mitre_index.json are the default track's, carried over.

The embedding model is TTP_EMBEDDING_MODEL (all-MiniLM-L6-v2 by default).  The
default track has no mitre_embeddings_manifest.json, and a track built with
MiniLM has none either; with any other model the track gets one (model,
dimensions, thresholds), so that Stage 2c reads that model and its thresholds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline import attack_data
from scripts import build_indexes

_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
_VERSION = re.compile(r"[0-9]+\.[0-9]+")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

# What a track holds: the default track has no embeddings manifest, so a track
# built with its model has none (stage2c then reads both the same way), and
# another model's gets one; --skip-embeddings leaves out the three files an
# encoder builds.
_EMBEDDINGS_MANIFEST = "mitre_embeddings_manifest.json"
_DEFAULT_MODEL = "all-MiniLM-L6-v2"
_TRACK_FILES = attack_data.ATTACK_FILES - {_EMBEDDINGS_MANIFEST}
_EMBEDDING_FILES = frozenset({"mitre_embeddings.npy", "mitre_embeddings_meta.json",
                              "attack_retrieval_embeddings.npy"})


class BuildError(Exception):
    """The track cannot be built; the message says why."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _rel(path: Path) -> str:
    """`path` from the repository root, POSIX style; outside it, the file name
    alone.  A link is not followed first: a worktree's `data` is often a link
    to the main checkout's.  The manifest never records a local absolute path."""
    for candidate in (Path(os.path.abspath(path)), path.resolve()):
        try:
            return candidate.relative_to(_ROOT).as_posix()
        except ValueError:
            continue
    return path.name


def _git_rev() -> str | None:
    """HEAD of the repository, else the CTIPARSOR_GIT_REV a container build
    stamps (as api.run_config does), else None."""
    try:
        done = subprocess.run(["git", "rev-parse", "HEAD"], cwd=_ROOT,
                              capture_output=True, text=True, timeout=10)
        rev = done.stdout.strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        rev = ""
    return rev or os.getenv("CTIPARSOR_GIT_REV", "").strip() or None


def _verify(release: str, stix_dir: Path) -> list[dict]:
    """The manifest `sources` of the three bundles in `stix_dir`, once each is
    the file GitHub published for the release and holds ATT&CK `release`."""
    meta_path = stix_dir / "release.json"
    if not meta_path.is_file():
        raise BuildError(f"{meta_path} is missing: run `python scripts/download_attack.py "
                         f"--release {release}`")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"{meta_path} unreadable: {exc}") from exc
    listed = meta.get("assets") if isinstance(meta, dict) else None
    assets = {a.get("name"): a for a in listed or [] if isinstance(a, dict)}

    sources = []
    for domain in _DOMAINS:
        name = f"{domain}.json"
        asset = assets.get(name) or {}
        digest = str(asset.get("digest") or "")
        if not _DIGEST.fullmatch(digest):
            raise BuildError(f"{meta_path} records no sha256 digest for {name}")
        path = stix_dir / name
        if not path.is_file():
            raise BuildError(f"{path} is missing: run `python scripts/download_attack.py "
                             f"--release {release}`")
        got = _sha256(path)
        if f"sha256:{got}" != digest:
            raise BuildError(f"{path}: sha256 is {got}, the release published {digest}")
        objects = json.loads(path.read_text(encoding="utf-8")).get("objects", [])
        collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
        found = [str(c.get("x_mitre_version")) for c in collections]
        if found != [release]:
            raise BuildError(f"{path}: its x-mitre-collection says ATT&CK {found or 'nothing'}, "
                             f"not {release}")
        sources.append({
            "domain": domain,
            "file": _rel(path),
            "url": asset.get("url"),
            "sha256": got,
            "published_digest": digest,
            "collection_version": found[0],
            "collection_modified": collections[0].get("modified"),
        })
    return sources


def _summary(directory: Path) -> None:
    index = json.loads((directory / "mitre_index.json").read_text(encoding="utf-8"))
    per_domain = Counter(t["domain"] for t in index["techniques"])
    corpus = json.loads((directory / "attack_retrieval_corpus.json").read_text(encoding="utf-8"))
    pairs = json.loads((directory / "attack_relationships.json").read_text(encoding="utf-8"))["pairs"]
    print()
    print(f"ATT&CK track written to {directory}")
    for domain, n in sorted(per_domain.items()):
        print(f"  {domain:18s}: {n} techniques")
    print(f"  retrieval corpus  : {len(corpus['entries'])} entries")
    print(f"  curated pairs     : {len(pairs)}")


def build_release(release: str, stix_dir: Path | None = None, out_dir: Path | None = None,
                  capec_index: Path | None = None, force: bool = False,
                  skip_embeddings: bool = False) -> Path:
    """Build the track of ATT&CK `release` in `out_dir`; raises BuildError.

    `skip_embeddings` leaves the three embedding files out and says so in the
    manifest: it is for tests, never a way to ship a track.
    """
    if not _VERSION.fullmatch(release):
        raise BuildError(f"{release!r} is not an ATT&CK release: expected X.Y, e.g. 20.0")
    stix_dir = stix_dir or _ROOT / "data" / "attack-stix" / f"v{release}"
    out_dir = out_dir or attack_data.TRACKS_DIR / release
    capec_index = capec_index or attack_data.DATA_DIR / "mitre_index.json"
    if out_dir.exists() and not force:
        raise BuildError(f"{out_dir} exists: pass --force to replace it")

    sources = _verify(release, stix_dir)
    if not capec_index.is_file():
        raise BuildError(f"{capec_index} (the CAPEC entries to carry over) is missing")
    capec = [t for t in json.loads(capec_index.read_text(encoding="utf-8")).get("techniques", [])
             if t.get("domain") == "capec"]
    if not capec:
        raise BuildError(f"{capec_index} holds no CAPEC technique to carry over")

    from dotenv import load_dotenv
    load_dotenv()
    model_id = os.getenv("TTP_EMBEDDING_MODEL", _DEFAULT_MODEL)
    write_manifest = model_id != _DEFAULT_MODEL

    paths = {s["domain"]: stix_dir / f"{s['domain']}.json" for s in sources}
    all_domains: dict[str, Path | None] = {
        "enterprise": paths["enterprise-attack"],
        "mobile": paths["mobile-attack"],
        "ics": paths["ics-attack"],
    }
    enterprise_only: dict[str, Path | None] = {"enterprise": paths["enterprise-attack"]}

    out_dir.parent.mkdir(parents=True, exist_ok=True)
    building = out_dir.parent / f".{out_dir.name}.building"
    shutil.rmtree(building, ignore_errors=True)
    building.mkdir()
    try:
        build_indexes.build_mitre_index(all_domains, building, capec_index)
        build_indexes.build_gazetteer(all_domains, building)
        build_indexes.build_attack_relationships(all_domains, building)
        build_indexes.build_revoked(enterprise_only, building)
        if not skip_embeddings:
            build_indexes.build_embeddings(all_domains, building, write_manifest=write_manifest)
        build_indexes.build_retrieval(enterprise_only, neutralise=True, out_dir=building,
                                      embed=not skip_embeddings)

        names = sorted(p.name for p in building.iterdir() if p.is_file())
        expected = set(_TRACK_FILES)
        if skip_embeddings:
            expected -= _EMBEDDING_FILES
        elif write_manifest:
            expected.add(_EMBEDDINGS_MANIFEST)
        if set(names) != expected:
            raise BuildError(
                f"built {names}, expected {sorted(expected)}"
                + ("" if skip_embeddings else " (is sentence-transformers installed?)"))
        files = {name: _sha256(building / name) for name in names}

        built_with: dict = {"script": "scripts/build_attack_release.py", "git_rev": _git_rev(),
                            "embedding_model": None if skip_embeddings else model_id}
        if skip_embeddings:
            built_with["embeddings"] = "skipped"
        manifest = {
            "release": release,
            "track": "release",
            "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "built_with": built_with,
            "sources": sources,
            "capec": {"carried_from": _rel(capec_index), "sha256": _sha256(capec_index),
                      "entries": len(capec)},
            "retrieval_domains": ["enterprise-attack"],
            "revoked_domains": ["enterprise-attack"],
            "exceptions": {
                "mitre_index.json (CAPEC)": f"the {len(capec)} CAPEC entries are the default track's, "
                                            "carried over: CAPEC is not part of ATT&CK, so the two "
                                            "tracks differ by ATT&CK only"},
            "files": files,
        }
        (building / attack_data.MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

        if out_dir.exists():
            previous = out_dir.parent / f".{out_dir.name}.previous"
            shutil.rmtree(previous, ignore_errors=True)
            out_dir.rename(previous)
            try:
                building.rename(out_dir)
            except OSError:
                previous.rename(out_dir)
                raise
            shutil.rmtree(previous, ignore_errors=True)
        else:
            building.rename(out_dir)
    except BaseException:
        shutil.rmtree(building, ignore_errors=True)
        raise

    _summary(out_dir)
    return out_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release", required=True, metavar="X.Y", help="ATT&CK version, e.g. 20.0")
    parser.add_argument("--stix-dir", type=Path,
                        help="bundles and release.json (default data/attack-stix/v<X.Y>/)")
    parser.add_argument("--out-dir", type=Path,
                        help="the track (default pipeline/data/attack/<X.Y>/)")
    parser.add_argument("--capec-index", type=Path,
                        help="mitre_index.json whose CAPEC entries are carried over "
                             "(default: the default track's)")
    parser.add_argument("--force", action="store_true", help="replace an existing track")
    parser.add_argument("--skip-embeddings", action="store_true",
                        help="tests only: build no embeddings (the manifest says so)")
    args = parser.parse_args(argv)
    try:
        build_release(args.release, args.stix_dir, args.out_dir, args.capec_index,
                      args.force, args.skip_embeddings)
    except BuildError as exc:
        print(f"✖ {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
