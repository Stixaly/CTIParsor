#!/usr/bin/env python3
"""
Download the MITRE ATT&CK Enterprise STIX bundle for offline TTP normalization.

Usage:
    python scripts/download_attack.py             # downloads enterprise-attack.json
    python scripts/download_attack.py --force     # re-downloads even if file exists
    python scripts/download_attack.py --check     # prints version info and exits

    # One release's three bundles (enterprise, mobile, ics), checked against
    # the sha256 GitHub publishes for each asset (ADR-0087)
    python scripts/download_attack.py --release 19.2 [--out DIR]

The file is saved to data/enterprise-attack.json (~12 MB).  With --release the
bundles and a release.json (tag, digests, fetch date) go to
data/attack-stix/v<X.Y>/ (~67 MB for v20.0), which scripts/build_attack_release.py reads.
This directory is in .gitignore — do not commit the bundles to the repo.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

# Official MITRE CTI GitHub — enterprise ATT&CK STIX 2.1 bundle
_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_REPO_ROOT = Path(__file__).parent.parent
_OUT = _REPO_ROOT / "data" / "enterprise-attack.json"

# --release: the assets of mitre-attack/attack-stix-data's releases, and what
# the repository already records about them (pipeline/attack_data.py).
_REPOSITORY = "mitre-attack/attack-stix-data"
_API = f"https://api.github.com/repos/{_REPOSITORY}/releases/tags"
_DOWNLOADS = f"https://github.com/{_REPOSITORY}/releases/download"
_BUNDLES = ("enterprise-attack.json", "mobile-attack.json", "ics-attack.json")
_VERSION = re.compile(r"[0-9]+\.[0-9]+")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_USER_AGENT = "cti-to-stix/1.0 (MITRE ATT&CK normalizer)"
_DEFAULT_MANIFEST = _REPO_ROOT / "pipeline" / "data" / "attack_manifest.json"
_TRACKS_DIR = _REPO_ROOT / "pipeline" / "data" / "attack"


def _count_techniques(bundle_path: Path) -> tuple[int, int]:
    """Returns (total_techniques, sub_techniques) from a local bundle."""
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    techs = [
        o for o in data.get("objects", [])
        if o.get("type") == "attack-pattern"
    ]
    subs = [t for t in techs if t.get("x_mitre_is_subtechnique", False)]
    return len(techs), len(subs)


def _refuse(message: str) -> NoReturn:
    print(f"✖ {message}")
    sys.exit(1)


def _read_manifest(path: Path) -> dict:
    """A track manifest; {} when the file is not there."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        _refuse(f"{path} unreadable: {e}")
    return data if isinstance(data, dict) else {}


def _recorded(version: str) -> list[tuple[str | None, str | None, Path]]:
    """(domain, sha256, manifest) for each bundle of `version` the repository's
    manifests name: a track's own sources, and the default track's equivalent
    release assets when `version` is its release."""
    out: list[tuple[str | None, str | None, Path]] = []
    track = _TRACKS_DIR / version / "attack_manifest.json"
    for source in _read_manifest(track).get("sources") or []:
        out.append((source.get("domain"), source.get("sha256"), track))
    default = _read_manifest(_DEFAULT_MANIFEST)
    if str(default.get("release")) == version:
        for source in default.get("sources") or []:
            asset = source.get("equivalent_release_asset") or {}
            out.append((source.get("domain"), asset.get("sha256"), _DEFAULT_MANIFEST))
    return out


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _get_json(url: str) -> object:
    req = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def _fetch(url: str, tmp: Path, size: int) -> str:
    """Stream `url` into `tmp`; the sha256 of what was written.  `size` is what
    GitHub publishes for the asset: a stream that goes past it is cut off
    (ValueError), and so is one that ends with another size."""
    h = hashlib.sha256()
    written = 0
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp, tmp.open("wb") as f:
        for block in iter(lambda: resp.read(1 << 20), b""):
            written += len(block)
            if written > size:
                raise ValueError(f"the stream goes past the {size} bytes GitHub publishes")
            h.update(block)
            f.write(block)
    if written != size:
        raise ValueError(f"{written} bytes received, GitHub publishes {size}")
    return h.hexdigest()


def _mkdirs(path: Path) -> list[Path]:
    """Create `path`; the directories this made, deepest first."""
    made = []
    p = path
    while not p.exists():
        made.append(p)
        p = p.parent
    path.mkdir(parents=True, exist_ok=True)
    return made


def download_release(version: str, out: Path | None = None) -> None:
    """Download the enterprise, mobile and ics bundles of attack-stix-data's
    release `version` into `out`, and write release.json beside them.

    Each asset must publish a sha256 digest, be served from that release's own
    download URL, and agree with what the repository's manifests already
    record for `version`.  Every bundle is downloaded to a .tmp file and
    checked before any is renamed; a failure leaves nothing behind and exits 1.
    """
    if not _VERSION.fullmatch(version):
        _refuse(f"{version!r} is not an ATT&CK release: expected X.Y, e.g. 19.2")
    tag = f"v{version}"
    out = out or _REPO_ROOT / "data" / "attack-stix" / tag

    print(f"Reading the metadata of {_REPOSITORY} {tag}...")
    try:
        release = _get_json(f"{_API}/{tag}")
    except (OSError, ValueError) as e:
        _refuse(f"Could not read the metadata of {tag}: {e}")
    if not isinstance(release, dict) or release.get("tag_name") != tag:
        _refuse(f"The metadata do not describe release {tag}")
    by_name = {a.get("name"): a for a in release.get("assets") or [] if isinstance(a, dict)}
    recorded = _recorded(version)

    assets: list[dict] = []
    for name in _BUNDLES:
        asset = by_name.get(name)
        if asset is None:
            _refuse(f"Release {tag} has no asset {name}")
        digest = str(asset.get("digest") or "")
        if not _DIGEST.fullmatch(digest):
            _refuse(f"{name}: no sha256 digest published (got {digest!r})")
        url = str(asset.get("browser_download_url") or "")
        if url != f"{_DOWNLOADS}/{tag}/{name}":
            _refuse(f"{name}: unexpected download URL {url!r}")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            _refuse(f"{name}: no size published (got {size!r})")
        domain = name.removesuffix(".json")
        for d, sha, manifest in recorded:
            if d == domain and sha and sha != digest.removeprefix("sha256:"):
                _refuse(f"{name}: GitHub publishes {digest}, but {manifest} records sha256:{sha}")
        assets.append({"name": name, "size": size, "digest": digest, "url": url})

    made: list[Path] = []
    fetched: list[tuple[Path, Path]] = []
    try:
        made = _mkdirs(out)
        for asset in assets:
            target = out / asset["name"]
            want = asset["digest"].removeprefix("sha256:")
            if target.is_file() and _sha256_file(target) == want:
                print(f"  {asset['name']}: already present, sha256 matches")
                continue
            tmp = target.with_name(target.name + ".tmp")
            fetched.append((tmp, target))
            print(f"  {asset['name']}: downloading ({asset['size']} bytes)...")
            try:
                got = _fetch(asset["url"], tmp, asset["size"])
            except (OSError, ValueError) as e:
                _refuse(f"{asset['name']}: download failed: {e}")
            if got != want:
                _refuse(f"{asset['name']}: sha256 is {got}, GitHub publishes {want}")
        for tmp, target in fetched:
            tmp.replace(target)
    except BaseException:
        for tmp, _ in fetched:
            tmp.unlink(missing_ok=True)
        for directory in made:
            try:
                directory.rmdir()
            except OSError:
                pass
        raise

    (out / "release.json").write_text(json.dumps({
        "repository": _REPOSITORY,
        "tag": tag,
        "name": release.get("name"),
        "published_at": release.get("published_at"),
        "html_url": release.get("html_url"),
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "assets": assets,
    }, indent=1) + "\n", encoding="utf-8")
    print(f"✔ ATT&CK {version}: {len(assets)} bundles verified")
    print(f"  Saved to: {out}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="Re-download even if file exists")
    parser.add_argument("--check", action="store_true", help="Print bundle stats and exit (no download)")
    parser.add_argument("--release", metavar="X.Y",
                        help="Download this attack-stix-data release (enterprise, mobile and ics), "
                             "verified against GitHub's sha256, instead of mitre/cti master")
    parser.add_argument("--out", type=Path,
                        help="With --release: where to save (default data/attack-stix/v<X.Y>/)")
    args = parser.parse_args()

    if args.release:
        if args.check or args.force:
            parser.error("--release cannot be combined with --check or --force")
        download_release(args.release, args.out)
        return
    if args.out:
        parser.error("--out needs --release")

    if args.check:
        if not _OUT.exists():
            print(f"Bundle not found at {_OUT}")
            print("Run:  python scripts/download_attack.py")
            sys.exit(1)
        total, subs = _count_techniques(_OUT)
        size_mb = _OUT.stat().st_size / 1e6
        print(f"Bundle : {_OUT}")
        print(f"Size   : {size_mb:.1f} MB")
        print(f"Techniques      : {total - subs}")
        print(f"Sub-techniques  : {subs}")
        print(f"Total patterns  : {total}")
        return

    if _OUT.exists() and not args.force:
        total, subs = _count_techniques(_OUT)
        size_mb = _OUT.stat().st_size / 1e6
        print(f"✔ Bundle already present ({size_mb:.1f} MB, {total} techniques).")
        print("  Use --force to re-download.")
        return

    print("Downloading MITRE ATT&CK enterprise bundle...")
    print(f"  Source : {_URL}")
    print(f"  Target : {_OUT}")
    print()

    _OUT.parent.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(
            _URL,
            headers={"User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
    except urllib.error.URLError as e:
        print(f"✖ Download failed: {e}")
        print("  Check your internet connection or download manually from:")
        print(f"  {_URL}")
        sys.exit(1)

    # Write to a temp file first, then rename atomically so an interrupted
    # download never leaves a partially-written file that looks valid.
    tmp = _OUT.with_suffix('.tmp')
    tmp.write_bytes(data)
    tmp.replace(_OUT)

    # Validate it parsed correctly
    try:
        total, subs = _count_techniques(_OUT)
        size_mb = len(data) / 1e6
        print(f"✔ Downloaded {size_mb:.1f} MB")
        print(f"  Techniques     : {total - subs}")
        print(f"  Sub-techniques : {subs}")
        print(f"  Total patterns : {total}")
        print()
        print(f"  Saved to: {_OUT}")
    except Exception as e:
        print(f"✖ File downloaded but validation failed: {e}")
        sys.exit(1)

    # mitre/cti master is the latest ATT&CK release, which is not necessarily
    # the track the pipeline reads by default (ADR-0087).
    default = _read_manifest(_DEFAULT_MANIFEST).get("release")
    if default:
        print()
        print("  Note: this is the latest release of mitre/cti, not necessarily the default track,")
        print(f"  which is {default} (pipeline/data/attack_manifest.json); "
              f"for its bundles run: --release {default}")


if __name__ == "__main__":
    main()
