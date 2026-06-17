#!/usr/bin/env python3
"""
Download the MITRE ATT&CK Enterprise STIX bundle for offline TTP normalization.

Usage:
    python scripts/download_attack.py             # downloads enterprise-attack.json
    python scripts/download_attack.py --force     # re-downloads even if file exists
    python scripts/download_attack.py --check     # prints version info and exits

The file is saved to data/enterprise-attack.json (~12 MB).
This directory is in .gitignore — do not commit the bundle to the repo.
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

# Official MITRE CTI GitHub — enterprise ATT&CK STIX 2.1 bundle
_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

_OUT = Path(__file__).parent.parent / "data" / "enterprise-attack.json"


def _count_techniques(bundle_path: Path) -> tuple[int, int]:
    """Returns (total_techniques, sub_techniques) from a local bundle."""
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    techs = [
        o for o in data.get("objects", [])
        if o.get("type") == "attack-pattern"
    ]
    subs = [t for t in techs if t.get("x_mitre_is_subtechnique", False)]
    return len(techs), len(subs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="Re-download even if file exists")
    parser.add_argument("--check", action="store_true", help="Print bundle stats and exit (no download)")
    args = parser.parse_args()

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
            headers={"User-Agent": "cti-to-stix/1.0 (MITRE ATT&CK normalizer)"},
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


if __name__ == "__main__":
    main()
