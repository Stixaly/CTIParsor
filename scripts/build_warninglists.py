"""Vendor the MISP warninglists Stage 4 uses to keep benign values from
becoming Indicators (audit B 8.1.7).

    python scripts/build_warninglists.py [--commit SHA]

Writes pipeline/data/warninglists.json from MISP/misp-warninglists at a pinned
commit.  The lists are CC0 1.0 (the repository's README, "License").  Three
lists, chosen for what a CTI report names without accusing it:

- security-provider-blogpost: vendors' and researchers' sites, the reference
  links a report cites;
- automated-malware-analysis: sandboxes (any.run, Intezer…), the same;
- tranco10k: the 10,000 most popular domains, used for an exact domain only
  (pipeline/benign.py), so `x.duckdns.org` or `evil.blogspot.com` stay
  Indicators.

Not vendored: public-dns-v4 (62,780 addresses, every open resolver seen, a
compromised C2 among them possibly); non-routable addresses are recognised by
Python's `ipaddress` instead of the RFC lists.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

REPO = "MISP/misp-warninglists"
COMMIT = "af01b1d67ae78b2064c2823ebfd9078d6e7828c9"     # main on 2026-10-11
LISTS = ("security-provider-blogpost", "automated-malware-analysis", "tranco10k")
OUT = Path(__file__).resolve().parent.parent / "pipeline" / "data" / "warninglists.json"


def _fetch(commit: str, name: str) -> dict:
    url = f"https://raw.githubusercontent.com/{REPO}/{commit}/lists/{name}/list.json"
    with urllib.request.urlopen(url, timeout=60) as resp:   # noqa: S310 — a fixed https URL
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", default=COMMIT, help="misp-warninglists commit to vendor")
    args = parser.parse_args()
    lists = {}
    for name in LISTS:
        data = _fetch(args.commit, name)
        values = sorted({v.strip().lower() for v in data.get("list", []) if isinstance(v, str) and v.strip()})
        lists[name] = {"description": data.get("description", ""), "version": data.get("version"),
                       "type": data.get("type"), "values": values}
        print(f"  {name:28} {data.get('type'):10} {len(values):6} values (version {data.get('version')})")
    OUT.write_text(json.dumps({"source": f"https://github.com/{REPO}", "commit": args.commit,
                               "license": "CC0-1.0", "lists": lists}, indent=0) + "\n", encoding="utf-8")
    print(f"written {OUT}")


if __name__ == "__main__":
    main()
