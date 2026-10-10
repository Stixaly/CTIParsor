"""Check that no requirement's floor is a version with a known vulnerability.

The locks pin what is installed, and pip-audit checks them.  But OSV-Scanner,
the scanner of OpenSSF Scorecard's Vulnerabilities check, may read a range
such as ``python-multipart>=0.0.9`` as version 0.0.9: a low floor then reads
as a vulnerable install (October 2026: eight advisories on python-multipart,
whose lock pinned 0.0.32).  This asks OSV about each floor (``>=``, ``==`` or
``~=``) in requirements/requirements*.txt, the locks excepted, and exits 1 when
one is affected, naming the versions that fix it.

    python3 scripts/check_requirement_floors.py

Needs network access to api.osv.dev; part of the quarterly routine
(docs/dependencies.md).
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

OSV = "https://api.osv.dev/v1"
LISTS = ("requirements.txt", "requirements-full.txt", "requirements-dev.txt", "requirements-audit.txt")


def floors(directory: Path) -> dict[str, tuple[str, str]]:
    """{package: (floor version, file)} for every requirement that has a floor."""
    out = {}
    for name in LISTS:
        for raw in (directory / name).read_text(encoding="utf-8").splitlines():
            line = raw.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(.*)$", line)
            floor = re.search(r"(?:>=|==|~=)\s*([0-9][^,;\s]*)", m.group(2))
            if floor:
                out[m.group(1)] = (floor.group(1), name)
    return out


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(f"{OSV}{path}", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def _get(path: str) -> dict:
    with urllib.request.urlopen(f"{OSV}{path}", timeout=60) as resp:
        return json.load(resp)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    found = floors(Path(__file__).resolve().parent.parent / "requirements")
    queries = [{"package": {"name": pkg, "ecosystem": "PyPI"}, "version": version}
               for pkg, (version, _) in sorted(found.items())]
    results = _post("/querybatch", {"queries": queries})["results"]
    bad = 0
    for query, result in zip(queries, results, strict=True):
        ids = sorted(v["id"] for v in result.get("vulns", []))
        if not ids:
            continue
        bad += 1
        pkg, version = query["package"]["name"], query["version"]
        fixed = set()
        for vid in ids:
            for affected in _get(f"/vulns/{vid}").get("affected", []):
                if _norm(affected["package"]["name"]) == _norm(pkg):
                    fixed.update(event["fixed"] for rng in affected.get("ranges", [])
                                 for event in rng.get("events", []) if "fixed" in event)
        # OSV also lists fixing git commits; keep the releases, in version order.
        releases = sorted((f for f in fixed if re.fullmatch(r"\d+(\.\d+)+[0-9A-Za-z.]*", f)),
                          key=lambda v: [(0, int(t)) if t.isdigit() else (1, t) for t in re.split(r"[.]", v)])
        print(f"{pkg} {version} ({found[pkg][1]}): {len(ids)} advisories, fixed in {', '.join(releases)}")
    print(f"{bad} of {len(queries)} floors are vulnerable versions")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
