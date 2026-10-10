"""Give every pin of a PyPI lock the sha256 of PyPI's own files (ADR-0080).

`scripts/lock.sh` resolves with the PyTorch index next to PyPI, to get
torch's CPU build.  That index re-hosts common packages (markupsafe, jinja2,
colorama…) under PyPI's file names but not PyPI's bytes, and uv then records
those files' hashes, not PyPI's: markupsafe's Linux wheel had none of PyPI's.
The locks rewritten here name no index, so pip installs from PyPI; their
hashes must be PyPI's.  torch is left alone: requirements-torch.lock.txt
installs it from the PyTorch index first, and here it is already satisfied.

    python3 scripts/lock_pypi_hashes.py requirements/requirements.lock.txt [more locks…]
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

KEEP = {"torch"}            # installed from the PyTorch index, never from PyPI
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)")


def pypi_hashes(name: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=60) as response:
        files = json.load(response)["urls"]
    hashes = sorted({f["digests"]["sha256"] for f in files})
    if not hashes:
        raise SystemExit(f"{name}=={version}: PyPI lists no file for this release")
    return hashes


def rewrite(path: str) -> tuple[int, int]:
    lines = open(path, encoding="utf-8").read().split("\n")
    blocks: list[tuple[int, int, str, str]] = []      # (pin line, last hash line, name, version)
    i = 0
    while i < len(lines):
        m = PIN.match(lines[i])
        if m and lines[i].rstrip().endswith("\\"):
            j = i + 1
            while j < len(lines) and lines[j].lstrip().startswith("--hash="):
                j += 1
            blocks.append((i, j, m.group(1), m.group(2)))
            i = j
        else:
            i += 1
    wanted = [(n, v) for _, _, n, v in blocks if n.lower() not in KEEP]
    with ThreadPoolExecutor(12) as pool:
        found = dict(zip(wanted, pool.map(lambda nv: pypi_hashes(*nv), wanted), strict=True))
    changed = 0
    for start, end, name, version in reversed(blocks):
        if name.lower() in KEEP:
            continue
        new = found[(name, version)]
        old = [re.search(r"sha256:([0-9a-f]{64})", line).group(1) for line in lines[start + 1:end]]
        if sorted(old) != new:
            changed += 1
        hash_lines = [f"    --hash=sha256:{h} \\" for h in new]
        hash_lines[-1] = hash_lines[-1][:-2]
        lines[start + 1:end] = hash_lines
    with open(path, "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(lines))
    return len(wanted), changed


if __name__ == "__main__":
    for lock in sys.argv[1:]:
        total, changed = rewrite(lock)
        print(f"{lock}: {total} pins hashed from PyPI ({changed} differed from the resolver's)")
