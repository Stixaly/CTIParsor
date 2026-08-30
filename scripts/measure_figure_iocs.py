"""Read-only harness measuring whether VLM `iocs` are grounded in `verbatim_text`."""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from pathlib import Path

# Ensure repo root is importable when run from elsewhere
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pipeline.figure_store import SqliteReadCache
from pipeline.stage1f_figures import EMPTY_KINDS, find_figures, read_figures
from pipeline.vlm import FigureRead, get_backend


def normalise(value: str) -> str:
    """Reduce a value for comparison: lowercase, strip, deobfuscate."""
    v = value.strip().lower()
    v = re.sub(r"\[\.\]", ".", v)
    v = re.sub(r"\(\.\)", ".", v)
    v = re.sub(r"\[:\]", ":", v)
    v = v.replace("hxxp", "http")
    return v


def ioc_grounding(read: FigureRead) -> tuple[int, int, list[str]]:
    """Return (n_grounded, n_ungrounded, ungrounded_values) for a FigureRead."""
    haystack = normalise(" ".join(read.verbatim_text))
    n_grounded = 0
    n_ungrounded = 0
    ungrounded_values: list[str] = []
    for v in read.iocs:
        nv = normalise(v)
        if not nv:
            continue
        if nv in haystack:
            n_grounded += 1
        else:
            n_ungrounded += 1
            ungrounded_values.append(v)
    return n_grounded, n_ungrounded, ungrounded_values


def measure_pdf(pdf_path: Path, backend, cache) -> dict:
    """Measure IoC grounding for a single PDF; never raises."""
    name = pdf_path.name
    try:
        candidates = find_figures(str(pdf_path))
    except Exception:
        candidates = []

    result: dict = {
        "name": name,
        "candidates": len(candidates),
        "read": 0,
        "kinds": Counter(),
        "iocs_total": 0,
        "iocs_grounded": 0,
        "iocs_ungrounded": 0,
        "ungrounded_samples": [],
        "edges_total": 0,
        "verbatim_lines": 0,
        "elapsed_s": 0.0,
    }

    try:
        reads = read_figures(str(pdf_path), backend, cache=cache)
    except Exception as exc:
        print(f"WARNING: read_figures failed for {name}: {exc}", file=sys.stderr)
        result["error"] = str(exc)
        return result

    for _cand, read, _raw in reads:
        if read.kind in EMPTY_KINDS:
            continue
        result["read"] += 1
        result["kinds"][read.kind] += 1
        result["edges_total"] += len(read.edges)
        result["verbatim_lines"] += len(read.verbatim_text)
        result["elapsed_s"] += read.elapsed_s

        n_g, n_u, ungrounded = ioc_grounding(read)
        # Not len(read.iocs): `ioc_grounding` drops values that normalise to
        # nothing, so counting the raw list here would inflate the denominator
        # and understate the grounded share without saying so.
        result["iocs_total"] += n_g + n_u
        result["iocs_grounded"] += n_g
        result["iocs_ungrounded"] += n_u
        result["ungrounded_samples"].extend(ungrounded)

    result["ungrounded_samples"] = result["ungrounded_samples"][:5]
    return result


def main() -> int:
    """Entry point: parse args, measure PDFs, print summary."""
    parser = argparse.ArgumentParser(description="Measure IoC grounding in VLM figure reads.")
    parser.add_argument("pdfs", nargs="+", help="Paths to PDF files")
    parser.add_argument("--limit", type=int, default=0, help="Max number of PDFs to process (0 = no limit)")
    args = parser.parse_args()

    pdfs = args.pdfs
    if args.limit > 0:
        pdfs = pdfs[: args.limit]

    backend = get_backend()
    if backend is None:
        print("VISION_PROVIDER is not configured — set it in .env", file=sys.stderr)
        return 2

    cache = SqliteReadCache()

    header = f"{'name':<34} {'cand':>5} {'read':>5} {'iocs':>5} {'grnd':>5} {'ungr':>5} {'s':>6}"
    print(header)
    print("-" * len(header))

    totals = {
        "candidates": 0,
        "read": 0,
        "iocs_total": 0,
        "iocs_grounded": 0,
        "iocs_ungrounded": 0,
        "elapsed_s": 0.0,
    }
    all_kinds: Counter = Counter()
    all_ungrounded: list[str] = []

    for pdf_str in pdfs:
        pdf_path = Path(pdf_str)
        r = measure_pdf(pdf_path, backend, cache)

        name_display = r["name"][:34]
        print(
            f"{name_display:<34} {r['candidates']:>5} {r['read']:>5} "
            f"{r['iocs_total']:>5} {r['iocs_grounded']:>5} {r['iocs_ungrounded']:>5} "
            f"{r['elapsed_s']:>6.1f}"
        )

        totals["candidates"] += r["candidates"]
        totals["read"] += r["read"]
        totals["iocs_total"] += r["iocs_total"]
        totals["iocs_grounded"] += r["iocs_grounded"]
        totals["iocs_ungrounded"] += r["iocs_ungrounded"]
        totals["elapsed_s"] += r["elapsed_s"]
        all_kinds.update(r["kinds"])
        all_ungrounded.extend(r["ungrounded_samples"])

    print("-" * len(header))
    print(
        f"{'TOTAL':<34} {totals['candidates']:>5} {totals['read']:>5} "
        f"{totals['iocs_total']:>5} {totals['iocs_grounded']:>5} {totals['iocs_ungrounded']:>5} "
        f"{totals['elapsed_s']:>6.1f}"
    )

    if totals["iocs_total"] > 0:
        pct = (totals["iocs_grounded"] / totals["iocs_total"]) * 100
        print(f"\nIoC grounded: {pct:.1f}%")
    else:
        print("\nIoC grounded: n/a")

    if all_kinds:
        print("\nKind distribution:")
        for kind, count in sorted(all_kinds.items(), key=lambda x: x[1], reverse=True):
            print(f"  {kind}: {count}")

    if all_ungrounded:
        print("\nUngrounded IoC samples:")
        for v in all_ungrounded[:10]:
            print(f"  ! {v}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
