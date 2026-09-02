#!/usr/bin/env python3
"""
Measure the cold-start cost of a worker process.

Usage:
    python scripts/measure_cold_start.py [--json]

This script measures the time and memory overhead of importing heavy
dependencies and loading ML models. It is intended to be run on the
production host to determine the appropriate pool size for ADR-0036.
"""

import argparse
import importlib
import json
import math
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict

# The model-loading steps import from `pipeline/`, which is only importable when
# the repository root is on sys.path.  Without this the two steps that measure
# the 4.4 GB of weights fail with "No module named 'pipeline'", the peak RSS
# reflects the bare imports alone, and the suggested pool size comes out several
# times too high — measured 16 on a 15 GB host where the answer is 2.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _rss_mb() -> float:
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 0.0


def _peak_rss_mb() -> float:
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1]) / 1024.0
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 0.0


def _host_ram_gb() -> float:
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return float(line.split()[1]) / (1024.0 * 1024.0)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 0.0


def _timed(label: str, fn: Callable[[], Any]) -> Dict[str, Any]:
    rss_before = _rss_mb()
    start = time.perf_counter()
    error_msg = None
    try:
        fn()
    except Exception as e:
        error_msg = str(e)
    end = time.perf_counter()
    rss_after = _rss_mb()

    result: Dict[str, Any] = {
        "step": label,
        "seconds": end - start,
        "rss_before_mb": rss_before,
        "rss_after_mb": rss_after,
        "delta_mb": rss_after - rss_before,
    }
    if error_msg:
        result["error"] = error_msg
    return result


def measure() -> Dict[str, Any]:
    steps = []

    steps.append(_timed("import torch", lambda: __import__("torch")))
    steps.append(_timed("import sentence_transformers", lambda: __import__("sentence_transformers")))

    # The loaders are named explicitly rather than discovered.  An earlier version
    # searched for a callable whose name started with `_load` and contained
    # "model"; `_load_gliner` contains neither, so the step that holds 4 367 of
    # the 4 400 MB reported "loader not found" and the measurement silently
    # omitted almost all of the memory it exists to measure.  If one of these is
    # renamed the step fails loudly, which is the behaviour we want.
    def _call(module: str, func: str) -> Callable[[], Any]:
        def _run() -> Any:
            mod = importlib.import_module(module)
            loader = getattr(mod, func, None)
            if not callable(loader):
                raise AttributeError(f"{module}.{func} is missing or not callable")
            return loader()
        return _run

    steps.append(_timed("load embedding model",
                        _call("pipeline.stage2c_ttp_semantic", "_load_model")))
    steps.append(_timed("load GLiNER",
                        _call("pipeline.stage2e_gliner", "_load_gliner")))

    total_seconds = sum(s["seconds"] for s in steps)
    peak_rss = _peak_rss_mb()
    host_ram = _host_ram_gb()

    return {
        "host_ram_gb": host_ram,
        "steps": steps,
        "total_seconds": total_seconds,
        "peak_rss_mb": peak_rss,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure cold start cost")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    result = measure()
    failed = [s for s in result["steps"] if "error" in s]

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{'Step':<30} {'Seconds':>10} {'Delta MB':>10}")
        print("-" * 52)
        for step in result["steps"]:
            err = f" [ERROR: {step.get('error', '')}]" if "error" in step else ""
            print(f"{step['step']:<30} {step['seconds']:>10.2f} {step['delta_mb']:>10.1f}{err}")
        print("-" * 52)
        print(f"{'Total':<30} {result['total_seconds']:>10.2f}")
        print(f"Host RAM: {result['host_ram_gb']:.2f} GB")
        print(f"Peak RSS: {result['peak_rss_mb']:.2f} MB")

        peak_rss_gb = result["peak_rss_mb"] / 1024.0
        if failed:
            # Refuse to advise on a partial measurement.  A failed model-load
            # step leaves the peak RSS at the cost of the bare imports, and the
            # formula would then recommend a pool several times too large — the
            # one number in this output an operator acts on directly.
            print("")
            print(f"NO POOL SIZE SUGGESTED — {len(failed)} step(s) failed: "
                  f"{', '.join(s['step'] for s in failed)}")
            print("The peak RSS above excludes the model weights, so any pool size")
            print("derived from it would overcommit the host.  Fix the failures and")
            print("re-run before sizing anything.")
        elif peak_rss_gb > 0:
            suggested = max(1, int(math.floor((result["host_ram_gb"] - 4) / peak_rss_gb)))
            print(f"suggested pool size = floor((RAM_GB - 4) / peak_RSS_GB) = {suggested}")
        else:
            print("NO POOL SIZE SUGGESTED — peak RSS could not be read (non-Linux host?).")

    # Non-zero exit on a partial run so this cannot pass silently in a script.
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
