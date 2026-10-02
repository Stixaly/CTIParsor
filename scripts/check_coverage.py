"""Coverage floors for the areas a regression costs most in, on top of the
total floor in pyproject.toml ([tool.coverage.report] fail_under).

Run after `pytest --cov` (CI's fast-tests job, `make ci`): it reads the
.coverage data that run left in the working directory and exits 1 when an
area's coverage (lines and branches) is below its floor.

Each floor is what CI's fast-tests job measured, rounded down: it stops a
change from removing tests or adding untested code in these files, without
asking for new tests.  Raise a floor when its area gains tests.
Measured 2026-10-03: STIX mapping and validation 92.7%, persistence 91.8%.
"""
from __future__ import annotations

import io
import sys

import coverage

# area -> (files, floor in percent)
AREAS: dict[str, tuple[list[str], float]] = {
    # What reaches OpenCTI: the bundle, its validation, the ledger that says
    # why each object ships or not, and the import gates on quoted rules.
    "STIX mapping and validation": ([
        "pipeline/stage4_stix_mapping.py",
        "pipeline/stage5_validation.py",
        "pipeline/bundle_ledger.py",
        "pipeline/stix_ids.py",
        "pipeline/stix_rel_spec.py",
        "pipeline/detection/pattern_check.py",
        "pipeline/detection/yara_check.py",
    ], 92),
    # The job store and the write -> finalize round trip through it.
    "Persistence": ([
        "api/db.py",
        "api/db_backend.py",
        "api/storage.py",
        "api/worker.py",
        "api/paths.py",
    ], 91),
}


def main() -> int:
    cov = coverage.Coverage()
    cov.load()
    failed = False
    for area, (files, floor) in AREAS.items():
        pct = cov.report(include=files, file=io.StringIO())
        ok = pct >= floor
        failed |= not ok
        print(f"{'ok  ' if ok else 'FAIL'} {area}: {pct:.1f}% (floor {floor}%)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
