"""What every fuzz target shares (ADR-0081).

Imported first by each `fuzz_*.py`: the repository on the path.  When the
process *is* a fuzzer (`python fuzz/fuzz_<target>.py …`), also the heavy
models off and logging silenced — a fuzzer runs a target millions of times,
and a warning per input would bury the one line that matters.

Not when pytest imports a target for the seed test (tests/test_fuzz_targets.py):
`logging.disable` and the environment are process-wide, and the tests that
run after it would lose their log records and, in the model-tests job,
their heavy models.
"""
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

if os.path.basename(sys.argv[0]).startswith("fuzz_"):
    os.environ.setdefault("SKIP_HEAVY_MODELS", "1")
    logging.disable(logging.CRITICAL)
