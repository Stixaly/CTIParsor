"""What every fuzz target shares (ADR-0081).

Imported first by each `fuzz_*.py`: the repository on the path, the heavy
models off, logging quiet — a fuzzer runs a target millions of times, and a
warning per input would bury the one line that matters.
"""
import logging
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
os.environ.setdefault("SKIP_HEAVY_MODELS", "1")
logging.disable(logging.CRITICAL)
