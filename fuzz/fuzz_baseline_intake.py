"""Fuzz the reading of a baseline STIX bundle and of the patterns in it (ADR-0090).

The first byte picks the entry point, the rest is the input:
  0 intake of a bundle as /inspect reads it (preview), 1 the keys of a STIX
  pattern, 2 intake as the creation of a job reads it (no preview), 3 the
  preview without the JSON-schema validation (fast: validate_bundle costs
  milliseconds an input, which mode 0 and 2 pay).
`intake` answers with an index or with BaselineError, and never raises
anything else: the analyst's file is hostile input, and the 400 it earns must
not become a 500.  `pattern_keys` never raises.  libFuzzer catches a crash, a
hang (-timeout) and a memory blow-up (-rss_limit_mb), such as a deep JSON or a
pattern of thousands of terms.

    python fuzz/fuzz_baseline_intake.py -max_total_time=60 -timeout=10 <corpus dir>
"""
import sys

import _harness  # noqa: F401  (path, quiet logs, no heavy models)
import atheris

with atheris.instrument_imports():
    from pipeline.baseline_stix import BaselineError, BaselineIndex, intake, pattern_keys

EXCLUSION_FIELDS = {"id", "type", "reason", "detail"}


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    mode, payload = data[0] % 4, data[1:]
    if mode == 1:
        for keys in pattern_keys(payload.decode("utf-8", errors="replace")):
            assert all(isinstance(k, tuple) and all(isinstance(part, str) for part in k) for k in keys)
        return
    try:
        index, summary, _ = intake(payload, preview=mode in (0, 3), validate=mode != 3)
    except BaselineError:
        return
    for excluded in summary.excluded:
        assert set(excluded) == EXCLUSION_FIELDS
        assert all(isinstance(value, str) for value in excluded.values())
    if index is None:
        assert mode in (0, 3) and summary.needs_report_choice
    else:
        assert not summary.needs_report_choice
        assert BaselineIndex.from_json(index.to_json()) == index


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
