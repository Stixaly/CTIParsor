"""Fuzz the date reading of ADR-0063 on report text (ADR-0081).

normalize() reads a quoted time expression, locate() finds it in its chunk,
header_candidates() looks for a publication date in the first lines.  All
three take text from the report; none may raise, and libFuzzer's -timeout
catches an input that makes one slow (the quarter regexes were quadratic).

    python fuzz/fuzz_dates.py -max_total_time=60 -timeout=10 <corpus dir>
"""
import sys

import _harness  # noqa: F401  (path, quiet logs, no heavy models)
import atheris

with atheris.instrument_imports():
    from pipeline.temporal import ROLES, Anchor, header_candidates, locate, normalize

ANCHOR = Anchor(value="2024-03-12", source="publication_meta")


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    role = fdp.PickValueInList([*ROLES, None])
    anchor = ANCHOR if fdp.ConsumeBool() else None
    expression = fdp.ConsumeUnicodeNoSurrogates(256)
    chunk = fdp.ConsumeUnicodeNoSurrogates(4096)
    normalize(expression, role=role, anchor=anchor)
    locate(expression, chunk)
    header_candidates(chunk)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
