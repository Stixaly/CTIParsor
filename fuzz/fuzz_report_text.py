"""Fuzz Stage 2 on report text, the attacker's input (ADR-0081).

refang() rewrites defanged IoCs; extract_entities() runs every regex
extractor.  Report text is whatever the report's author wrote: neither may
raise, and libFuzzer's -timeout catches an input that makes either slow (the
ReDoS of ADR-0049 and of the CodeQL triage).

    python fuzz/fuzz_report_text.py -max_total_time=60 -timeout=10 <corpus dir>
"""
import sys

import _harness  # noqa: F401  (path, quiet logs, no heavy models)
import atheris

with atheris.instrument_imports():
    from pipeline.stage2_extraction import extract_entities, refang


def TestOneInput(data: bytes) -> None:
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    assert isinstance(refang(text), str)
    for entity in extract_entities(text):
        assert entity.value, f"empty {entity.entity_type} entity"


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
