"""Fuzz the enclosure of report text in LLM prompts (ADR-0074, ADR-0081).

fit_report() puts the report between two marker lines carrying a nonce
derived from the text.  Whatever the report contains, the prompt must hold
each marker exactly once, in order, with the report — cut to fit, never
altered — between them, and the instruction that follows it intact: a report
that could close its block early, or push the question out, would be a
prompt injection.

    python fuzz/fuzz_spotlight.py -max_total_time=60 -timeout=10 <corpus dir>
"""
import hashlib
import sys

import _harness  # noqa: F401  (path, quiet logs, no heavy models)
import atheris

with atheris.instrument_imports():
    from pipeline.llm_parse import fit_report

TEMPLATE = "Extract the indicators from this report.\n{text}\nAnswer with JSON only."
QUESTION = "Answer with JSON only."


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    max_chars = fdp.PickValueInList([None, 80, 400, 4000])
    text = fdp.ConsumeUnicodeNoSurrogates(len(data))
    prompt, rule = fit_report(TEMPLATE, text, max_chars)

    nonce = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    opening, closing = f"<<<REPORT {nonce}>>>", f"<<<END REPORT {nonce}>>>"
    assert prompt.count(opening) == 1 and prompt.count(closing) == 1, "a marker is repeated"
    start, end = prompt.index(opening), prompt.index(closing)
    assert start < end, "the block closes before it opens"
    enclosed = prompt[start + len(opening) + 1:end - 1]
    assert text.startswith(enclosed), "the report was altered, not only cut"
    assert prompt.endswith(QUESTION), "the instruction after the report was lost"
    assert opening in rule and closing in rule


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
