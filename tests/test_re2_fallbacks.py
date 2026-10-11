"""The patterns that run without RE2's linear-time guarantee are known and measured.

`compile_pattern` (ADR-0049) falls back to stdlib `re` for a pattern RE2's
syntax refuses: lookaround, backreferences.  The October 2026 audit (B 8.2.5)
found the ReDoS guard missed Stage 2's key patterns that way; eight of Stage
2's did.  Five were rewritten for RE2 with their guards in code (IPv4, hash
blocks, the half-bracket defang, the SHA-1 and MD5 labels), with the same
output on AnnoCTR's 400 texts.  What is left is listed here: each has a match
that a filter after one RE2 pass cannot find (a lookahead the engine
backtracks over, a valid path inside a refused one), and each runs in linear
time on the inputs below.

A new pattern RE2 refuses fails `test_only_the_listed_patterns_fall_back`:
rewrite it for RE2, or measure it here and list it.
"""
from __future__ import annotations

import importlib
import pkgutil
import re
import time

import pytest

from pipeline import regex_safety

# (module, start of the pattern) — the pattern itself is long for the domain.
LISTED = {
    ("pipeline.stage2_extraction", r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}"),
    ("pipeline.stage2_extraction", r"(?<![\w./\\-])([A-Za-z0-9_][\w.-]*\.(?:"),
    ("pipeline.stage2_extraction", r"(?<!\w)/(?:bin|boot|dev|etc|home|lib(?:64)?|opt|proc"),
    ("pipeline.stage2c_ttp_semantic", r"(?<=[.!?])\s+|\n{1,}|;\s+"),
    ("pipeline.stage4_stix_mapping", r"(?<=[.!?])\s+|\n{2,}"),
    ("pipeline.ttp_retrieval", r"(?<=[.!?])\s+|\n+|;\s+"),
}

N = 50_000
BUDGET_S = 1.0     # 50,000 characters: a linear pattern takes milliseconds
ADVERSARIAL = {
    "dotted": "a." * N,
    "hyphenated": "a-" * N + "!",
    "one letter": "a" * N,
    "longest labels": ("a" * 61 + ".") * (N // 62),
    "extension, hyphen": "a.exe-" * (N // 6),
    "underscores": "_" * N + ".exe-",
    "dots": "." * N,
    "sentence ends": ". " * N,
    "newlines": "\n" * N,
    "semicolons": "; " * N,
    "one long blank": "." + " " * N + "x",
    "no-break spaces": ". " * N,
    "nested roots": "/tmp" * (N // 4),
    "refused roots": "x/tmp " * (N // 6),
}


def _import_every_module() -> None:
    import pipeline
    for mod in pkgutil.walk_packages(pipeline.__path__, "pipeline."):
        importlib.import_module(mod.name)
    for name in ("api.main", "api.routes.ingest", "api.routes.settings"):
        importlib.import_module(name)


def _listed(module: str, pattern: str) -> bool:
    return any(module == m and pattern.startswith(prefix) for m, prefix in LISTED)


def test_only_the_listed_patterns_fall_back():
    pytest.importorskip("re2")       # without re2 everything is `re`: nothing to pin
    _import_every_module()
    unlisted = sorted({(m, p[:80]) for m, p in regex_safety.FALLBACKS if not _listed(m, p)})
    assert unlisted == [], "RE2 refuses these patterns: rewrite them, or measure and list them"
    found = {(m, prefix) for m, prefix in LISTED for fm, fp in regex_safety.FALLBACKS
             if fm == m and fp.startswith(prefix)}
    assert found == LISTED, f"listed but now compiled by RE2, unlist: {sorted(LISTED - found)}"


def _fallback_patterns() -> list[tuple[str, re.Pattern]]:
    from pipeline import stage2_extraction as s2
    from pipeline import stage2c_ttp_semantic as s2c
    from pipeline import stage4_stix_mapping as s4
    from pipeline import ttp_retrieval

    def stdlib(compiled) -> re.Pattern:
        # Under re2, `.pattern` carries the flags inline ("(?i)…"); `re` reads them too.
        flags = compiled.flags if isinstance(compiled, re.Pattern) else 0
        return re.compile(compiled.pattern, flags)

    return [
        ("domain", stdlib(s2._DOMAIN_PATTERN)),
        ("bare filename", stdlib(s2._BARE_FILENAME_PATTERN)),
        ("Unix path", stdlib(s2._UNIX_PATH_PATTERN)),
        ("Stage 2c sentences", stdlib(s2c._SENTENCE_SPLIT_RE)),
        ("Stage 4 sentences", stdlib(s4._SENTENCE_SPLIT_RE)),
        ("retrieval passages", stdlib(ttp_retrieval._BOUNDARY)),
    ]


@pytest.mark.parametrize("name, rx", _fallback_patterns(), ids=lambda v: v if isinstance(v, str) else "")
def test_a_listed_pattern_is_linear_under_re(name, rx):
    for label, text in ADVERSARIAL.items():
        start = time.perf_counter()
        for _ in rx.finditer(text):
            pass
        rx.split(text)
        elapsed = time.perf_counter() - start
        assert elapsed < BUDGET_S, f"{name}: {elapsed:.2f} s on {label!r}"


def test_py_whitespace_is_what_python_calls_whitespace():
    """The class the RE2 rewrites use in place of `\\s` (regex_safety.PY_WHITESPACE)."""
    expected = {chr(c) for c in range(0x110000) if chr(c).isspace()}
    stdlib = re.compile("[" + regex_safety.PY_WHITESPACE + "]")
    assert {c for c in map(chr, range(0x110000)) if stdlib.fullmatch(c)} == expected
    re2 = pytest.importorskip("re2")
    rx = re2.compile("[" + regex_safety.PY_WHITESPACE + "]")
    assert {c for c in expected | {"a", "​"} if rx.fullmatch(c)} == expected
