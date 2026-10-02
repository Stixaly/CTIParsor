"""OpenCTI's Snort rule parser, copied unmodified (ADR-0070).

Source: OpenCTI master of 2026-10-01,
``opencti-platform/opencti-graphql/src/python/runtime/snort/`` —
``snort_parser.py`` and ``snort_dicts.py``.
Copyright (c) 2021-2026 Filigran SAS.  Licensed under the Apache License,
Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).

OpenCTI refuses a Snort Indicator when ``Parser(pattern)`` raises
(``check_indicator.py``).  Stage 4 runs the same parser, so it never ships one
OpenCTI would refuse.  The parser is not on PyPI, hence the copy: to update it,
copy the two files again and leave them unchanged.
"""
from pipeline.detection.opencti_snort.snort_parser import Parser

__all__ = ["Parser"]
