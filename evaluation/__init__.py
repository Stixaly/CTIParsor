"""Evaluation protocol (ADR-0060): gold data, metrics, runs, comparisons.

    python -m evaluation --help

Kept out of `tests/` (unit tests) and `pipeline/` (production): it runs the
production pipeline through `pipeline.orchestrator` exactly as the worker does
and scores what comes out.
"""
