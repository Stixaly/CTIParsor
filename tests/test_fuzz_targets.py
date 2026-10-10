"""The fuzz targets (fuzz/, ADR-0081) run over their seed corpora.

The Fuzzing workflow runs them for minutes; this keeps them from rotting
between runs: a target that no longer imports, or whose invariant a seed
breaks, fails the ordinary test suite.
"""
import importlib
import pathlib
import sys

import pytest

pytest.importorskip("atheris")      # Linux x86_64 only (requirements/requirements-dev.txt)

FUZZ = pathlib.Path(__file__).resolve().parent.parent / "fuzz"
TARGETS = sorted(p.stem.removeprefix("fuzz_") for p in FUZZ.glob("fuzz_*.py"))


def _target(name: str):
    if str(FUZZ) not in sys.path:
        sys.path.insert(0, str(FUZZ))
    return importlib.import_module(f"fuzz_{name}").TestOneInput


def test_every_target_has_seeds():
    assert TARGETS
    for name in TARGETS:
        assert any((FUZZ / "corpus" / name).iterdir()), f"no seed for fuzz_{name}"


@pytest.mark.parametrize("name", TARGETS)
def test_target_accepts_its_seeds(name):
    run = _target(name)
    for seed in sorted((FUZZ / "corpus" / name).iterdir()):
        run(seed.read_bytes())
    run(b"")
