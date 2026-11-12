"""The vendored Snort parser documents itself: module, class and public function docstrings, and a README.

Ast-based, so the modules are not imported. A new module or public function
without a docstring fails here.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SNORT_DIR = ROOT / "pipeline" / "detection" / "opencti_snort"
MODULES = sorted(SNORT_DIR.glob("*.py"))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_the_package_has_the_expected_modules():
    assert {p.name for p in MODULES} == {"__init__.py", "snort_dicts.py", "snort_parser.py"}


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_every_module_has_a_docstring(path: Path):
    assert ast.get_docstring(_tree(path)), f"{path.name} has no module docstring"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_every_public_class_and_function_has_a_docstring(path: Path):
    missing: list[str] = []
    for node in _tree(path).body:
        if isinstance(node, ast.ClassDef):
            if not node.name.startswith("_") and not ast.get_docstring(node):
                missing.append(node.name)
            members = [m for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            members = [node]
        else:
            continue
        for fn in members:
            if not fn.name.startswith("_") and not ast.get_docstring(fn):
                missing.append(fn.name)
    assert not missing, f"{path.name}: no docstring on {', '.join(missing)}"


def test_the_public_api_is_the_one_documented():
    # The 28 public functions of the two modules (the issue's count). A new public function
    # must be documented, and this count makes it visible when it is added.
    public: list[str] = []
    for path in MODULES:
        if path.name == "__init__.py":
            continue
        for node in _tree(path).body:
            if isinstance(node, ast.ClassDef):
                public += [
                    m.name
                    for m in node.body
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and not m.name.startswith("_")
                ]
    assert len(public) == 28


def test_the_readme_states_source_licence_and_local_patches():
    readme = (SNORT_DIR / "README.md").read_text(encoding="utf-8")
    for needle in ("OpenCTI", "Apache License 2.0", "Local changes", "Known limitations", "#422", "#624"):
        assert needle in readme, f"README.md does not mention {needle!r}"
