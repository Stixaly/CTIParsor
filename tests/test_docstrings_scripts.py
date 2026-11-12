"""Every script, model and evaluation module has a module docstring (#650, #652).

Every ``cmd_*`` command of ``evaluation/__main__.py`` has a docstring too, and
so does every public top-level function of the four scripts of #650 item 3.
The checks read the source with ``ast``: no module is imported, so a script
with side effects at import time is not run.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATTERNS = ("scripts/*.py", "models/*.py", "evaluation/*.py")
EVALUATION_MAIN = ROOT / "evaluation" / "__main__.py"


def _modules() -> list[Path]:
    found: list[Path] = []
    for pattern in MODULE_PATTERNS:
        found.extend(sorted(ROOT.glob(pattern)))
    return found


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


MODULES = _modules()


def test_the_glob_finds_the_modules() -> None:
    # Guards against the test passing because the patterns matched nothing.
    assert len(MODULES) > 80, f"only {len(MODULES)} modules matched {MODULE_PATTERNS}"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_module_has_a_docstring(path: Path) -> None:
    rel = path.relative_to(ROOT).as_posix()
    assert ast.get_docstring(_tree(path)), f"{rel} has no module docstring"


def test_every_cmd_function_has_a_docstring() -> None:
    commands = [
        node
        for node in _tree(EVALUATION_MAIN).body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("cmd_")
    ]
    # The file defines 15 commands; a smaller count means the test is looking elsewhere.
    assert len(commands) >= 15, f"found {len(commands)} cmd_ functions in evaluation/__main__.py"
    missing = [node.name for node in commands if not ast.get_docstring(node)]
    assert not missing, f"cmd_ functions without a docstring: {missing}"


# The four scripts of #650 item 3. Every public top-level function (no leading
# underscore) of each must have a docstring; a new public function without one
# fails here.
ITEM3_SCRIPTS = (
    "scripts/check_model_journey.py",
    "scripts/check_failure_recipe.py",
    "scripts/opencti_import_check.py",
    "scripts/measure_ner_precision.py",
)


@pytest.mark.parametrize("rel", ITEM3_SCRIPTS)
def test_public_functions_have_a_docstring(rel: str) -> None:
    tree = _tree(ROOT / rel)
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    ]
    assert functions, f"no public function found in {rel}: the test is looking at the wrong file"
    missing = [node.name for node in functions if not ast.get_docstring(node)]
    assert not missing, f"{rel}: public functions without a docstring: {missing}"
