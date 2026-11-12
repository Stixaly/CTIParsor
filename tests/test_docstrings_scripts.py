"""Every script, model and evaluation module has a module docstring (#650, #652).

Every ``cmd_*`` command of ``evaluation/__main__.py`` has a docstring too. The
checks read the source with ``ast``: no module is imported, so a script with
side effects at import time is not run.
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
