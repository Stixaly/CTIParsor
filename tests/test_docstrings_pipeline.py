"""Every module of pipeline/ says what it is, and every public function says what it does.

Checked on the source with the ast module, so nothing is imported and no
optional dependency is needed.  A module or a public function added without a
docstring fails here.  The vendored Snort parser (pipeline/detection/opencti_snort/)
is excluded: it is vendored code and has its own documentation in that folder.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "pipeline"
EXCLUDED_DIRS = frozenset({"opencti_snort", "__pycache__"})


def _pipeline_sources() -> list[Path]:
    return sorted(
        p for p in PIPELINE.rglob("*.py")
        if not (set(p.relative_to(PIPELINE).parts[:-1]) & EXCLUDED_DIRS)
    )


def _public_functions(tree: ast.Module) -> list[tuple[str, ast.AST]]:
    """Top-level public functions and public methods of top-level classes."""
    found: list[tuple[str, ast.AST]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            found.append((node.name, node))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            for child in node.body:
                if (isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and not child.name.startswith("_")):
                    found.append((f"{node.name}.{child.name}", child))
    return found


def test_the_scan_covers_the_pipeline():
    sources = _pipeline_sources()
    assert len(sources) > 50, "the pipeline/ scan found almost no modules: check the path"
    assert (PIPELINE / "orchestrator.py") in sources


def test_every_pipeline_module_has_a_module_docstring():
    missing = [
        str(p.relative_to(ROOT)).replace("\\", "/")
        for p in _pipeline_sources()
        if ast.get_docstring(ast.parse(p.read_text(encoding="utf-8"))) is None
    ]
    assert not missing, f"module without a docstring: {missing}"


def test_every_public_pipeline_function_has_a_docstring():
    missing: list[str] = []
    for path in _pipeline_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = str(path.relative_to(ROOT)).replace("\\", "/")
        for name, node in _public_functions(tree):
            if ast.get_docstring(node) is None:
                missing.append(f"{rel}:{node.lineno} {name}")
    assert not missing, f"public function without a docstring: {missing}"


def test_the_checks_notice_a_missing_docstring():
    """The two checks above are only as good as the ast walk: prove it sees a gap."""
    source = (
        "class Stage:\n"
        "    def run(self):\n"
        "        return 1\n"
        "    def _private(self):\n"
        "        return 2\n"
        "def public():\n"
        "    return 3\n"
    )
    tree = ast.parse(source)
    undocumented = [name for name, node in _public_functions(tree) if ast.get_docstring(node) is None]
    assert undocumented == ["Stage.run", "public"]
    assert ast.get_docstring(tree) is None
