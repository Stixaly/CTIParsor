"""Docstrings of api/ (issues #649 and #656), checked on the source text with ast.

Three rules, all read from the code and not imported:
- every api/**/*.py module has a module docstring;
- every function in api/ whose name does not start with an underscore has a docstring, at any depth
  (top-level functions, methods of any class, and nested functions), which is how issue #649 counts them;
- every class of api/response_models/ has a docstring: the docstring is the description of the model.

A function that is still undocumented can be listed in KNOWN_GAPS, with the reason. The test fails when
a listed gap is fixed, so the list does not go stale.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"
RESPONSE_MODELS = API / "response_models"

# (file, function name) pairs that have no docstring yet, with the reason they are left alone.
KNOWN_GAPS = {
    ("api/auth/oidc.py", "reset_cache"): "owned by the OIDC change (nonce fix, issue #646); to be documented there",
    ("api/auth/oidc.py", "load"): "two nested functions of the OIDC change (issue #646); to be documented there",
}


def _api_files():
    return sorted(p for p in API.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path):
    return path.relative_to(ROOT).as_posix()


def _undocumented_functions(source):
    """(line, name) of each function whose name does not start with an underscore and that has no docstring."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            if ast.get_docstring(node) is None:
                found.append((node.lineno, node.name))
    return found


def _undocumented_classes(source):
    """(line, name) of each top-level class that has no docstring."""
    return [(node.lineno, node.name) for node in ast.parse(source).body
            if isinstance(node, ast.ClassDef) and ast.get_docstring(node) is None]


def test_every_api_module_has_a_module_docstring():
    missing = [_rel(p) for p in _api_files()
               if ast.get_docstring(ast.parse(p.read_text(encoding="utf-8"))) is None]
    assert not missing, f"modules without a docstring: {missing}"


def test_every_public_function_in_api_has_a_docstring():
    missing = []
    for path in _api_files():
        rel = _rel(path)
        for line, name in _undocumented_functions(path.read_text(encoding="utf-8")):
            if (rel, name) not in KNOWN_GAPS:
                missing.append(f"{rel}:{line} {name}")
    assert not missing, f"public functions without a docstring: {missing}"


def test_known_gaps_are_still_gaps():
    still = set()
    for path in _api_files():
        rel = _rel(path)
        for _line, name in _undocumented_functions(path.read_text(encoding="utf-8")):
            still.add((rel, name))
    fixed = sorted(gap for gap in KNOWN_GAPS if gap not in still)
    assert not fixed, f"documented now, remove from KNOWN_GAPS: {fixed}"


def test_every_response_model_class_has_a_docstring():
    missing = []
    for path in sorted(RESPONSE_MODELS.glob("*.py")):
        for line, name in _undocumented_classes(path.read_text(encoding="utf-8")):
            missing.append(f"{_rel(path)}:{line} {name}")
    assert not missing, f"response model classes without a docstring: {missing}"


def test_checker_reports_what_it_is_meant_to_report():
    source = (
        "def public(): pass\n"
        "def _private(): pass\n"
        "class Holder:\n"
        "    def method(self): pass\n"
        "    def _hidden(self): pass\n"
        "    def documented(self):\n"
        "        '''Done.'''\n"
        "def outer():\n"
        "    '''Outer.'''\n"
        "    def inner():\n"
        "        pass\n"
    )
    names = [name for _line, name in _undocumented_functions(source)]
    assert sorted(names) == ["inner", "method", "public"]
    assert _undocumented_classes("class A:\n    '''doc'''\nclass B:\n    pass\n") == [(3, "B")]
