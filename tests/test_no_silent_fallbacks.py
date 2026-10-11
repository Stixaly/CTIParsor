"""No broad exception handler in the shipped code falls back without a word.

The October 2026 audit (B 8.1.9) and D10 removed the `except Exception: pass`
blocks; ruff's S110/S112 keep `pass` and `continue` out.  A handler that
*returns a fallback* passed both: 23 did, among them the alias table read
(an unreadable gazetteer turned alias resolution off for the whole process),
the ATT&CK definitions of the Stage 3f prompt, the Report SDO rebuilt without
its optional fields and the embedded detection rule that vanished from the
bundle.  ruff's BLE001 flags every broad handler, 124 of them, most of which
log; it is not enforced.  This test is narrower: a broad handler must say
something (log, write the ledger or a record, use the exception, raise), or
state on its `except` line, in a `noqa` with a reason, why it says nothing.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_SHIPPED = ("api", "pipeline", "models", "main.py")

# Calls that put the failure somewhere a person or the record will see it.
_SAYING_RECEIVERS = {"logger", "log", "logging", "led", "ledger", "warnings", "stats"}
_SAYING_FUNCTIONS = {"print", "_record", "record", "bump", "record_call", "emit_progress",
                     "set_job_status", "_fail", "fail"}
_JUSTIFIED = re.compile(r"#\s*noqa:[^#]*\b(BLE001|S110|S112)\b.*—")


def _shipped_files() -> list[Path]:
    files: list[Path] = []
    for entry in _SHIPPED:
        path = _REPO / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files += sorted(path.rglob("*.py"))
    return files


def _is_broad(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return any(isinstance(t, ast.Name) and t.id in ("Exception", "BaseException") for t in types)


def _says_something(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            return True
        if handler.name and isinstance(node, ast.Name) and node.id == handler.name:
            return True
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _SAYING_FUNCTIONS:
                return True
            if isinstance(func, ast.Attribute):
                receiver = func.value
                if isinstance(receiver, ast.Name) and receiver.id in _SAYING_RECEIVERS:
                    return True
    return False


def silent_handlers() -> list[str]:
    found = []
    for path in _shipped_files():
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.ExceptHandler) or not _is_broad(node):
                continue
            if _says_something(node) or _JUSTIFIED.search(lines[node.lineno - 1]):
                continue
            found.append(f"{path.relative_to(_REPO).as_posix()}:{node.lineno}")
    return found


def test_every_broad_handler_says_something_or_why_not():
    assert silent_handlers() == [], (
        "a broad `except` returns or continues without a word: log the error, "
        "record it (ledger, stage report), or justify it on the except line "
        "with `# noqa: BLE001 — <why nothing is lost>`"
    )


def test_the_check_sees_a_silent_fallback(tmp_path, monkeypatch):
    """The test above fails on the pattern it exists for."""
    pkg = tmp_path / "pipeline"
    pkg.mkdir()
    (pkg / "m.py").write_text(
        "def f():\n"
        "    try:\n"
        "        return load()\n"
        "    except Exception:\n"
        "        return {}\n"
        "def g():\n"
        "    try:\n"
        "        return load()\n"
        "    except Exception as exc:\n"
        "        logger.warning(f'no data: {exc}')\n"
        "        return {}\n"
        "def h():\n"
        "    try:\n"
        "        return load()\n"
        "    except Exception:  # noqa: BLE001 — a cache miss, the caller loads it again\n"
        "        return {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "_REPO", tmp_path)
    assert silent_handlers() == ["pipeline/m.py:4"]
