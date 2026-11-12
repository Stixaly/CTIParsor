"""The internal exceptions of the API and the pipeline say when they are raised and what the
caller answers (#662).  The table "Internal errors and their answers" in docs/api.md names each of them."""
from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Module -> the exception classes it defines and that the table in docs/api.md documents.
DOCUMENTED = {
    "api.auth.store": ("AuthError", "UsernameTakenError", "LastAdminError"),
    "api.auth.config": ("AuthConfigError",),
    "api.auth.oidc": ("OidcError",),
    "api.migrate": ("MigrationError",),
    "pipeline.baseline_stix": ("BaselineError",),
    "api.worker": ("BundleInvalidError", "FinalizeOvertaken"),
    "pipeline.web_capture": ("CaptureError", "CaptureUnavailable"),
}

# A class whose name ends in Error but which is not an exception: a Pydantic response model.
NOT_EXCEPTIONS = {"FileError"}  # api/response_models/settings.py


@pytest.mark.parametrize(("module", "name"), [(m, n) for m, names in DOCUMENTED.items() for n in names])
def test_each_internal_exception_has_a_docstring(module, name):
    cls = getattr(importlib.import_module(module), name)
    assert issubclass(cls, BaseException)
    assert cls.__doc__ and cls.__doc__.strip(), f"{module}.{name} has no docstring"


def test_the_table_in_the_api_docs_names_each_documented_exception():
    docs = (ROOT / "docs" / "api.md").read_text(encoding="utf-8")
    section = docs.split("## Internal errors and their answers", 1)[1]
    missing = [n for names in DOCUMENTED.values() for n in names if f"`{n}`" not in section]
    assert missing == []


def test_every_error_class_of_the_api_and_the_pipeline_is_listed():
    """A new top-level `*Error` or `*Exception` class in api/ or pipeline/ fails this test until it is
    added to DOCUMENTED, with a docstring (the first test checks that)."""
    found: set[str] = set()
    for folder in ("api", "pipeline"):
        for path in (ROOT / folder).rglob("*.py"):
            if "opencti_snort" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name.endswith(("Error", "Exception")):
                    found.add(node.name)
    # CaptureUnavailable is a subclass of CaptureError and does not carry the suffix; it is listed above.
    listed = {n for names in DOCUMENTED.values() for n in names if n.endswith(("Error", "Exception"))}
    assert found - NOT_EXCEPTIONS == listed
