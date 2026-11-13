"""Batch output names: every bundle of a `--input-dir` run gets its own path (#722).

Each run goes through the real `main.run_directory` and `main.run_pipeline`.
Only the backend (`main.run_document`, the pipeline) is replaced, by one that
writes through Stage 5's own `export_bundle`, so the file names and the
`_invalid` rule are the real ones.  Everything is written under tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import main
from pipeline.stage5_validation import INVALID, VALIDATED, ValidationResult, export_bundle


@pytest.fixture(autouse=True)
def _no_database_no_local_settings(monkeypatch):
    """No database and no variable of a developer's `.env` that changes how
    the run reads its options (main.py loads `.env` at import)."""
    import api.db as db

    monkeypatch.setattr(db, "DATABASE_URL", None)
    for var in ("PIPELINE_DISABLED_STAGES", "STIX_TLP", "TTP_MODE"):
        monkeypatch.delenv(var, raising=False)


class _Backend:
    """Stands in for `pipeline.orchestrator.run_document`.  It writes the bundle
    of each document as `{"source": <file name>}` through Stage 5's export, with
    the verdict given for that file (`validated` unless said otherwise)."""

    def __init__(self, verdicts: dict[str, str] | None = None, corrupted: tuple[str, ...] = ()):
        self.verdicts = verdicts or {}
        self.corrupted = set(corrupted)

    def __call__(self, document, options, hooks):
        name = document.original_filename
        if name in self.corrupted:
            raise RuntimeError(f"cannot parse {name}")
        status = self.verdicts.get(name, VALIDATED)
        export_bundle(json.dumps({"source": name}), document.output_path,
                      ValidationResult(status, [], []))
        return SimpleNamespace(entities=[], llm_result=None, ran=lambda stage: False,
                               ioc_coverage=None, bundle=None, stages=[],
                               valid=status != INVALID, validation=status)


def _batch(monkeypatch, tmp_path: Path, names: list[str], backend: _Backend) -> tuple[Path, Path]:
    src, out = tmp_path / "in", tmp_path / "out"
    src.mkdir()
    for name in names:
        (src / name).write_text(f"text of {name}", encoding="utf-8")
    monkeypatch.setattr(main, "run_document", backend)
    return src, out


def _bundles(out: Path) -> dict[str, str]:
    """The JSON files of `out`: file name -> the source it was written from."""
    return {p.name: json.loads(p.read_text(encoding="utf-8"))["source"]
            for p in sorted(out.glob("*.json"))}


def test_the_triplet_gives_three_bundles_each_from_its_source(monkeypatch, tmp_path, capsys):
    # #722: report_txt.md took the name report.txt had planned and overwrote it.
    src, out = _batch(monkeypatch, tmp_path, ["report.md", "report.txt", "report_txt.md"], _Backend())
    main.run_directory(str(src), str(out))
    assert _bundles(out) == {
        "report_md_bundle.json": "report.md",
        "report_txt_2_bundle.json": "report.txt",
        "report_txt_bundle.json": "report_txt.md",
    }
    summary = capsys.readouterr().out.split("RÉSUMÉ")[1]
    for name in _bundles(out):
        assert name in summary          # the summary prints the paths that were written


def test_case_variants_do_not_share_a_bundle_name(monkeypatch, tmp_path):
    # Two names that differ only by case are one name on a case-insensitive
    # filesystem (Windows, macOS); the plan treats them as a collision everywhere.
    src, out = _batch(monkeypatch, tmp_path, ["Report.md", "report.txt", "report_md.txt"], _Backend())
    main.run_directory(str(src), str(out))
    assert _bundles(out) == {
        "report_md_bundle.json": "report_md.txt",     # the simple name keeps its place
        "Report_md_2_bundle.json": "Report.md",
        "report_txt_bundle.json": "report.txt",
    }


def test_chained_collisions_each_get_a_free_name(monkeypatch, tmp_path):
    names = ["report.md", "report.txt", "report_txt.md", "report_txt_2.md"]
    src, out = _batch(monkeypatch, tmp_path, names, _Backend())
    main.run_directory(str(src), str(out))
    assert _bundles(out) == {
        "report_md_bundle.json": "report.md",
        "report_txt_3_bundle.json": "report.txt",
        "report_txt_bundle.json": "report_txt.md",
        "report_txt_2_bundle.json": "report_txt_2.md",
    }


def test_an_invalid_bundle_is_written_under_its_invalid_name_and_reported(monkeypatch, tmp_path, capsys):
    # Stage 5 writes `<name>_bundle_invalid.json` when the schemas refuse the
    # bundle: the summary must print that path, and the member is a failure.
    backend = _Backend(verdicts={"report.md": INVALID})
    src, out = _batch(monkeypatch, tmp_path, ["report.md", "report.txt"], backend)
    with pytest.raises(SystemExit) as exc:
        main.run_directory(str(src), str(out))
    assert exc.value.code == 1
    assert _bundles(out) == {
        "report_md_bundle_invalid.json": "report.md",
        "report_txt_bundle.json": "report.txt",
    }
    summary = capsys.readouterr().out.split("RÉSUMÉ")[1]
    assert "report_md_bundle_invalid.json" in summary


def test_a_rerun_replaces_its_own_bundle_and_touches_no_other_file(monkeypatch, tmp_path):
    # Documented policy (docs/pipeline.md): a bundle of an earlier batch under
    # a name this batch plans is replaced; a file this batch does not plan stays.
    src, out = _batch(monkeypatch, tmp_path, ["report.md", "report.txt"], _Backend())
    out.mkdir()
    (out / "report_md_bundle.json").write_text('{"source": "old"}', encoding="utf-8")
    (out / "keep_bundle.json").write_text('{"source": "keep"}', encoding="utf-8")
    main.run_directory(str(src), str(out))
    assert _bundles(out) == {
        "report_md_bundle.json": "report.md",
        "report_txt_bundle.json": "report.txt",
        "keep_bundle.json": "keep",
    }


def test_a_corrupted_input_does_not_stop_the_others(monkeypatch, tmp_path):
    backend = _Backend(corrupted=("a.txt",))
    src, out = _batch(monkeypatch, tmp_path, ["a.txt", "b.txt", "c.md"], backend)
    with pytest.raises(SystemExit) as exc:
        main.run_directory(str(src), str(out))
    assert exc.value.code == 1
    assert _bundles(out) == {"b_bundle.json": "b.txt", "c_bundle.json": "c.md"}


# ── The plan itself ──────────────────────────────────────────────────────────

def test_names_that_do_not_collide_are_unchanged(tmp_path):
    files = [tmp_path / "a.txt", tmp_path / "b.md", tmp_path / "c.pdf"]
    plan = main.plan_bundle_paths(files, tmp_path / "out")
    assert [p.name for p in plan] == ["a_bundle.json", "b_bundle.json", "c_bundle.json"]


@pytest.mark.parametrize("names", [
    ["report.md", "report.txt", "report_txt.md"],
    ["Report.md", "report.txt", "report_md.txt"],
    ["report.md", "report.txt", "report_txt.md", "report_txt_2.md"],
    ["a.md", "a.txt", "a_md.txt"],
    ["a.txt", "a.md", "a_bundle.txt", "a_bundle_invalid.md", "a_txt.md"],
    ["x.PDF", "x.pdf", "x_pdf.txt"],
])
def test_every_planned_name_and_its_invalid_name_are_distinct(tmp_path, names):
    # Case-insensitive: the names may not differ only by case.  The `_invalid`
    # name of one file never equals the planned name of another.
    files = [tmp_path / n for n in names]
    plan = main.plan_bundle_paths(files, tmp_path / "out")
    lowered = [p.name.lower() for p in plan]
    assert len(set(lowered)) == len(files)
    invalid = {p.with_stem(p.stem + "_invalid").name.lower() for p in plan}
    assert not invalid & set(lowered)
    assert all(p.parent == tmp_path / "out" for p in plan)
