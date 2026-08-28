"""Geometric triage must survive a tall-sheet capture, and Stage 1f must find its PDF."""
from __future__ import annotations

import types

from api.worker import _figure_source_pdf
from pipeline.stage1f_figures import (
    MIN_FIGURE_AREA_PT2,
    find_figures,
)

A4_W, A4_H = 595.0, 842.0
TALL_W, TALL_H = 960.0, 14400.0


def _img(w: float, h: float, x0: float = 50.0, top: float = 100.0) -> dict:
    """One pdfplumber image dict of the given size."""
    return {"x0": x0, "x1": x0 + w, "top": top, "bottom": top + h}


class _Page:
    """A pdfplumber page: only width, height and images are read."""

    def __init__(self, width: float, height: float, images: list[dict]) -> None:
        self.width = width
        self.height = height
        self.images = images


class _PDF:
    """A pdfplumber document usable as a context manager."""

    def __init__(self, pages: list[_Page]) -> None:
        self.pages = pages

    def __enter__(self) -> _PDF:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _fake_pdfplumber(pages: list[_Page]):
    """A stub module whose `open` ignores its argument and yields these pages."""
    return types.SimpleNamespace(open=lambda path: _PDF(pages))


def test_tall_sheet_keeps_a_half_page_diagram(monkeypatch):
    """One of the six diagrams the SilkParasite capture was losing."""
    page = _Page(TALL_W, TALL_H, [_img(576, 384)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert len(find_figures("x.pdf")) == 1


def test_tall_sheet_still_drops_an_icon(monkeypatch):
    """The largest icon measured on the capture must still be rejected."""
    page = _Page(TALL_W, TALL_H, [_img(112, 150)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_tall_sheet_drops_a_tiny_image(monkeypatch):
    """A 60x60 image is far below both thresholds."""
    page = _Page(TALL_W, TALL_H, [_img(60, 60)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_normal_page_behaviour_is_unchanged_for_a_small_image(monkeypatch):
    """The absolute floor is an OR; it must not admit anything new on a normal page."""
    page = _Page(A4_W, A4_H, [_img(80, 80)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_normal_page_keeps_a_real_figure(monkeypatch):
    """A 400x300 figure on A4 is well above both thresholds."""
    page = _Page(A4_W, A4_H, [_img(400, 300)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert len(find_figures("x.pdf")) == 1


def test_area_floor_matches_the_documented_value():
    """The floor separates the icon population from the real-diagram population."""
    assert 112 * 150 < MIN_FIGURE_AREA_PT2 < 450 * 253


def test_side_and_aspect_guards_still_apply_on_a_tall_sheet(monkeypatch):
    """The area floor must not bypass the minimum-side or aspect-ratio guards."""
    page = _Page(TALL_W, TALL_H, [_img(40, 2000), _img(3000, 100)])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_figure_source_pdf_returns_an_uploaded_pdf(tmp_path):
    """An ingested .pdf is returned as-is."""
    p = tmp_path / "job.pdf"
    p.write_bytes(b"%PDF-1.4")
    assert _figure_source_pdf(str(p)) == p


def test_figure_source_pdf_finds_the_capture_archive_beside_the_text(tmp_path):
    """URL capture: pipeline ingests the .txt, figures live in the sibling .pdf."""
    txt = tmp_path / "job.txt"
    txt.write_text("dom")
    pdf = tmp_path / "job.pdf"
    pdf.write_bytes(b"%PDF-1.4")
    assert _figure_source_pdf(str(txt)) == pdf


def test_figure_source_pdf_returns_none_for_a_lone_text_file(tmp_path):
    """A .txt with no sibling .pdf yields None."""
    txt = tmp_path / "job.txt"
    txt.write_text("dom")
    assert _figure_source_pdf(str(txt)) is None


def test_figure_source_pdf_returns_none_for_a_missing_pdf(tmp_path):
    """A .pdf path that does not exist yields None."""
    p = tmp_path / "job.pdf"
    assert _figure_source_pdf(str(p)) is None


def test_figure_source_pdf_ignores_a_partial_capture(tmp_path):
    """A .part file is an interrupted render and must not be treated as the archive."""
    (tmp_path / "job.pdf.part").write_bytes(b"partial")
    assert _figure_source_pdf(str(tmp_path / "job.txt")) is None
