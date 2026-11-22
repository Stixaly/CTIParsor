"""Issue #982 (point 1): the OCR summary says why a scanned PDF came back empty
and how many of its pages were not read.  pdfplumber, pdf2image and Tesseract
are replaced by fakes, so no binary is needed."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from pipeline import stage1_ingestion as s1


class _Pdf:
    def __init__(self, pages: int):
        self.pages = [None] * pages

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _pdfplumber(monkeypatch, pages: int = 0, fail: Exception | None = None):
    def open_(path):
        if fail is not None:
            raise fail
        return _Pdf(pages)

    monkeypatch.setattr(s1, "pdfplumber", SimpleNamespace(open=open_))


@pytest.fixture()
def ocr(monkeypatch):
    """A working OCR stack: each rasterised page reads as "ocr p<N>"."""
    monkeypatch.setenv("OCR_LANG", "eng")
    monkeypatch.setattr(s1, "_ocr_langs_in_use", {})
    monkeypatch.setattr(s1, "_installed_cache", {})
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", True)

    def convert_from_path(path, dpi, first_page, last_page):
        return [SimpleNamespace(label=f"p{n}", close=lambda: None)
                for n in range(first_page, last_page + 1)]

    monkeypatch.setattr(s1, "convert_from_path", convert_from_path, raising=False)
    monkeypatch.setattr(s1, "pytesseract", SimpleNamespace(
        image_to_string=lambda img, lang: f"ocr {img.label} [{lang}]",
        get_languages=lambda config="": ["eng"]), raising=False)


def test_ocr_available_reports_the_imports_and_the_binaries(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)
    assert s1.ocr_available() is False
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", True)
    assert s1.ocr_available() is True
    monkeypatch.setattr(shutil, "which", lambda name: None if name == "tesseract" else f"/usr/bin/{name}")
    assert s1.ocr_available() is False


def test_without_ocr_libraries_the_summary_says_why_the_text_is_empty(monkeypatch, tmp_path):
    _pdfplumber(monkeypatch, pages=3)
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)

    with s1.ocr_summary() as summary:
        text = s1._read_pdf_ocr(tmp_path / "r.pdf")

    assert text == ""
    assert summary == {"pages": 0, "pages_failed": 3, "pages_total": 3,
                       "unavailable": "OCR libraries not installed (pytesseract, pdf2image)"}


def test_a_pdf_that_cannot_be_opened_for_ocr_says_why(monkeypatch, tmp_path):
    _pdfplumber(monkeypatch, fail=OSError("truncated"))

    with s1.ocr_summary() as summary:
        assert s1._read_pdf_ocr(tmp_path / "r.pdf") == ""

    assert summary["unavailable"] == "PDF could not be opened for OCR: truncated"
    assert "pages_total" not in summary


def test_a_batch_that_cannot_be_rasterised_counts_its_pages_as_failed(monkeypatch, tmp_path, ocr):
    _pdfplumber(monkeypatch, pages=12)
    real = s1.convert_from_path

    def flaky(path, dpi, first_page, last_page):
        if first_page == 1:
            raise RuntimeError("poppler crashed")
        return real(path, dpi, first_page, last_page)

    monkeypatch.setattr(s1, "convert_from_path", flaky)

    with s1.ocr_summary() as summary:
        text = s1._read_pdf_ocr(tmp_path / "r.pdf")

    assert text == "ocr p11 [eng]\nocr p12 [eng]"
    assert summary == {"pages": 2, "pages_failed": 10, "pages_total": 12,
                       "languages": {"eng": 2}}
    assert "unavailable" not in summary


def test_a_page_tesseract_cannot_read_is_failed_and_the_others_are_counted(monkeypatch, tmp_path, ocr):
    _pdfplumber(monkeypatch, pages=3)

    def flaky(img, lang):
        if img.label == "p2":
            raise RuntimeError("tesseract crashed")
        return f"ocr {img.label} [{lang}]"

    monkeypatch.setattr(s1, "pytesseract", SimpleNamespace(image_to_string=flaky,
                                                          get_languages=lambda config="": ["eng"]))

    with s1.ocr_summary() as summary:
        text = s1._read_pdf_ocr(tmp_path / "r.pdf")

    assert text == "ocr p1 [eng]\nocr p3 [eng]"
    assert summary["pages"] == 2
    assert summary["pages_failed"] == 1
    assert summary["pages_total"] == 3
    assert summary["languages"] == {"eng": 2}
    assert "unavailable" not in summary


def test_a_complete_ocr_has_no_failed_page_and_no_reason(monkeypatch, tmp_path, ocr):
    _pdfplumber(monkeypatch, pages=3)

    with s1.ocr_summary() as summary:
        text = s1._read_pdf_ocr(tmp_path / "r.pdf")

    assert text == "ocr p1 [eng]\nocr p2 [eng]\nocr p3 [eng]"
    assert summary["pages"] == 3
    assert summary["pages_failed"] == 0
    assert summary["pages_total"] == 3
    assert "unavailable" not in summary


def test_a_page_of_a_mixed_document_that_cannot_be_ocrd_is_failed(monkeypatch, tmp_path):
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)

    with s1.ocr_summary() as summary:
        assert s1._ocr_page(tmp_path / "r.pdf", 2) == ""

    assert summary == {"pages": 0, "pages_failed": 1,
                       "unavailable": "OCR libraries not installed (pytesseract, pdf2image)"}
