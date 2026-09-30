"""Stage 1 — the PDF routing (text layer, per-page OCR, whole-document OCR),
PDF/DOCX metadata dates and the document anchor, driven through fakes so no
poppler, Tesseract or markitdown is needed."""
from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from pipeline import stage1_ingestion as s1

# ── Fakes ────────────────────────────────────────────────────────────────────

_PROSE = "APT29 deployed SUNBURST against SolarWinds customers in 2020. " * 3


class _Page:
    """What pdfplumber exposes of a page: glyphs, images, size, text."""

    def __init__(self, text: str = "", image_share: float = 0.0):
        self._text = text
        self.chars = [{"text": c} for c in text]
        self.width, self.height = 100, 100
        side = 100 * image_share ** 0.5
        self.images = [{"x0": 0, "x1": side, "top": 0, "bottom": side}] if image_share else []

    def extract_text(self):
        return self._text or None


class _Pdf:
    def __init__(self, pages, metadata=None):
        self.pages, self.metadata = pages, metadata

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _pdfplumber(monkeypatch, pages=(), metadata=None, fail: Exception | None = None):
    def open_(path):
        if fail is not None:
            raise fail
        return _Pdf(list(pages), metadata)

    monkeypatch.setattr(s1, "pdfplumber", SimpleNamespace(open=open_))


class _Image:
    closed = 0

    def __init__(self, label: str):
        self.label = label

    def close(self):
        _Image.closed += 1


@pytest.fixture()
def ocr(monkeypatch):
    """A working OCR stack: each rasterised page reads as "ocr p<N>"."""
    calls: list[tuple[int, int]] = []
    _Image.closed = 0

    def convert_from_path(path, dpi, first_page, last_page):
        calls.append((first_page, last_page))
        return [_Image(f"p{n}") for n in range(first_page, last_page + 1)]

    monkeypatch.setattr(s1, "_OCR_AVAILABLE", True)
    monkeypatch.setattr(s1, "convert_from_path", convert_from_path, raising=False)
    monkeypatch.setattr(s1, "pytesseract",
                        SimpleNamespace(image_to_string=lambda img, lang: f"ocr {img.label} [{lang}]"),
                        raising=False)
    return calls


# ── Page classification ──────────────────────────────────────────────────────

@pytest.mark.parametrize("page,scanned", [
    (_Page(_PROSE), False),                      # a text layer
    (_Page("", image_share=0.9), True),          # a full-page image, no text
    (_Page("Fig. 1", image_share=0.6), True),    # a caption on a scan
    (_Page(""), False),                          # blank page: nothing to OCR
    (_Page("", image_share=0.2), False),         # a logo on a divider page
])
def test_a_page_is_a_scan_only_when_an_image_covers_it(page, scanned):
    assert s1._page_is_scanned(page) is scanned


def test_the_whole_document_heuristic_samples_the_first_pages(monkeypatch):
    _pdfplumber(monkeypatch, [_Page(""), _Page("x"), _Page(""), _Page(_PROSE * 10)])
    assert s1._is_scanned_pdf("r.pdf") is True
    _pdfplumber(monkeypatch, [_Page(_PROSE)])
    assert s1._is_scanned_pdf("r.pdf") is False
    _pdfplumber(monkeypatch, [])
    assert s1._is_scanned_pdf("r.pdf") is False
    _pdfplumber(monkeypatch, fail=OSError("encrypted"))
    assert s1._is_scanned_pdf("r.pdf") is False


# ── _read_pdf routing ────────────────────────────────────────────────────────

def test_a_text_pdf_is_read_from_its_text_layer(monkeypatch, tmp_path):
    _pdfplumber(monkeypatch, [_Page(_PROSE), _Page(""), _Page("Page three.")])
    monkeypatch.setattr(s1, "_MARKITDOWN_AVAILABLE", False)
    assert s1._read_pdf(tmp_path / "r.pdf") == f"{_PROSE}\nPage three."


def test_a_mixed_pdf_ocrs_only_its_scanned_pages_in_place(monkeypatch, tmp_path, ocr):
    monkeypatch.setenv("OCR_LANG", "eng+fra")
    _pdfplumber(monkeypatch, [_Page(_PROSE), _Page("", image_share=1.0), _Page("The end." * 10)])

    text = s1._read_pdf(tmp_path / "r.pdf")

    assert text.split("\n") == [_PROSE, "ocr p2 [eng+fra]", "The end." * 10]
    assert ocr == [(2, 2)] and _Image.closed == 1


def test_a_scanned_page_that_ocr_cannot_read_keeps_its_text_layer(monkeypatch, tmp_path):
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)
    _pdfplumber(monkeypatch, [_Page(_PROSE), _Page("Fig. 2", image_share=1.0)])
    assert s1._read_pdf(tmp_path / "r.pdf") == f"{_PROSE}\nFig. 2"


def test_a_fully_scanned_pdf_is_ocrd_in_page_batches(monkeypatch, tmp_path, ocr):
    monkeypatch.delenv("OCR_LANG", raising=False)
    _pdfplumber(monkeypatch, [_Page("", image_share=1.0) for _ in range(23)])

    text = s1._read_pdf(tmp_path / "r.pdf")

    assert ocr == [(1, 10), (11, 20), (21, 23)]           # never the whole document at once
    assert text.split("\n")[0] == "ocr p1 [eng]" and len(text.split("\n")) == 23
    assert _Image.closed == 23


def test_an_unreadable_page_structure_falls_back_to_the_document_heuristic(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(s1, "_is_scanned_pdf", lambda p: seen.append("detect") or True)
    monkeypatch.setattr(s1, "_read_pdf_ocr", lambda p: "ocr text")
    monkeypatch.setattr(s1, "_read_pdf_text", lambda p: "layer text")
    _pdfplumber(monkeypatch, fail=ValueError("broken xref"))

    assert s1._read_pdf(tmp_path / "r.pdf") == "ocr text"
    monkeypatch.setattr(s1, "_is_scanned_pdf", lambda p: False)
    assert s1._read_pdf(tmp_path / "r.pdf") == "layer text"
    assert seen == ["detect"]


def test_ingest_routes_a_pdf_and_rejoins_hyphenated_breaks(monkeypatch, tmp_path):
    path = tmp_path / "r.PDF"
    path.write_bytes(b"%PDF-1.4")
    monkeypatch.setattr(s1, "_read_pdf", lambda p: "update.solar-\nwinds[.]com")
    assert s1.ingest(str(path)) == "update.solar-winds[.]com"


# ── OCR building blocks ──────────────────────────────────────────────────────

def test_without_ocr_libraries_nothing_is_ocrd(monkeypatch, tmp_path):
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)
    assert s1._read_pdf_ocr(tmp_path / "r.pdf") == ""
    assert s1._ocr_page(tmp_path / "r.pdf", 1) == ""


def test_ocr_skips_a_batch_that_cannot_be_rasterised(monkeypatch, tmp_path, ocr):
    _pdfplumber(monkeypatch, [_Page() for _ in range(12)])
    real = s1.convert_from_path

    def flaky(path, dpi, first_page, last_page):
        if first_page == 1:
            raise RuntimeError("poppler crashed")
        return real(path, dpi, first_page, last_page)

    monkeypatch.setattr(s1, "convert_from_path", flaky)
    assert s1._read_pdf_ocr(tmp_path / "r.pdf") == "ocr p11 [eng]\nocr p12 [eng]"


def test_ocr_of_a_pdf_that_cannot_be_opened_is_empty(monkeypatch, tmp_path, ocr):
    _pdfplumber(monkeypatch, fail=OSError("truncated"))
    assert s1._read_pdf_ocr(tmp_path / "r.pdf") == "" and ocr == []


def test_one_page_ocr_failures_are_empty_not_errors(monkeypatch, tmp_path, ocr):
    assert s1._ocr_page(tmp_path / "r.pdf", 4) == "ocr p4 [eng]"

    def no_tesseract(img, lang):
        raise OSError("tesseract is not installed")

    monkeypatch.setattr(s1, "pytesseract", SimpleNamespace(image_to_string=no_tesseract))
    assert s1._ocr_page(tmp_path / "r.pdf", 4) == ""
    assert _Image.closed == 2                                   # closed either way

    def no_poppler(*a, **kw):
        raise RuntimeError("pdftoppm not found")

    monkeypatch.setattr(s1, "convert_from_path", no_poppler)
    assert s1._ocr_page(tmp_path / "r.pdf", 4) == ""


def test_the_ocr_language_defaults_to_english(monkeypatch):
    monkeypatch.setenv("OCR_LANG", "   ")
    assert s1.ocr_lang() == "eng"
    monkeypatch.setenv("OCR_LANG", " deu ")
    assert s1.ocr_lang() == "deu"


# ── markitdown ───────────────────────────────────────────────────────────────

def _markitdown(monkeypatch, result: str | Exception):
    class MarkItDown:
        def convert(self, path):
            if isinstance(result, Exception):
                raise result
            return SimpleNamespace(text_content=result)

    monkeypatch.setattr(s1, "_MARKITDOWN_AVAILABLE", True)
    monkeypatch.setattr(s1, "MarkItDown", MarkItDown, raising=False)


def test_markitdown_output_is_preferred_when_substantial(monkeypatch, tmp_path):
    _markitdown(monkeypatch, "# Report\n\n| IoC | Type |\n" + _PROSE)
    _pdfplumber(monkeypatch, [_Page("plain")])
    assert s1._read_pdf_text(tmp_path / "r.pdf").startswith("# Report")


@pytest.mark.parametrize("result", ["tiny", RuntimeError("converter crashed")])
def test_a_thin_or_failed_markitdown_falls_back_to_pdfplumber(monkeypatch, tmp_path, result):
    _markitdown(monkeypatch, result)
    _pdfplumber(monkeypatch, [_Page("plain text")])
    assert s1._read_pdf_text(tmp_path / "r.pdf") == "plain text"


# ── Reference dates ──────────────────────────────────────────────────────────

def test_a_pdf_reference_date_comes_from_its_info_dictionary(monkeypatch, tmp_path):
    _pdfplumber(monkeypatch, metadata={"CreationDate": "D:20230315120000Z"})
    assert s1.extract_reference_date(str(tmp_path / "r.pdf")) == datetime(2023, 3, 15, 12, tzinfo=timezone.utc)
    _pdfplumber(monkeypatch, metadata={"CreationDate": "garbage", "ModDate": "D:20220101"})
    assert s1.extract_reference_date(str(tmp_path / "r.pdf")) == datetime(2022, 1, 1, tzinfo=timezone.utc)
    _pdfplumber(monkeypatch, metadata=None)
    assert s1.extract_reference_date(str(tmp_path / "r.pdf")) is None


def _docx_with_core(tmp_path, core: str | None):
    path = tmp_path / "r.docx"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/document.xml", "<w:document/>")
        if core is not None:
            zf.writestr("docProps/core.xml", core)
    return path


_CORE = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
         'xmlns:dcterms="http://purl.org/dc/terms/">{}</cp:coreProperties>')


@pytest.mark.parametrize("core,expected", [
    (None, None),                                                        # no core.xml at all
    (_CORE.format(""), None),                                            # no dcterms:created
    (_CORE.format("<dcterms:created> </dcterms:created>"), None),
    (_CORE.format("<dcterms:created>2021-06-01T08:00:00</dcterms:created>"),
     datetime(2021, 6, 1, 8, tzinfo=timezone.utc)),                      # naive → UTC
    (_CORE.format("<dcterms:created>1980-01-01T00:00:00Z</dcterms:created>"), None),   # implausible
])
def test_docx_creation_dates(tmp_path, core, expected):
    assert s1.extract_reference_date(str(_docx_with_core(tmp_path, core))) == expected


# ── The document anchor ──────────────────────────────────────────────────────

def test_a_capture_sidecar_supplies_publication_candidates(tmp_path):
    source = tmp_path / "job1.txt"
    source.write_text("Body without dates.")
    sidecar = s1.capture_meta_path(source)
    assert sidecar == tmp_path / "meta" / "job1.json"
    sidecar.parent.mkdir()
    sidecar.write_text(json.dumps({"candidates": [
        {"value": "2024-02-03", "source": "publication_meta", "kind": "published", "detail": "article:published_time"},
        "not a candidate",
    ]}))

    anchor = s1.extract_anchor(str(source), "Body without dates.")

    assert anchor is not None and (anchor.value, anchor.source) == ("2024-02-03", "publication_meta")


def test_an_unreadable_sidecar_is_ignored(tmp_path):
    source = tmp_path / "job1.txt"
    (tmp_path / "meta").mkdir()
    s1.capture_meta_path(source).write_text("{corrupt")
    assert s1.extract_anchor(str(source), "") is None


def test_an_html_file_anchors_on_its_own_metadata(tmp_path):
    page = tmp_path / "advisory.html"
    page.write_text(
        '<html><head><meta property="article:published_time" content="2023-11-20T10:00:00Z">'
        '<meta name="robots" content="noindex"><meta name="" content="x">'
        '<script type="application/ld+json">{"datePublished": "2023-11-19"}</script></head>'
        '<body><time itemprop="dateModified" datetime="2023-12-01">Dec 1</time><time>no prop</time>'
        "<p>Volt Typhoon used netsh.</p></body></html>"
    )
    anchor = s1.extract_anchor(str(page), s1.ingest(str(page)))
    assert anchor is not None and anchor.value.startswith("2023-11")


def test_html_candidates_read_meta_json_ld_and_time_tags():
    candidates = s1.html_publication_candidates(
        '<meta itemprop="datePublished" content="2022-05-04">'
        '<script type="application/ld+json">{"dateModified": "2022-06-01"}</script>'
        '<time itemprop="datePublished" datetime="2022-05-04T09:00:00Z"></time>'
    )
    assert {c["value"][:10] for c in candidates} >= {"2022-05-04", "2022-06-01"}


def test_no_path_and_no_dates_is_no_anchor():
    assert s1.extract_anchor(None, "") is None
