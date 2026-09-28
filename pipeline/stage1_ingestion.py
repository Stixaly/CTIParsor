import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import defusedxml.ElementTree as ET
import docx
import pdfplumber
from bs4 import BeautifulSoup

# Initialize logging
from api.logging_config import get_logger
from pipeline.regex_safety import compile_pattern

logger = get_logger(__name__)

# pdfminer (used internally by pdfplumber) emits WARNING-level messages for PDFs
# with incomplete font descriptors ("Could not get FontBBox…").  These are benign
# — the text is still extracted correctly — but they spam the server log.
logging.getLogger("pdfminer").setLevel(logging.ERROR)

# Matches an alphanumeric token ending with a hyphen immediately before a line
# break (single or double \n).  PDFs break long tokens — especially domain names
# and paths — at column/page boundaries: "git-\n\ntanstack[.]com" must become
# "git-tanstack[.]com" BEFORE defanging so the full domain is preserved.
_HYPHEN_LINEBREAK = compile_pattern(r"([A-Za-z0-9])-[ \t]*\n\n?[ \t]*([A-Za-z0-9])")


def _join_hyphen_linebreaks(text: str) -> str:
    """
    Rejoin words/tokens split by a soft hyphen across a PDF line or page break.

    Examples:
        "git-\\n\\ntanstack[.]com"  →  "git-tanstack[.]com"
        "trans-\\nformers.pyz"      →  "trans-formers.pyz"

    Applied during ingestion so chunks never contain split tokens.
    """
    return _HYPHEN_LINEBREAK.sub(r"\1-\2", text)

try:
    from markitdown import MarkItDown
    _MARKITDOWN_AVAILABLE = True
except Exception:  # ImportError, ModuleNotFoundError, native-lib failures
    _MARKITDOWN_AVAILABLE = False

try:
    import pytesseract
    from pdf2image import convert_from_path
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False

# Minimum average chars per page to consider a PDF text-based (not scanned)
_MIN_CHARS_PER_PAGE = 50
_DETECTION_SAMPLE_PAGES = 3


def ingest(file_path: str) -> str:
    """
    Lit un fichier CTI (PDF, DOCX, HTML, TXT) et retourne le texte brut normalisé.

    Args:
        file_path: chemin vers le fichier rapport

    Returns:
        Le texte extrait, nettoyé des espaces superflus

    Raises:
        ValueError: si le format n'est pas supporté
        FileNotFoundError: si le fichier n'existe pas
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    suffix = path.suffix.lower()

    if suffix == ".pdf":
        raw = _read_pdf(path)
    elif suffix == ".docx":
        raw = _read_docx(path)
    elif suffix in (".html", ".htm"):
        raw = _read_html(path)
    elif suffix in (".txt", ".md"):
        raw = path.read_text(encoding="utf-8", errors="replace")
    else:
        raise ValueError(f"Format non supporté : {suffix}. Formats acceptés : pdf, docx, html, htm, txt, md")

    # Rejoin tokens split by PDF soft-hyphen line wraps before chunking
    return _join_hyphen_linebreaks(raw)


# PDF Info dictionary date string (ISO 32000-1:2008 7.9.4), e.g.
# "D:20230315120000+00'00'" or "D:20230315203811Z00'00'". The "D:" prefix is
# occasionally missing on non-compliant producers, so it is optional here;
# everything after the seconds field (timezone offset) is ignored — a
# reference anchor for resolving relative dates only needs day precision.
_PDF_DATE_RE = compile_pattern(r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?")


def _plausible_reference_year(dt: datetime) -> bool:
    return 1990 <= dt.year <= datetime.now(timezone.utc).year + 1


def _parse_pdf_date(raw: str | None) -> datetime | None:
    """Parse a PDF Info dictionary CreationDate/ModDate string into a UTC
    datetime, or None if absent/unparseable/implausible. Never raises."""
    if not raw:
        return None
    m = _PDF_DATE_RE.match(raw.strip())
    if not m:
        return None
    year, month, day, hour, minute, second = m.groups()
    try:
        dt = datetime(
            int(year), int(month or "01"), int(day or "01"),
            int(hour or "00"), int(minute or "00"), int(second or "00"),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    return dt if _plausible_reference_year(dt) else None


_DOCX_CORE_NS = {"dcterms": "http://purl.org/dc/terms/"}


def _docx_created_date(path: Path) -> datetime | None:
    """Read docProps/core.xml's dcterms:created straight out of the .docx zip.

    ingest() already constructs a full python-docx Document to read the body
    text; doing that a second time here just to reach one metadata field
    (python-docx's own core_properties.created reads this exact element)
    doubles a non-trivial parse for every DOCX job. A .docx is a zip archive
    with the creation timestamp in its own small XML part, independent of the
    body -- reading that part directly avoids the second full parse.
    """
    with zipfile.ZipFile(path) as zf:
        try:
            data = zf.read("docProps/core.xml")
        except KeyError:
            return None
    el = ET.fromstring(data).find("dcterms:created", _DOCX_CORE_NS)
    if el is None or not el.text:
        return None
    text = el.text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def extract_reference_date(file_path: str) -> datetime | None:
    """
    Best-effort "document creation time" for a report — the file's own
    metadata timestamp, used by Stage 3 to anchor an LLM's resolution of
    RELATIVE relationship dates ("since last month"). This mirrors the
    standard TimeML/TIMEX3 practice of resolving relative expressions against
    a document creation time (DCT) rather than leaving them unresolved.

    Caveat, confirmed on real samples in this repo: file metadata reflects
    when the FILE was produced, not necessarily when the underlying report
    was first published — a web article "printed to PDF" carries the print
    timestamp, which can be months or years after the article's own date.
    This is why Stage 3's prompt treats the value as a best-effort anchor,
    not ground truth, and stays conservative (omits the date) when resolving
    against it would be a guess rather than a straightforward calculation.

    Returns None for formats with no reliable creation-date metadata (HTML,
    TXT, MD) or when extraction fails for any reason — Stage 3 already
    degrades gracefully to "explicit dates only" in that case.
    """
    path = Path(file_path)
    suffix = path.suffix.lower()
    try:
        if suffix == ".pdf":
            with pdfplumber.open(path) as pdf:
                meta = pdf.metadata or {}
            return (
                _parse_pdf_date(meta.get("CreationDate"))
                or _parse_pdf_date(meta.get("ModDate"))
            )
        if suffix == ".docx":
            created = _docx_created_date(path)
            return created if created and _plausible_reference_year(created) else None
    except Exception as exc:
        # Deliberately still returns None either way (see the docstring), but
        # a systematic failure here (a pdfplumber/python-docx version bump
        # breaking metadata access, a permissions error) should leave a trail
        # -- every sibling broad-except added this month logs before
        # swallowing; this one silently did not.
        logger.debug(f"[reference date] {suffix} metadata extraction failed for {file_path}: {exc}")
        return None
    return None


def capture_meta_path(source: Path) -> Path:
    """Where a URL capture leaves the page's publication metadata for the job
    whose source is `source` (ADR-0063 §4).  A subdirectory, so the
    ``uploads/{job_id}.*`` globs that find a job's source file never see it."""
    return source.parent / "meta" / f"{source.stem}.json"


def html_publication_candidates(html: str) -> list[dict]:
    """Publication-date candidates from an HTML page's own metadata:
    ``<meta>`` names and properties, JSON-LD ``datePublished`` /
    ``dateModified``, and ``<time itemprop=…>``.  ``html_to_text`` drops all of
    it, so it is read here, from the file, before the markup is gone."""
    from pipeline.temporal import publication_candidates

    soup = BeautifulSoup(html, "html.parser")
    metas: list[tuple[str, str]] = []
    for tag in soup.find_all("meta"):
        key = tag.get("property") or tag.get("name") or tag.get("itemprop") or ""
        content = tag.get("content") or ""
        if isinstance(key, str) and isinstance(content, str) and key and content:
            metas.append((key, content))
    jsonld = [s.get_text() for s in soup.find_all("script", attrs={"type": "application/ld+json"})]
    times: list[tuple[str, str]] = []
    for tag in soup.find_all("time"):
        prop, value = tag.get("itemprop"), tag.get("datetime")
        if isinstance(prop, str) and isinstance(value, str):
            times.append((prop, value))
    return publication_candidates(metas, jsonld, times)


def extract_anchor(file_path: str | None, text: str):
    """The document anchor relationship dates are resolved against (ADR-0063
    §4), with its source: a URL capture's publication metadata, an HTML
    file's, an explicit "Published …" line near the top of the text, and only
    then the file's own timestamp — which is kept but, being when the file was
    produced, never resolves "last month".  Returns a ``pipeline.temporal.
    Anchor`` carrying every candidate seen, or None."""
    from pipeline.temporal import choose_anchor, header_candidates

    candidates: list[dict] = []
    path = Path(file_path) if file_path else None
    if path is not None:
        sidecar = capture_meta_path(path)
        try:
            if sidecar.is_file():
                import json as _json
                for c in _json.loads(sidecar.read_text(encoding="utf-8")).get("candidates", []):
                    if isinstance(c, dict):
                        candidates.append(c)
        except Exception as exc:
            logger.debug(f"[anchor] capture metadata unreadable for {file_path}: {exc}")
        if path.suffix.lower() in (".html", ".htm"):
            try:
                candidates.extend(html_publication_candidates(
                    path.read_text(encoding="utf-8", errors="replace")))
            except Exception as exc:
                logger.debug(f"[anchor] HTML metadata unreadable for {file_path}: {exc}")
    candidates.extend(header_candidates(text or ""))
    if path is not None:
        created = extract_reference_date(str(path))
        if created is not None:
            candidates.append({"value": created.date().isoformat(), "source": "file_metadata",
                               "kind": "created", "detail": path.suffix.lower().lstrip(".")})
    return choose_anchor(candidates)


def _is_scanned_pdf(path: Path) -> bool:
    """
    Returns True if the PDF has no embedded text layer (scanned / image-only).
    Samples the first few pages — fast, no full parse needed.
    """
    try:
        with pdfplumber.open(path) as pdf:
            pages = pdf.pages[:_DETECTION_SAMPLE_PAGES]
            if not pages:
                return False
            total_chars = sum(len(page.extract_text() or "") for page in pages)
            avg_chars = total_chars / len(pages)
            return avg_chars < _MIN_CHARS_PER_PAGE
    except Exception:
        return False


# Pages rasterized per convert_from_path() call.  A single A4 page at 300 DPI
# is ~25-30 MB uncompressed in RAM; converting a whole document in one call
# (the previous behaviour) holds every page's image at once, so a 100-page
# scanned report could spike to ~3 GB before Tesseract reads the first page.
# Batching bounds peak RAM to roughly this many pages regardless of document
# length, at the cost of one extra poppler invocation per batch.
_OCR_BATCH_PAGES = 10


def _read_pdf_ocr(path: Path) -> str:
    """OCR path for scanned PDFs — rasterizes and OCRs in fixed-size page
    batches so a large scan never holds every page as an image in RAM at once."""
    if not _OCR_AVAILABLE:
        logger.warning("OCR libraries not available. Install pdf2image and pytesseract.")
        logger.warning("On Linux: sudo apt install tesseract-ocr && pip install pdf2image pytesseract")
        return ""

    try:
        with pdfplumber.open(path) as pdf:
            num_pages = len(pdf.pages)
    except Exception as e:
        logger.warning(f"OCR failed: could not open {path.name}: {e}")
        return ""

    pages_text: list[str] = []
    for start in range(1, num_pages + 1, _OCR_BATCH_PAGES):
        end = min(start + _OCR_BATCH_PAGES - 1, num_pages)
        try:
            images = convert_from_path(str(path), dpi=300, first_page=start, last_page=end)
        except Exception as e:
            logger.warning(f"OCR failed on pages {start}-{end} of {path.name}: {e}")
            continue
        try:
            pages_text.extend(pytesseract.image_to_string(img, lang=ocr_lang()) for img in images)
        finally:
            # Close all PIL images to free resources before the next batch
            for img in images:
                img.close()

    return "\n".join(t for t in pages_text if t.strip())


def ocr_lang() -> str:
    """Tesseract language(s), e.g. "eng" or "eng+fra" (OCR_LANG; default eng)."""
    return (os.getenv("OCR_LANG") or "eng").strip() or "eng"


# A page is read as a scan when it carries almost no text and an image covers
# at least this share of it.  The image test is what keeps a blank page, a
# sparse cover or a divider out of OCR.
_SCAN_IMAGE_COVERAGE = 0.5


def _page_is_scanned(page) -> bool:
    # Glyph count rather than extract_text(): the detection runs on every page
    # of every PDF, and text-layout grouping is the expensive part.
    if sum(1 for c in page.chars if not c["text"].isspace()) >= _MIN_CHARS_PER_PAGE:
        return False
    area = float(page.width * page.height) or 1.0
    covered = sum(
        max(0.0, float(img["x1"]) - float(img["x0"])) * max(0.0, float(img["bottom"]) - float(img["top"]))
        for img in page.images
    )
    return covered / area >= _SCAN_IMAGE_COVERAGE


def _ocr_page(path: Path, page_number: int) -> str:
    """OCR one page (1-based); "" when OCR is unavailable or fails."""
    if not _OCR_AVAILABLE:
        return ""
    try:
        images = convert_from_path(str(path), dpi=300, first_page=page_number, last_page=page_number)
    except Exception as e:
        logger.warning(f"OCR failed on page {page_number} of {path.name}: {e}")
        return ""
    try:
        return "\n".join(pytesseract.image_to_string(img, lang=ocr_lang()) for img in images)
    except Exception as e:
        logger.warning(f"OCR failed on page {page_number} of {path.name}: {e}")
        return ""
    finally:
        for img in images:
            img.close()


def _read_pdf(path: Path) -> str:
    """Text of a PDF, with OCR decided page by page.

    The decision used to be made once, on the first few pages: a report whose
    first pages carried text and whose later pages were scans lost those pages
    entirely, and one that opened with a scanned cover was OCR'd throughout,
    text layer and all.
    """
    try:
        with pdfplumber.open(path) as pdf:
            n_pages = len(pdf.pages)
            scanned = [i for i, page in enumerate(pdf.pages) if _page_is_scanned(page)]
            # Page-by-page text is only needed for a mixed document.
            page_texts = ([page.extract_text() or "" for page in pdf.pages]
                          if 0 < len(scanned) < n_pages else [])
    except Exception as exc:
        logger.warning(f"Could not read {path.name} page by page ({exc}); using the "
                       "whole-document heuristic")
        if _is_scanned_pdf(path):
            logger.info("Scanned PDF detected — using OCR")
            return _read_pdf_ocr(path)
        return _read_pdf_text(path)

    if n_pages and len(scanned) == n_pages:
        logger.info("Scanned PDF detected — using OCR")
        return _read_pdf_ocr(path)
    if scanned:
        # Mixed document: keep each page in place, OCR only the scanned ones.
        logger.info(f"{len(scanned)} of {n_pages} pages are scans — OCR on those pages "
                    f"(lang={ocr_lang()})")
        for i in scanned:
            page_texts[i] = _ocr_page(path, i + 1) or page_texts[i]
        return "\n".join(t for t in page_texts if t.strip())
    return _read_pdf_text(path)


def _read_pdf_text(path: Path) -> str:
    """A PDF with a text layer on every page."""
    # Text-based PDF: markitdown preserves headers, tables, and lists
    if _MARKITDOWN_AVAILABLE:
        try:
            md = MarkItDown()
            result = md.convert(str(path))
            if result.text_content and len(result.text_content.strip()) > 100:
                return result.text_content
        except Exception:
            pass

    # Fallback: pdfplumber plain-text extraction
    text_parts = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                text_parts.append(text)
    return "\n".join(text_parts)


def _read_docx(path: Path) -> str:
    """Body text of a Word document — paragraphs AND tables, in reading order.

    `doc.paragraphs` alone skips every table, and CTI reports keep their IoCs in
    tables: a hash in a cell never reached Stage 2.  A table row becomes one
    line, its cells joined by " | "; a table nested in a cell is flattened into
    that cell's text.
    """
    doc = docx.Document(str(path))
    lines: list[str] = []
    _docx_blocks(doc.element.body, doc, lines)
    return "\n".join(line for line in lines if line.strip())


def _docx_blocks(parent_el, parent, lines: list[str]) -> None:
    """Append the text of every paragraph and table under `parent_el`, in order."""
    from docx.oxml.ns import qn
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    for child in parent_el.iterchildren():
        if child.tag == qn("w:p"):
            lines.append(Paragraph(child, parent).text)
        elif child.tag == qn("w:tbl"):
            _docx_table(Table(child, parent), lines)


def _docx_table(table, lines: list[str]) -> None:
    for row in table.rows:
        cells: list[str] = []
        seen: list = []
        for cell in row.cells:
            # A cell spanning several grid columns is returned once per column.
            if any(cell._tc is tc for tc in seen):
                continue
            seen.append(cell._tc)
            inner: list[str] = []
            _docx_blocks(cell._tc, cell, inner)
            cells.append(" ".join(t.strip() for t in inner if t.strip()))
        if any(cells):
            lines.append(" | ".join(cells))


def html_to_text(html: str) -> str:
    """
    Strip markup from an HTML document and return its visible text.

    Split out of `_read_html` so the ingestion API can measure what the pipeline
    will actually read from a pasted document before it creates a job: raw HTML
    can be thousands of characters and yield almost no prose, and a job built on
    that runs five stages to produce nothing.
    """
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return soup.get_text(separator="\n")


def _read_html(path: Path) -> str:
    return html_to_text(path.read_text(encoding="utf-8", errors="replace"))


def chunk_text(text: str, max_chars: int = 3000, overlap: int = 400) -> list[str]:
    """
    Splits text into chunks for LLM processing with a sliding-window overlap.

    Chunking strategy (cascade):
    1. Paragraph boundaries (\\n\\n) — ideal for well-structured text
    2. Line boundaries (\\n)          — fallback for PDFs without double newlines
    3. Raw character slice            — final fallback for monolithic blobs

    The `overlap` parameter appends the last N characters of each chunk to the
    beginning of the next one, preventing named entities that straddle a chunk
    boundary from being silently dropped.  The LLM merge step de-duplicates any
    entity that appears in both the tail of chunk N and the head of chunk N+1.

    Args:
        text:      input text
        max_chars: maximum characters per chunk (before overlap is added)
        overlap:   characters from the end of chunk[i] prepended to chunk[i+1]

    Returns:
        List of non-empty text chunks
    """
    # Choose separator based on text structure
    if text.count("\n\n") >= 3:
        units = text.split("\n\n")
        separator = "\n\n"
    elif text.count("\n") >= 3:
        units = text.split("\n")
        separator = "\n"
    else:
        # Monolithic blob — character slice only
        raw = [text[i:i + max_chars] for i in range(0, len(text), max_chars)]
        return _apply_overlap(raw, overlap, separator="")

    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for unit in units:
        unit = unit.strip()
        if not unit:
            continue
        if len(unit) > max_chars:
            if current:
                chunks.append(separator.join(current))
                current = []
                current_len = 0
            # Collect the raw slices separately — overlap is applied globally
            # at the end so these sub-chunks don't receive a double-overlap.
            for i in range(0, len(unit), max_chars):
                chunks.append(unit[i:i + max_chars])
            # Reset current so the next unit starts fresh (not appended after
            # an oversized unit that already filled the budget)
            current = []
            current_len = 0
            continue

        if current_len + len(unit) > max_chars and current:
            chunks.append(separator.join(current))
            current = [unit]
            current_len = len(unit)
        else:
            current.append(unit)
            current_len += len(unit)

    if current:
        chunks.append(separator.join(current))

    return _apply_overlap(chunks, overlap, separator=separator)


def _apply_overlap(chunks: list[str], overlap: int, separator: str = "\n\n") -> list[str]:
    """
    Prepends the last `overlap` characters of chunk[i] to chunk[i+1].
    Tries to break at a natural newline boundary within the overlap window.
    """
    if overlap <= 0 or len(chunks) <= 1:
        return chunks

    result = [chunks[0]]
    for i in range(1, len(chunks)):
        tail = chunks[i - 1][-overlap:]
        # Prefer breaking at a newline so the overlap starts at a sentence/line.
        # find() returns -1 when absent; >= 0 also handles a newline at index 0.
        nl = tail.find("\n")
        if nl >= 0:
            tail = tail[nl + 1:]
        result.append((tail + separator + chunks[i]) if tail else chunks[i])
    return result
