"""Stage 1: read a CTI report file and turn it into normalised text.

ingest() reads PDF, DOCX, HTML and plain text files, rejoins words split by a
line break, reads scanned PDF pages with OCR and keeps the rows of tables.  The
module also finds the report's reference date (extract_reference_date(),
extract_anchor()), reads publication metadata from HTML captures, and splits the
text into overlapping chunks for Stage 3 (chunk_text()).
"""

import logging
import os
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
except ModuleNotFoundError:
    _MARKITDOWN_AVAILABLE = False   # optional: the image installs it, the light runtime does not
except Exception as _exc:  # installed but broken (a native library, a bad dependency)
    _MARKITDOWN_AVAILABLE = False
    logger.warning(f"[Stage 1] markitdown is installed but does not load, PDFs are read as "
                   f"plain text and their tables lose their structure: {type(_exc).__name__}: {_exc}")

try:
    import pytesseract
    from pdf2image import convert_from_path
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False

# Minimum average chars per page to consider a PDF text-based (not scanned)
_MIN_CHARS_PER_PAGE = 50
_DETECTION_SAMPLE_PAGES = 3


def _read_corrupt_as_value_error(path: Path, reader: Callable[[Path], str], ext: str) -> str:
    """Run a PDF/DOCX reader; a parser exception on a corrupt file becomes ValueError (#609).

    The parsers (pdfplumber's PdfminerException, zipfile.BadZipFile, ...) raise
    their own types, which callers do not expect.  ValueError (a size guard, say)
    passes as-is; an OSError (missing file, no permission), MemoryError and
    KeyboardInterrupt are not a corrupt file and are re-raised untouched.
    """
    try:
        return reader(path)
    except (ValueError, OSError, MemoryError, KeyboardInterrupt):
        raise
    except Exception as exc:
        raise ValueError(f"{path.name}: unreadable or corrupt {ext} file "
                         f"({type(exc).__name__}: {exc})") from exc


def ingest(file_path: str) -> str:
    """
    Lit un fichier CTI (PDF, DOCX, HTML, TXT) et retourne le texte brut normalisé.

    Args:
        file_path: chemin vers le fichier rapport

    Returns:
        Le texte extrait, nettoyé des espaces superflus

    Raises:
        ValueError: si le format n'est pas supporté, ou si le PDF/DOCX est illisible ou corrompu
        FileNotFoundError: si le fichier n'existe pas
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    suffix = path.suffix.lower()

    # HTML and text readers do not raise on corrupt input (#609): only the
    # binary formats whose parsers raise their own exception types are wrapped.
    if suffix == ".pdf":
        raw = _read_corrupt_as_value_error(path, _read_pdf, "pdf")
    elif suffix == ".docx":
        raw = _read_corrupt_as_value_error(path, _read_docx, "docx")
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
_PDF_DATE_RE = compile_pattern(
    r"^(?:D:)?([0-9]{4})([0-9]{2})?([0-9]{2})?([0-9]{2})?([0-9]{2})?([0-9]{2})?")


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

# A zip bomb inflates a few megabytes of XML into gigabytes.
_MAX_DOCX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


def _check_docx_size(path: Path) -> None:
    """Refuse a .docx whose members would inflate past _MAX_DOCX_UNCOMPRESSED_BYTES."""
    with zipfile.ZipFile(path) as zf:
        total = sum(info.file_size for info in zf.infolist())
    if total > _MAX_DOCX_UNCOMPRESSED_BYTES:
        raise ValueError(f"Document trop volumineux : {total} octets décompressés "
                         f"(maximum {_MAX_DOCX_UNCOMPRESSED_BYTES})")


def _docx_created_date(path: Path) -> datetime | None:
    """Read docProps/core.xml's dcterms:created straight out of the .docx zip.

    ingest() already constructs a full python-docx Document to read the body
    text; doing that a second time here just to reach one metadata field
    (python-docx's own core_properties.created reads this exact element)
    doubles a non-trivial parse for every DOCX job. A .docx is a zip archive
    with the creation timestamp in its own small XML part, independent of the
    body -- reading that part directly avoids the second full parse.
    """
    _check_docx_size(path)
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
    except Exception as exc:
        logger.warning(f"[Stage 1] could not tell whether {Path(path).name} is a scan, reading it as "
                       f"text (no OCR): {type(exc).__name__}: {exc}")
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
            for page, img in enumerate(images, start):
                try:
                    pages_text.append(pytesseract.image_to_string(img, lang=ocr_page_lang(img)))
                except Exception as e:
                    logger.warning(f"OCR failed on page {page} of {path.name}: {e}")
        finally:
            # Close all PIL images to free resources before the next batch
            for img in images:
                img.close()

    return "\n".join(t for t in pages_text if t.strip())


# OCR_LANG=auto: each scanned page is read in the languages of the script that
# Tesseract's orientation and script detection (OSD) finds on that page.
OCR_LANG_AUTO = "auto"

# What a scanned page is read with when OCR_LANG is unset or blank: auto.  On the
# English pages measured for this default, the Latin set read English within
# 0.0006 character error rate of "eng"; the speed cost is in docs/configuration.md.
OCR_LANG_DEFAULT = OCR_LANG_AUTO

# The languages a Latin-script page is read in.  Also the set for a page whose
# script is not in _OCR_SCRIPT_LANGS, whose OSD fails, or whose script
# confidence is below _OSD_MIN_SCRIPT_CONFIDENCE.
_OCR_LATIN_LANGS = "eng+fra+spa+por+deu+ita+pol+tur+vie+ind"

# Languages per script name as Tesseract's OSD writes it.
_OCR_SCRIPT_LANGS = {
    "Latin": _OCR_LATIN_LANGS,
    "Cyrillic": "rus+ukr",
    "Han": "chi_sim+chi_tra",
    "Japanese": "jpn",
    "Hangul": "kor",
    "Arabic": "ara+fas+urd",
    "Devanagari": "hin",
    "Bengali": "ben",
    "Hebrew": "heb",
    "Thai": "tha",
}

# OSD script confidence below which the script is not trusted.
_OSD_MIN_SCRIPT_CONFIDENCE = 1.0

# OCR_LANG as requested, mapped to the languages Tesseract has data for.
_ocr_langs_in_use: dict[str, str] = {}

# The languages Tesseract has data for, listed once ("installed") or the error
# of the listing ("error").
_installed_cache: dict[str, Any] = {}

# Per-document OCR record, set while ingest() runs (see ocr_summary()).
_ocr_summary: ContextVar[dict[str, Any] | None] = ContextVar("stage1_ocr_summary", default=None)


def _ocr_setting() -> str:
    """OCR_LANG as written, or OCR_LANG_DEFAULT when it is unset or blank."""
    return (os.getenv("OCR_LANG") or "").strip() or OCR_LANG_DEFAULT


def ocr_lang() -> str:
    """Tesseract language(s) for a scanned page, e.g. "eng" or "eng+fra": OCR_LANG,
    or OCR_LANG_DEFAULT when it is unset or blank.  With OCR_LANG=auto the value
    is "auto", and each page's languages come from ocr_page_lang().  Languages
    that Tesseract has no data for are left out (see _resolve_ocr_lang)."""
    requested = _ocr_setting()
    if requested == OCR_LANG_AUTO:
        return OCR_LANG_AUTO
    if requested not in _ocr_langs_in_use:
        _ocr_langs_in_use[requested] = _resolve_ocr_lang(requested, f"OCR_LANG={requested}")
    return _ocr_langs_in_use[requested]


def _installed_languages() -> frozenset[str] | None:
    """The Tesseract languages with data, listed once; None when they cannot be listed."""
    if "installed" not in _installed_cache:
        try:
            _installed_cache["installed"] = frozenset(pytesseract.get_languages(config=""))
        except Exception as exc:
            _installed_cache["error"] = f"{type(exc).__name__}: {exc}"
            return None
    return _installed_cache["installed"]


def _resolve_ocr_lang(requested: str, label: str) -> str:
    """The requested languages that Tesseract has installed, joined with "+".

    `label` names the setting in the warning (e.g. "OCR_LANG=eng+fra").  One
    warning names the languages left out.  When none is installed, or the
    installed list cannot be read, the setting is returned unchanged: each
    page's OCR then fails and logs its own warning, as before."""
    if not _OCR_AVAILABLE:
        return requested
    installed = _installed_languages()
    if installed is None:
        logger.warning(f"[Stage 1] could not list the Tesseract languages "
                       f"({_installed_cache['error']}); {label} is used as set")
        return requested
    wanted = [lang for lang in requested.split("+") if lang]
    usable = [lang for lang in wanted if lang in installed]
    missing = [lang for lang in wanted if lang not in installed]
    if not missing:
        return requested
    if not usable:
        logger.warning(f"[Stage 1] {label}: Tesseract has no data for any of these "
                       f"languages ({', '.join(missing)}); scanned pages will fail to OCR. "
                       f"Install the tesseract-ocr-<lang> packages.")
        return requested
    logger.warning(f"[Stage 1] {label}: Tesseract has no data for "
                   f"{', '.join(missing)}; scanned pages are read in {'+'.join(usable)}. "
                   f"Install the tesseract-ocr-<lang> packages for the missing languages.")
    return "+".join(usable)


def _page_script(img: Any) -> tuple[str, float]:
    """The script and its confidence that Tesseract's OSD finds on one page image.

    ("", 0.0) when OSD fails (it does on a page with little text) or its output
    has no script line."""
    try:
        osd = pytesseract.image_to_osd(img)
    except Exception as exc:
        logger.debug(f"[Stage 1] OSD found no script on a page: {type(exc).__name__}: {exc}")
        return "", 0.0
    fields: dict[str, str] = {}
    for line in osd.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    try:
        return fields.get("Script", ""), float(fields.get("Script confidence", "0"))
    except ValueError:
        return "", 0.0


def _languages_for_script(script: str, confidence: float) -> tuple[str, str]:
    """(script to report, languages to read the page with) for an OSD answer."""
    if not script or confidence < _OSD_MIN_SCRIPT_CONFIDENCE:
        return "unknown", _OCR_LATIN_LANGS
    return script, _OCR_SCRIPT_LANGS.get(script, _OCR_LATIN_LANGS)


def _auto_langs(script: str, langs: str) -> str:
    """The languages of one script, filtered by the installed ones.  A script
    with no installed language is read in the Latin set (one warning)."""
    key = f"{OCR_LANG_AUTO}:{script}"
    if key not in _ocr_langs_in_use:
        label = f"OCR_LANG=auto, {script} pages"
        installed = _installed_languages() if _OCR_AVAILABLE else None
        if langs != _OCR_LATIN_LANGS and installed is not None \
                and not set(langs.split("+")) & installed:
            logger.warning(f"[Stage 1] {label}: Tesseract has no data for {langs}; "
                           f"these pages are read in the Latin set")
            langs = _OCR_LATIN_LANGS
            label = "OCR_LANG=auto, Latin set"
        _ocr_langs_in_use[key] = _resolve_ocr_lang(langs, label)
    return _ocr_langs_in_use[key]


def _count(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _note_page(langs: str, script: str | None) -> None:
    """Adds one OCR'd page to the document's record, when one is collecting."""
    summary = _ocr_summary.get()
    if summary is None:
        return
    summary["pages"] = summary.get("pages", 0) + 1
    _count(summary.setdefault("languages", {}), langs)
    if script is not None:
        _count(summary.setdefault("scripts", {}), script)


def ocr_page_lang(img: Any) -> str:
    """The languages one page image is read with.

    ocr_lang() for an explicit OCR_LANG; with OCR_LANG=auto, the languages of
    the script that OSD finds on the page (see _languages_for_script)."""
    if _ocr_setting() != OCR_LANG_AUTO:
        langs = ocr_lang()
        _note_page(langs, None)
        return langs
    script, langs = _languages_for_script(*_page_script(img))
    read_with = _auto_langs(script, langs)
    _note_page(read_with, script)
    return read_with


@contextmanager
def ocr_summary() -> Iterator[dict[str, Any]]:
    """Collects, for the document read inside the block, the pages OCR'd, the
    languages each page was read with and, with OCR_LANG=auto, the scripts found.
    The dict stays empty when no page was OCR'd.  It holds counts only, never
    page text."""
    summary: dict[str, Any] = {}
    token = _ocr_summary.set(summary)
    try:
        yield summary
    finally:
        _ocr_summary.reset(token)


# A page is read as a scan when it carries almost no text and an image covers
# at least this share of it.  The image test is what keeps a blank page, a
# sparse cover or a divider out of OCR.
_SCAN_IMAGE_COVERAGE = 0.5

# A page whose text is drawn as glyph outlines has no text layer and no image
# either: each glyph is a small filled path.  "Microsoft Print to PDF" writes a
# web page that way when it cannot embed its fonts (a CERT-UA advisory: 0
# characters, 3,777 such paths, an image over 7 % of the page), and the page
# used to be read as text, which gave nothing.  A page with almost no text and
# at least this many glyph-sized filled paths is read as a scan.  A vector logo
# on a cover stays below it; a diagram above it has its labels read by OCR,
# which is the only reading it can have.
_OUTLINED_GLYPHS = 100
_GLYPH_MAX_POINTS = 24.0   # width and height of a body or heading glyph


def _outlined_glyphs(page) -> int:
    """Filled paths of a glyph's size on the page."""
    return sum(
        1 for c in page.curves
        if c.get("fill")
        and float(c["x1"]) - float(c["x0"]) <= _GLYPH_MAX_POINTS
        and float(c["bottom"]) - float(c["top"]) <= _GLYPH_MAX_POINTS
    )


def _page_is_scanned(page) -> bool:
    """True when a page has almost no text layer but something to read: an
    image over half of it, or text drawn as glyph outlines."""
    # Glyph count rather than extract_text(): the detection runs on every page
    # of every PDF, and text-layout grouping is the expensive part.
    if sum(1 for c in page.chars if not c["text"].isspace()) >= _MIN_CHARS_PER_PAGE:
        return False
    area = float(page.width * page.height) or 1.0
    covered = sum(
        max(0.0, float(img["x1"]) - float(img["x0"])) * max(0.0, float(img["bottom"]) - float(img["top"]))
        for img in page.images
    )
    return covered / area >= _SCAN_IMAGE_COVERAGE or _outlined_glyphs(page) >= _OUTLINED_GLYPHS


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
        return "\n".join(pytesseract.image_to_string(img, lang=ocr_page_lang(img)) for img in images)
    except Exception as e:
        logger.warning(f"OCR failed on page {page_number} of {path.name}: {e}")
        return ""
    finally:
        for img in images:
            img.close()


# ── IoCs in wrapped table cells (audit B 8.1.5) ─────────────────────────────
# A narrow table column wraps a hash or a URL over several lines, and neither
# markitdown nor pdfplumber's page text keeps the pieces together: markitdown
# writes the continuation lines outside the table row, so on the audit's
# generated report Stage 2 found 0 of 12 SHA-256 and 0 of 6 URLs (16 of 34
# IoCs).  pdfplumber's table finder gives each cell's text whole; a cell whose
# lines are single tokens that join into one IoC-shaped value is glued back.
# The body text is kept as it is (ADR-0032 measured what replacing markitdown
# with pdfplumber's text costs: 18.2 % of the characters, hashes among them);
# the rows that had such a cell are added after it, under a marker.
_TABLE_MARK = "[[table rows rejoined from wrapped cells: page {page}]]"
_MAX_TABLES = 200          # a hostile PDF does not get to run the finder forever
_MAX_CELLS = 20_000
_IOC_SHAPED = compile_pattern(
    r"^(?:[0-9a-fA-F]{32,128}"                               # a hash
    r"|[A-Za-z][A-Za-z0-9+.-]*://\S+"                        # a URL
    r"|(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?"       # an IPv4[:port]
    r"|[^\s@]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"            # an email address
    r"|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?:[/:?#]\S*)?"   # a domain, a file
    r"|[A-Za-z]:\\\S+)$"                                     # a Windows path
)
_DEFANGS = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[:]", ":"), ("[at]", "@"), ("[@]", "@"),
            ("hxxp", "http"), ("fxp", "ftp"))


def _join_cell(cell: str | None) -> tuple[str, bool]:
    """A table cell's text on one line, and whether wrapped lines were glued.

    Lines are glued without a space only when each is a single token and the
    result, refanged, is IoC-shaped; prose is joined with spaces."""
    lines = [line.strip() for line in (cell or "").splitlines() if line.strip()]
    if len(lines) > 1 and not any(any(ch.isspace() for ch in line) for line in lines):
        glued = "".join(lines)
        live = glued
        for fanged, plain in _DEFANGS:
            live = live.replace(fanged, plain)
        if _IOC_SHAPED.match(live):
            return glued, True
    return " ".join(lines), False


def _rejoined_table_rows(path: Path, skip_pages: frozenset[int] = frozenset()) -> str:
    """The rows of the PDF's tables in which a wrapped cell was glued back, one
    per line with its cells joined by " | " (as Word tables are read), under a
    marker per page; "" when there is none.  `skip_pages` (0-based): scans."""
    out: list[str] = []
    tables = cells = 0
    try:
        with pdfplumber.open(path) as pdf:
            for index, page in enumerate(pdf.pages):
                if index in skip_pages:
                    continue
                rows: list[str] = []
                for table in page.extract_tables() or []:
                    tables += 1
                    for row in table:
                        cells += len(row)
                        joined = [_join_cell(c) for c in row]
                        if any(glued for _, glued in joined):
                            rows.append(" | ".join(text for text, _ in joined))
                    if tables >= _MAX_TABLES or cells >= _MAX_CELLS:
                        break
                if rows:
                    out.append(_TABLE_MARK.format(page=index + 1) + "\n" + "\n".join(rows))
                if tables >= _MAX_TABLES or cells >= _MAX_CELLS:
                    logger.warning(f"[Stage 1] {path.name}: table pass stopped at {tables} tables, "
                                   f"{cells} cells")
                    break
    except Exception as exc:
        logger.warning(f"[Stage 1] {path.name}: tables not read, wrapped IoCs in table cells may be "
                       f"lost: {type(exc).__name__}: {exc}")
        return ""
    if out:
        logger.info(f"[Stage 1] {path.name}: {sum(b.count(chr(10)) for b in out)} table rows "
                    "with wrapped IoC cells rejoined")
    return "\n\n".join(out)


def _with_table_rows(text: str, path: Path, skip_pages: frozenset[int] = frozenset()) -> str:
    rows = _rejoined_table_rows(path, skip_pages)
    return f"{text}\n\n{rows}" if rows else text


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
        return _with_table_rows("\n".join(t for t in page_texts if t.strip()), path,
                                frozenset(scanned))
    return _read_pdf_text(path)


def _read_pdf_text(path: Path) -> str:
    """A PDF with a text layer on every page."""
    # Text-based PDF: markitdown preserves headers, tables, and lists
    if _MARKITDOWN_AVAILABLE:
        try:
            md = MarkItDown()
            result = md.convert(str(path))
            if result.text_content and len(result.text_content.strip()) > 100:
                return _with_table_rows(result.text_content, path)
        except Exception as exc:
            # The fallback below loses the tables' structure: say so.
            logger.warning(f"[Stage 1] markitdown could not convert {path.name} ({exc}); "
                           "falling back to pdfplumber plain text")

    # Fallback: pdfplumber plain-text extraction
    text_parts = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                text_parts.append(text)
    return _with_table_rows("\n".join(text_parts), path)


def _read_docx(path: Path) -> str:
    """Body text of a Word document — paragraphs AND tables, in reading order.

    `doc.paragraphs` alone skips every table, and CTI reports keep their IoCs in
    tables: a hash in a cell never reached Stage 2.  A table row becomes one
    line, its cells joined by " | "; a table nested in a cell is flattened into
    that cell's text.
    """
    _check_docx_size(path)
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


# Elements a browser lays out as blocks (or as a line break): the text on
# either side of one is not one word.  Everything else (span, a, b, code, …) is
# inline and adds no separator.
_HTML_BLOCKS = frozenset({
    "address", "article", "aside", "blockquote", "body", "br", "caption", "dd", "details",
    "dialog", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
    "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html", "li",
    "main", "nav", "ol", "option", "p", "pre", "section", "summary", "table", "tbody",
    "td", "tfoot", "th", "thead", "title", "tr", "ul",
})


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
    # A line break between blocks only, as a browser renders it: a separator
    # between EVERY text node split "down<span>load</span>" into "down\nload",
    # and the URL it was part of was extracted cut (#295).
    for tag in soup.find_all(_HTML_BLOCKS):
        if tag.name == "br":
            tag.replace_with("\n")
            continue
        tag.insert_before("\n")
        tag.insert_after("\n")
    return soup.get_text()


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
    # Per chunk: the text between it and the one before in the SOURCE.  A
    # slice of an oversized unit continues the slice before it with nothing in
    # between; joining the overlap with the document's separator put a
    # paragraph break inside whatever straddled the cut (#291).
    joins: list[str] = []
    current: list[str] = []
    current_len = 0

    for unit in units:
        unit = unit.strip()
        if not unit:
            continue
        if len(unit) > max_chars:
            if current:
                chunks.append(separator.join(current))
                joins.append(separator)
                current = []
                current_len = 0
            # Collect the raw slices separately — overlap is applied globally
            # at the end so these sub-chunks don't receive a double-overlap.
            for k, piece in enumerate(_slice_at_spaces(unit, max_chars)):
                chunks.append(piece)
                joins.append(separator if k == 0 else "")
            # Reset current so the next unit starts fresh (not appended after
            # an oversized unit that already filled the budget)
            current = []
            current_len = 0
            continue

        if current_len + len(unit) > max_chars and current:
            chunks.append(separator.join(current))
            joins.append(separator)
            current = [unit]
            current_len = len(unit)
        else:
            current.append(unit)
            current_len += len(unit)

    if current:
        chunks.append(separator.join(current))
        joins.append(separator)

    return _apply_overlap(chunks, overlap, separator=separator, joins=joins)


def _slice_at_spaces(unit: str, max_chars: int) -> list[str]:
    """`unit` cut into pieces of at most `max_chars`, each cut on a space when
    the second half of the window has one: a cut inside a token gave the
    extractor a URL's prefix as an IoC of its own (#291).  The space starts the
    next piece, so the pieces joined with "" are `unit` again."""
    pieces: list[str] = []
    i = 0
    while len(unit) - i > max_chars:
        cut = unit.rfind(" ", i + max_chars // 2, i + max_chars)
        end = cut if cut > i else i + max_chars
        pieces.append(unit[i:end])
        i = end
    pieces.append(unit[i:])
    return pieces


def _apply_overlap(chunks: list[str], overlap: int, separator: str = "\n\n",
                   joins: list[str] | None = None) -> list[str]:
    """
    Prepends the last `overlap` characters of chunk[i] to chunk[i+1].
    Tries to break at a natural newline boundary within the overlap window.
    `joins[i]`, when given, is what separates chunk i from chunk i-1 in the
    source ("" for two slices of one unit); `separator` otherwise.
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
        join = joins[i] if joins is not None else separator
        result.append((tail + join + chunks[i]) if tail else chunks[i])
    return result
