import re
import logging
import pdfplumber
import docx
from bs4 import BeautifulSoup
from pathlib import Path

# Initialize logging
from api.logging_config import get_logger
logger = get_logger(__name__)

# pdfminer (used internally by pdfplumber) emits WARNING-level messages for PDFs
# with incomplete font descriptors ("Could not get FontBBox…").  These are benign
# — the text is still extracted correctly — but they spam the server log.
logging.getLogger("pdfminer").setLevel(logging.ERROR)

# Matches an alphanumeric token ending with a hyphen immediately before a line
# break (single or double \n).  PDFs break long tokens — especially domain names
# and paths — at column/page boundaries: "git-\n\ntanstack[.]com" must become
# "git-tanstack[.]com" BEFORE defanging so the full domain is preserved.
_HYPHEN_LINEBREAK = re.compile(r"([A-Za-z0-9])-[ \t]*\n\n?[ \t]*([A-Za-z0-9])")


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
    from pdf2image import convert_from_path
    import pytesseract
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


def _read_pdf_ocr(path: Path) -> str:
    """OCR path for scanned PDFs — converts each page to an image then runs Tesseract."""
    if not _OCR_AVAILABLE:
        logger.warning("OCR libraries not available. Install pdf2image and pytesseract.")
        logger.warning("On Linux: sudo apt install tesseract-ocr && pip install pdf2image pytesseract")
        return ""

    try:
        images = convert_from_path(str(path), dpi=300)
        try:
            pages_text = [pytesseract.image_to_string(img, lang="eng") for img in images]
            return "\n".join(t for t in pages_text if t.strip())
        finally:
            # Close all PIL images to free resources
            for img in images:
                img.close()
    except Exception as e:
        logger.warning(f"OCR failed: {e}")
        return ""


def _read_pdf(path: Path) -> str:
    if _is_scanned_pdf(path):
        logger.info("Scanned PDF detected — using OCR")
        return _read_pdf_ocr(path)

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
    doc = docx.Document(path)
    return "\n".join(para.text for para in doc.paragraphs if para.text.strip())


def _read_html(path: Path) -> str:
    html = path.read_text(encoding="utf-8", errors="replace")
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text(separator="\n")


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
        return _apply_overlap(raw, overlap)

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

    return _apply_overlap(chunks, overlap)


def _apply_overlap(chunks: list[str], overlap: int) -> list[str]:
    """
    Prepends the last `overlap` characters of chunk[i] to chunk[i+1].
    Tries to break at a natural newline boundary within the overlap window.
    """
    if overlap <= 0 or len(chunks) <= 1:
        return chunks

    result = [chunks[0]]
    for i in range(1, len(chunks)):
        tail = chunks[i - 1][-overlap:]
        # Prefer breaking at a newline so the overlap starts at a sentence/line
        nl = tail.find("\n")
        if nl > 0:
            tail = tail[nl + 1:]
        result.append((tail + "\n\n" + chunks[i]) if tail else chunks[i])
    return result
