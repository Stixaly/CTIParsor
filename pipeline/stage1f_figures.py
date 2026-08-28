from __future__ import annotations

import concurrent.futures
import hashlib
import io
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Protocol

import pdfplumber

from pipeline.vlm import PROMPT_VERSION, FigureRead, VisionBackend

logger = logging.getLogger(__name__)

# Tier 0 geometric triage (ADR-0032).  Measured on this corpus: it discards
# 194 of 341 images — 56.9% — before any model is involved, and it is the only
# tier whose cost does not grow with the corpus.
MIN_SIDE_PT = 48.0
MIN_AREA_RATIO = 0.02
MAX_ASPECT = 6.0

# An image whose bytes repeat on this many pages is furniture: a running header,
# a footer logo, a watermark.  Counted per document, not per page.
REPEAT_PAGE_LIMIT = 3

# 150 DPI is what the ADR-0032 probe used.  Crops are a fraction of a page, so
# this is a resolution budget, not a size one.
RENDER_DPI = 150

# Sentinels delimiting an injected figure.  U+27E6 / U+27E7 occur 0 times in the
# 415,981 characters of stored report text, they are in neither _CHAR_MAP nor
# _LIGATURES in evidence_span.py, so _normalise passes them through one-for-one
# and the offset invariant holds.
OPEN = "⟦"
CLOSE = "⟧"

# Kinds that carry no evidence.  They are still recorded — an ordinal must not
# renumber depending on what a model decided — but their block stays empty.
EMPTY_KINDS: frozenset[str] = frozenset({"logo", "none", "unread"})


@dataclass(frozen=True)
class FigureCandidate:
    page: int
    bbox: tuple[float, float, float, float]
    area_ratio: float


@dataclass(frozen=True)
class FigureSpan:
    ordinal: int
    page: int
    bbox: tuple[float, float, float, float]
    kind: str
    char_start: int
    char_end: int
    model: str
    sha256: str


class ReadCache(Protocol):
    """Persistence for figure reads, keyed on the crop bytes.

    Keyed on (sha256, model, prompt_version) rather than on the figure's
    position: re-ingesting the same report, or A/B-ing two models, must not
    pay for the same crop twice, and a stored read must never be served
    against a contract it did not answer.
    """
    def get(self, sha256: str, model: str,
            prompt_version: int) -> FigureRead | None: ...
    def put(self, sha256: str, model: str, prompt_version: int,
            read: FigureRead) -> None: ...


def find_figures(pdf_path: Path | str) -> list[FigureCandidate]:
    """Find figure candidates in a PDF using geometric triage."""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            # First pass: count distinct pages for each geometric key
            key_pages: dict[tuple[int, int, int], set[int]] = {}
            for page_idx, page in enumerate(pdf.pages, start=1):
                for im in page.images:
                    try:
                        x0 = float(im.get("x0", 0))
                        x1 = float(im.get("x1", 0))
                        top = float(im.get("top", 0))
                        bottom = float(im.get("bottom", 0))
                        w = abs(x1 - x0)
                        h = abs(bottom - top)
                        key = (round(w), round(h), round(x0))
                        if key not in key_pages:
                            key_pages[key] = set()
                        key_pages[key].add(page_idx)
                    except (TypeError, ValueError, AttributeError):
                        continue

            # Second pass: filter and collect candidates
            candidates: list[FigureCandidate] = []
            for page_idx, page in enumerate(pdf.pages, start=1):
                page_area = page.width * page.height
                if page_area <= 0:
                    continue

                for im in page.images:
                    try:
                        x0 = float(im.get("x0", 0))
                        x1 = float(im.get("x1", 0))
                        top = float(im.get("top", 0))
                        bottom = float(im.get("bottom", 0))
                    except (TypeError, ValueError, AttributeError):
                        continue

                    w = abs(x1 - x0)
                    h = abs(bottom - top)

                    if w < MIN_SIDE_PT or h < MIN_SIDE_PT:
                        continue
                    if (w * h) / page_area < MIN_AREA_RATIO:
                        continue
                    if h > 0 and w / h > MAX_ASPECT:
                        continue
                    if w > 0 and h / w > MAX_ASPECT:
                        continue

                    key = (round(w), round(h), round(x0))
                    page_count = len(key_pages.get(key, set()))
                    if page_count >= REPEAT_PAGE_LIMIT:
                        logger.debug("Skipping repeated figure key %s (count %d)", key, page_count)
                        continue

                    # Clamp bbox to page
                    cx0 = max(0.0, x0)
                    ctop = max(0.0, top)
                    cx1 = min(page.width, x1)
                    cbottom = min(page.height, bottom)

                    # Ensure min/max order
                    min_x = min(cx0, cx1)
                    max_x = max(cx0, cx1)
                    min_y = min(ctop, cbottom)
                    max_y = max(ctop, cbottom)

                    clamped_w = max_x - min_x
                    clamped_h = max_y - min_y

                    if clamped_w <= 0 or clamped_h <= 0:
                        continue

                    area_ratio = min((clamped_w * clamped_h) / page_area, 1.0)

                    candidates.append(FigureCandidate(
                        page=page_idx,
                        bbox=(min_x, min_y, max_x, max_y),
                        area_ratio=area_ratio
                    ))

            candidates.sort(key=lambda c: (c.page, c.bbox[1], c.bbox[0]))
            return candidates
    except Exception as e:
        logger.warning("Failed to find figures in %s: %s", pdf_path, e)
        return []


def render_crop(pdf_path: Path | str, cand: FigureCandidate,
                dpi: int = RENDER_DPI) -> bytes:
    """Render a crop of a PDF page as PNG bytes."""
    with pdfplumber.open(pdf_path) as pdf:
        page = pdf.pages[cand.page - 1]
        im = page.crop(cand.bbox).to_image(resolution=dpi)
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        return buf.getvalue()


def read_figures(pdf_path: Path | str, backend: VisionBackend,
                 max_figures: int = 40, dpi: int = RENDER_DPI,
                 cache: ReadCache | None = None,
                 ) -> list[tuple[FigureCandidate, FigureRead, str]]:
    """Read figures from a PDF using a vision backend."""
    candidates = find_figures(pdf_path)
    if len(candidates) > max_figures:
        logger.warning("Truncating %d figures to %d", len(candidates), max_figures)
        candidates = candidates[:max_figures]

    results: list[tuple[FigureCandidate, FigureRead, str]] = []
    pending: list[tuple[int, FigureCandidate, bytes, str]] = []

    for idx, cand in enumerate(candidates):
        try:
            png = render_crop(pdf_path, cand, dpi)
            sha256 = hashlib.sha256(png).hexdigest()
        except Exception as e:
            logger.warning("Render failed for candidate %d: %s", idx, e)
            read = FigureRead(
                kind="unread",
                verbatim_text=[],
                edges=[],
                iocs=[],
                provider=backend.name,
                model=backend.model,
                elapsed_s=0.0,
                error=f"render failed: {type(e).__name__}: {e}"
            )
            results.append((cand, read, ""))
            continue

        if cache is not None:
            cached = cache.get(sha256, backend.model, PROMPT_VERSION)
            if cached is not None:
                results.append((cand, cached, sha256))
                continue

        pending.append((idx, cand, png, sha256))

    if pending:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, backend.max_concurrency)) as executor:
            futures = {
                # Submit with one argument so the backend's own default prompt
                # applies.  Passing None here sent a null where the API wants a
                # string and every read came back 400.
                executor.submit(backend.read_figure, png): (idx, cand, sha256)
                for idx, cand, png, sha256 in pending
            }
            for future in concurrent.futures.as_completed(futures):
                idx, cand, sha256 = futures[future]
                try:
                    read = future.result()
                except Exception as e:
                    logger.warning("Read failed for candidate %d: %s", idx, e)
                    read = FigureRead(
                        kind="unread",
                        verbatim_text=[],
                        edges=[],
                        iocs=[],
                        provider=backend.name,
                        model=backend.model,
                        elapsed_s=0.0,
                        error=f"read failed: {type(e).__name__}: {e}"
                    )

                if cache is not None and read.kind != "unread":
                    cache.put(sha256, backend.model, PROMPT_VERSION, read)

                results.append((cand, read, sha256))

    # Restore the candidate order that `find_figures` established — the SAME
    # key, (page, top, x0).  Sorting on `page` alone was not enough: `results`
    # holds the cached and render-failed entries in candidate order followed by
    # the concurrently-read ones in COMPLETION order, and a page-only sort is
    # stable, so two figures on one page kept whichever order the threads
    # happened to finish in.  `inject` and `inject_append` number ordinals by
    # enumerating this list, so that made a figure printed lower on the page
    # carry the lower ordinal.
    results.sort(key=lambda x: (x[0].page, x[0].bbox[1], x[0].bbox[0]))
    return results


def render_block(ordinal: int, read: FigureRead) -> str:
    """Render a figure block with sentinels."""
    if read.kind in EMPTY_KINDS:
        return f"{OPEN}figure {ordinal} · {read.kind}{CLOSE}\n{OPEN}/figure {ordinal}{CLOSE}"

    body_lines = [line.strip() for line in read.verbatim_text]
    body_lines = [line for line in body_lines if line]
    body = "\n".join(body_lines)

    # Neutralize sentinels in body
    body = body.replace(OPEN, "[").replace(CLOSE, "]")

    return f"{OPEN}figure {ordinal} · {read.kind}{CLOSE}\n{body}\n{OPEN}/figure {ordinal}{CLOSE}"


def map_verbatim(reads: list[tuple[FigureCandidate, FigureRead, str]],
                 fn: Callable[[str], str],
                 ) -> list[tuple[FigureCandidate, FigureRead, str]]:
    """Apply `fn` to every transcribed line, before the blocks are rendered.

    Exists so the caller can refang figure text on the same terms as the rest of
    the document.  Order matters and is not negotiable: `refang` rewrites `[.]`
    to `.` and so *shortens* the text, which means any span computed before it
    runs points at the wrong characters afterwards.  Refang first, inject second.
    """
    return [
        (cand, replace(read, verbatim_text=[fn(line) for line in read.verbatim_text]), sha)
        for cand, read, sha in reads
    ]


def inject_append(base_text: str,
                  reads: list[tuple[FigureCandidate, FigureRead, str]],
                  ) -> tuple[str, list[FigureSpan]]:
    """Append every figure block after the document text, in reading order.

    This is the default placement, and it is a measured retreat from ADR-0032's
    "at that position in reading order".  Inline placement needs per-page text,
    which only pdfplumber gives; switching ingestion to it costs 18.2% of the
    characters across this corpus — and the observables that go with them are
    **not random**.  On `dac56b35` the five lost values were all SHA-256 hashes,
    broken across lines by a wrapped table column: the exact failure ADR-0029
    characterised, on the one observable class ADR-0030 weights at 1.00.

    So figures are appended to the markitdown text rather than woven into a
    pdfplumber one.  Reading-order *position* is lost; reading-order *sequence*
    is kept, `report_figures` still stores each figure's page and bbox, and not
    one hash is traded for it.

    Use `inject` instead when the caller genuinely has per-page text and has
    accepted that cost.
    """
    parts: list[str] = []
    spans: list[FigureSpan] = []
    pos = 0
    if base_text:
        parts.append(base_text)
        pos = len(base_text)

    # Emitted in `reads` order, which `read_figures` already sorts by
    # (page, top, x0).  Re-grouping by page here would let a later-read figure
    # carry a lower ordinal than one printed before it.
    for ordinal, (cand, read, sha256) in enumerate(reads, start=1):
        if parts:
            parts.append("\n\n")
            pos += 2
        char_start = pos
        block = render_block(ordinal, read)
        parts.append(block)
        pos += len(block)
        spans.append(FigureSpan(
            ordinal=ordinal,
            page=cand.page,
            bbox=cand.bbox,
            kind=read.kind,
            char_start=char_start,
            char_end=pos,
            model=read.model,
            sha256=sha256,
        ))

    return "".join(parts), spans


def inject(page_texts: list[str],
           reads: list[tuple[FigureCandidate, FigureRead, str]],
           ) -> tuple[str, list[FigureSpan]]:
    """Inject figure blocks into page texts and return their spans.

    Pages are joined with a single newline — the separator `_read_pdf`'s
    pdfplumber path already uses — so enabling Stage 1f changes where figures
    appear and nothing else about how pages are stitched together.
    """
    page_reads: dict[int, list[tuple[int, FigureCandidate, FigureRead, str]]] = {}
    for idx, (cand, read, sha256) in enumerate(reads, start=1):
        page_reads.setdefault(cand.page, []).append((idx, cand, read, sha256))

    parts: list[str] = []
    spans: list[FigureSpan] = []
    pos = 0

    def _append(chunk: str) -> None:
        """Append a chunk and advance the running offset."""
        nonlocal pos
        parts.append(chunk)
        pos += len(chunk)

    def _separate(sep: str) -> None:
        """Emit a separator — never before anything, never doubling one."""
        if not parts or parts[-1].endswith("\n\n"):
            return
        _append(sep)

    def _emit(entries: list[tuple[int, FigureCandidate, FigureRead, str]]) -> None:
        """Emit one block per entry, recording its span.

        char_start is read BEFORE the block is appended, so it always points at
        the opening sentinel and char_end just past the closing one — the
        invariant every downstream offset lookup depends on.
        """
        for ordinal, cand, read, sha256 in entries:
            _separate("\n\n")
            char_start = pos
            _append(render_block(ordinal, read))
            spans.append(FigureSpan(
                ordinal=ordinal,
                page=cand.page,
                bbox=cand.bbox,
                kind=read.kind,
                char_start=char_start,
                char_end=pos,
                model=read.model,
                sha256=sha256,
            ))

    for page_idx, page_text in enumerate(page_texts, start=1):
        if page_text:
            _separate("\n")
            _append(page_text)
        if page_idx in page_reads:
            _emit(page_reads[page_idx])

    max_page = len(page_texts)
    for page_idx in sorted(k for k in page_reads if k > max_page):
        logger.warning(
            "Figure on page %d exceeds the %d pages of text — appended at the end",
            page_idx, max_page,
        )
        _emit(page_reads[page_idx])

    spans.sort(key=lambda s: s.ordinal)
    return "".join(parts), spans
