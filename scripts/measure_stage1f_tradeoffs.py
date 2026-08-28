from __future__ import annotations

import argparse
import io
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

import pdfplumber

# Project root on sys.path so the pipeline package imports when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.stage1_ingestion import ingest
from pipeline.stage2_extraction import extract_entities

# Tier 0 triage, from ADR-0032.  Measured on this corpus: it discards 194 of
# 341 images (56.9%) before any model is involved.
MIN_SIDE_PT = 48.0
MIN_AREA_RATIO = 0.02
MAX_ASPECT = 6.0
RENDER_DPI = 150


@dataclass
class Figure:
    page: int              # 1-indexed
    bbox: tuple[float, float, float, float]   # x0, top, x1, bottom in points
    area_ratio: float


@dataclass
class TextCompare:
    path: str
    markitdown_chars: int
    pdfplumber_chars: int
    markitdown_obs: int
    pdfplumber_obs: int
    shared_obs: int        # observables found by BOTH
    error: str | None = None


def _figures(pdf) -> list[Figure]:
    """Extract candidate figures from an open pdfplumber PDF."""
    results: list[Figure] = []
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
                w = abs(x1 - x0)
                h = abs(bottom - top)
            except (TypeError, ValueError, AttributeError):
                continue
            if w < MIN_SIDE_PT or h < MIN_SIDE_PT:
                continue
            if (w * h) / page_area < MIN_AREA_RATIO:
                continue
            if h > 0 and (w / h) > MAX_ASPECT:
                continue
            if w > 0 and (h / w) > MAX_ASPECT:
                continue
            bx0 = max(0.0, min(x0, x1))
            btop = max(0.0, min(top, bottom))
            bx1 = min(page.width, max(x0, x1))
            bbottom = min(page.height, max(top, bottom))
            bw = bx1 - bx0
            bh = bbottom - btop
            if bw <= 0 or bh <= 0:
                continue
            results.append(Figure(
                page=page_idx, bbox=(bx0, btop, bx1, bbottom),
                area_ratio=(w * h) / page_area,
            ))
    results.sort(key=lambda f: (f.page, f.bbox[1]))
    return results


def _observables(text: str) -> set[str]:
    """Return the set of normalized entity observables found in text."""
    try:
        entities = extract_entities(text)
        return {f"{e.entity_type.value}:{e.value.lower()}" for e in entities}
    except Exception:
        return set()


def _compare_text(path: Path) -> TextCompare:
    """Compare markitdown and pdfplumber text extraction for one PDF."""
    try:
        markitdown_text = ingest(str(path))
        with pdfplumber.open(str(path)) as pdf:
            pdfplumber_text = "\n".join((page.extract_text() or "") for page in pdf.pages)
        md_obs = _observables(markitdown_text)
        pp_obs = _observables(pdfplumber_text)
        return TextCompare(
            path=str(path),
            markitdown_chars=len(markitdown_text),
            pdfplumber_chars=len(pdfplumber_text),
            markitdown_obs=len(md_obs),
            pdfplumber_obs=len(pp_obs),
            shared_obs=len(md_obs & pp_obs),
        )
    except Exception as e:
        return TextCompare(
            path=str(path), markitdown_chars=0, pdfplumber_chars=0,
            markitdown_obs=0, pdfplumber_obs=0, shared_obs=0, error=str(e),
        )


def _compare_crops(
    path: Path, figures: list[Figure], dpi: int, out_dir: Path | None,
) -> list[tuple[Figure, int, int, int, int]]:
    """Compare full-page and cropped PNG sizes for each figure."""
    rows: list[tuple[Figure, int, int, int, int]] = []
    try:
        with pdfplumber.open(str(path)) as pdf:
            for idx, fig in enumerate(figures, start=1):
                try:
                    page = pdf.pages[fig.page - 1]
                    page_im = page.to_image(resolution=dpi)
                    crop_im = page.crop(fig.bbox).to_image(resolution=dpi)
                    page_buf = io.BytesIO()
                    page_im.save(page_buf, format="PNG")
                    crop_buf = io.BytesIO()
                    crop_im.save(crop_buf, format="PNG")
                    page_bytes = len(page_buf.getvalue())
                    crop_bytes = len(crop_buf.getvalue())
                    page_px = page_im.original.size[0] * page_im.original.size[1]
                    crop_px = crop_im.original.size[0] * crop_im.original.size[1]
                    rows.append((fig, page_bytes, crop_bytes, page_px, crop_px))
                    if out_dir is not None:
                        out_dir.mkdir(parents=True, exist_ok=True)
                        out_path = out_dir / f"{path.stem[:32]}_p{fig.page}_{idx}.png"
                        crop_im.save(out_path, format="PNG")
                except Exception as e:
                    print(f"SKIP {path.name} p{fig.page}: {e}")
    except Exception as e:
        print(f"WARN {path.name}: {e}")
        return []
    return rows


def _print_text_table(rows: list[TextCompare]) -> None:
    """Print the text-extraction comparison table."""
    header = (
        f"{'NAME':<40}  {'MD_CHARS':>9}  {'PP_CHARS':>9}  {'DELTA%':>8}  "
        f"{'MD_OBS':>7}  {'PP_OBS':>7}  {'SHARED':>7}  {'KEPT%':>7}"
    )
    print(header)
    print("-" * len(header))
    total_md_chars = 0
    total_pp_chars = 0
    total_md_obs = 0
    total_pp_obs = 0
    total_shared = 0
    for row in rows:
        name = row.path
        if len(name) > 40:
            name = name[:39] + "…"
        if row.error is not None:
            print(f"{name:<40}  ERROR: {row.error}")
            continue
        delta = 0.0
        if row.markitdown_chars:
            delta = ((row.pdfplumber_chars - row.markitdown_chars)
                     / row.markitdown_chars * 100)
        kept = row.shared_obs / row.markitdown_obs * 100 if row.markitdown_obs != 0 else 0.0
        print(
            f"{name:<40}  {row.markitdown_chars:>9}  {row.pdfplumber_chars:>9}  "
            f"{delta:>8.1f}  {row.markitdown_obs:>7}  {row.pdfplumber_obs:>7}  "
            f"{row.shared_obs:>7}  {kept:>7.1f}"
        )
        total_md_chars += row.markitdown_chars
        total_pp_chars += row.pdfplumber_chars
        total_md_obs += row.markitdown_obs
        total_pp_obs += row.pdfplumber_obs
        total_shared += row.shared_obs
    print()
    global_kept = total_shared / total_md_obs * 100 if total_md_obs != 0 else 0.0
    print(
        f"TOTALS: MD_CHARS={total_md_chars} PP_CHARS={total_pp_chars} "
        f"MD_OBS={total_md_obs} PP_OBS={total_pp_obs} "
        f"SHARED={total_shared} KEPT%={global_kept:.1f}"
    )


def _print_crop_table(name: str, rows: list[tuple[Figure, int, int, int, int]]) -> None:
    """Print the page-vs-crop comparison table for one document."""
    header = (
        f"{'PAGE':>5}  {'AREA%':>6}  {'PAGE_KB':>8}  {'CROP_KB':>8}  "
        f"{'RATIO':>6}  {'PAGE_PX':>10}  {'CROP_PX':>10}"
    )
    print(header)
    print("-" * len(header))
    ratios: list[float] = []
    px_ratios: list[float] = []
    for fig, page_bytes, crop_bytes, page_px, crop_px in rows:
        area_pct = fig.area_ratio * 100
        page_kb = page_bytes / 1024
        crop_kb = crop_bytes / 1024
        if crop_bytes == 0:
            ratio_str = "inf"
        else:
            ratio = page_bytes / crop_bytes
            ratio_str = f"{ratio:.2f}"
            ratios.append(ratio)
        page_px_k = page_px / 1000
        crop_px_k = crop_px / 1000
        if crop_px != 0:
            px_ratios.append(page_px / crop_px)
        print(
            f"{fig.page:>5}  {area_pct:>6.1f}  {page_kb:>8.1f}  {crop_kb:>8.1f}  "
            f"{ratio_str:>6}  {page_px_k:>10.1f}k  {crop_px_k:>10.1f}k"
        )
    print()
    print(f"Figures: {len(rows)}")
    if ratios:
        print(f"Median RATIO: {statistics.median(ratios):.2f}")
    if px_ratios:
        print(f"Median PX RATIO: {statistics.median(px_ratios):.2f}")


def main(argv: list[str] | None = None) -> int:
    """Entry point for the Stage 1f tradeoff measurement script."""
    parser = argparse.ArgumentParser(description="Measure Stage 1f tradeoffs on real PDFs.")
    parser.add_argument("paths", nargs="*", default=["uploads"], help="PDF files or directories (non-recursive).")
    parser.add_argument("--dpi", type=int, default=RENDER_DPI, help="Render DPI for crop comparison.")
    parser.add_argument("--max-figures", type=int, default=6, help="Max figures compared per document.")
    parser.add_argument("--save-crops", type=str, default=None, help="Output directory for cropped PNGs.")
    parser.add_argument("--skip-text", action="store_true", help="Skip Question A (text comparison).")
    parser.add_argument("--skip-crops", action="store_true", help="Skip Question B (crop comparison).")
    args = parser.parse_args(argv)

    pdf_files: list[Path] = []
    for p in args.paths:
        path = Path(p)
        if path.is_file() and path.suffix.lower() == ".pdf":
            pdf_files.append(path)
        elif path.is_dir():
            for f in sorted(path.iterdir()):
                if f.is_file() and f.suffix.lower() == ".pdf":
                    pdf_files.append(f)
    pdf_files = sorted(set(pdf_files), key=lambda x: x.name)

    if not pdf_files:
        print("No PDFs found.")
        return 1

    filtered: list[Path] = []
    for f in pdf_files:
        if f.stat().st_size > 200 * 1024 * 1024:
            print(f"SKIP {f.name} (too large)")
        else:
            filtered.append(f)

    if not filtered:
        print("No PDFs found.")
        return 1

    if not args.skip_text:
        print("QUESTION A - markitdown vs pdfplumber")
        rows = [_compare_text(f) for f in filtered]
        _print_text_table(rows)
        print()

    if not args.skip_crops:
        print("QUESTION B - page vs crop")
        out_dir = Path(args.save_crops) if args.save_crops else None
        for f in filtered:
            try:
                with pdfplumber.open(str(f)) as pdf:
                    figures = _figures(pdf)
            except Exception as e:
                print(f"WARN {f.name}: {e}")
                continue
            figures = figures[:args.max_figures]
            if not figures:
                continue
            print(f"\n{f.name}")
            crop_rows = _compare_crops(f, figures, args.dpi, out_dir)
            _print_crop_table(f.name, crop_rows)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
