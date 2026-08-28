from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

import pdfplumber
from bs4 import BeautifulSoup


@dataclass
class ImageStat:
    page: int
    width_pt: float
    height_pt: float
    area_ratio: float
    kind: str


@dataclass
class DocStat:
    path: str
    kind: str
    pages: int
    chars: int
    images: list[ImageStat] = field(default_factory=list)
    error: str | None = None
    inline_images: int = 0
    inline_bytes: int = 0
    pre_blocks: int = 0
    tables: int = 0


def _classify(area_ratio: float, width_pt: float, height_pt: float) -> str:
    if width_pt < 48.0 or height_pt < 48.0:
        return "icon"
    if area_ratio < 0.02:
        return "icon"
    if height_pt > 0 and (width_pt / height_pt) > 6.0:
        return "banner"
    return "figure"


def _scan_pdf(path: Path) -> DocStat:
    try:
        pages = 0
        chars = 0
        images: list[ImageStat] = []
        with pdfplumber.open(path) as pdf:
            for i, page in enumerate(pdf.pages, start=1):
                pages += 1
                page_area = page.width * page.height
                text = page.extract_text() or ""
                chars += len(text)
                for im in page.images:
                    try:
                        x0 = float(im.get("x0", 0))
                        x1 = float(im.get("x1", 0))
                        top = float(im.get("top", 0))
                        bottom = float(im.get("bottom", 0))
                        width_pt = abs(x1 - x0)
                        height_pt = abs(bottom - top)
                        if page_area > 0:
                            area_ratio = min((width_pt * height_pt) / page_area, 1.0)
                        else:
                            area_ratio = 0.0
                        kind = _classify(area_ratio, width_pt, height_pt)
                        images.append(ImageStat(i, width_pt, height_pt, area_ratio, kind))
                    except (TypeError, ValueError, AttributeError):
                        continue
        return DocStat(str(path), "pdf", pages, chars, images)
    except Exception as e:
        return DocStat(str(path), "pdf", 0, 0, [], str(e))


def _scan_html(path: Path) -> DocStat:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        soup = BeautifulSoup(content, "html.parser")
        for tag in soup.find_all(["script", "style", "noscript", "template"]):
            tag.decompose()
        chars = len(soup.get_text(separator="\n"))
        images: list[ImageStat] = []
        inline_images = 0
        inline_bytes = 0
        for img in soup.find_all("img"):
            try:
                width_pt = float(img.get("width", 0))
            except (TypeError, ValueError):
                width_pt = 0.0
            try:
                height_pt = float(img.get("height", 0))
            except (TypeError, ValueError):
                height_pt = 0.0
            kind = _classify(0.0, width_pt, height_pt)
            images.append(ImageStat(1, width_pt, height_pt, 0.0, kind))
            src = img.get("src", "")
            if src.startswith("data:image"):
                inline_images += 1
                inline_bytes += len(src.encode("utf-8"))
        pre_blocks = len(soup.find_all("pre"))
        tables = len(soup.find_all("table"))
        return DocStat(
            str(path), "html", 1, chars, images, None, inline_images, inline_bytes, pre_blocks, tables
        )
    except Exception as e:
        return DocStat(str(path), "html", 0, 0, [], str(e))


def _print_table(stats: list[DocStat]) -> None:
    header = (
        f"{'NAME':<44}  {'KIND':<5}  {'PAGES':<5}  {'CHARS':<8}  {'IMGS':<5}  "
        f"{'FIG':<4}  {'BAN':<4}  {'ICO':<4}  {'FIG%PAGE':<9}  {'PRE':<4}  {'TBL':<4}"
    )
    print(header)
    print("-" * len(header))

    total_pages = 0
    total_chars = 0
    total_images = 0
    total_figures = 0
    total_banners = 0
    total_icons = 0
    total_inline_images = 0
    total_inline_bytes = 0

    for s in stats:
        name = Path(s.path).name
        if len(name) > 44:
            name = name[:43] + "…"
        if s.error is not None:
            print(f"{name:<44}  ERROR: {s.error}")
            continue
        figs = sum(1 for i in s.images if i.kind == "figure")
        bans = sum(1 for i in s.images if i.kind == "banner")
        icos = sum(1 for i in s.images if i.kind == "icon")
        fig_area = sum(i.area_ratio for i in s.images if i.kind == "figure")
        fig_pct = (fig_area / s.pages * 100) if s.pages > 0 else 0.0
        print(
            f"{name:<44}  {s.kind:<5}  {s.pages:<5}  {s.chars:<8}  {len(s.images):<5}  "
            f"{figs:<4}  {bans:<4}  {icos:<4}  {fig_pct:<9.1f}  {s.pre_blocks:<4}  {s.tables:<4}"
        )
        total_pages += s.pages
        total_chars += s.chars
        total_images += len(s.images)
        total_figures += figs
        total_banners += bans
        total_icons += icos
        total_inline_images += s.inline_images
        total_inline_bytes += s.inline_bytes

    print()
    print("TOTAUX")
    print(f"  documents scannés : {len(stats)}")
    print(f"  pages             : {total_pages}")
    print(f"  caractères        : {total_chars}")
    print(f"  images totales    : {total_images}")
    print(f"  figures           : {total_figures}")
    print(f"  bannières         : {total_banners}")
    print(f"  icônes            : {total_icons}")
    fpp = (total_figures / total_pages * 10) if total_pages > 0 else 0.0
    print(f"  figures per 10 pages : {fpp:.1f}")
    print(f"  images inline HTML  : {total_inline_images}")
    print(f"  octets inline       : {total_inline_bytes / (1024 * 1024):.1f} Mo")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        argv = ["uploads", "input"]

    files: list[Path] = []
    for arg in argv:
        p = Path(arg)
        if p.is_dir():
            for f in sorted(p.iterdir()):
                if f.is_file() and f.suffix.lower() in (".pdf", ".html", ".htm"):
                    files.append(f)
        elif p.is_file():
            if p.suffix.lower() in (".pdf", ".html", ".htm"):
                files.append(p)

    filtered: list[Path] = []
    for f in files:
        try:
            size = f.stat().st_size
        except OSError:
            size = 0
        if size > 200 * 1024 * 1024:
            print(f"SKIP {f.name} (too large)")
        else:
            filtered.append(f)

    if not filtered:
        print("No documents found.")
        return 1

    stats: list[DocStat] = []
    for f in filtered:
        if f.suffix.lower() == ".pdf":
            stats.append(_scan_pdf(f))
        else:
            stats.append(_scan_html(f))

    _print_table(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
