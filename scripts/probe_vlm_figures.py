from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pdfplumber
from pdf2image import convert_from_path

try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

OLLAMA_URL = "http://192.168.0.29:11434/api/generate"
DEFAULT_MODEL = "qwen3.8"
ANTHROPIC_MODEL = "claude-opus-5"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
RENDER_DPI = 150
REQUEST_TIMEOUT_S = 900

# Asks the model for exactly the three things Stage 1f would need from a
# figure: what kind of object it is, the text it carries verbatim, and the
# directed edges it draws.  Deliberately forbids prose so the answer can be
# compared across models.
PROMPT = """You are reading one page of a cyber threat intelligence report.

Answer with JSON only, no prose, matching this schema:
{
  "figure_kind": "network-diagram|attack-chain|screenshot|code-listing|table|chart|logo|none",
  "verbatim_text": ["every text string visible inside the figure, exactly as written"],
  "edges": [{"src": "node label", "dst": "node label", "label": "arrow label or empty"}],
  "iocs": ["any IP, domain, URL, hash, file path or registry key visible"]
}

If the page carries no figure, return figure_kind "none" with empty lists."""

_anthropic_client = None


@dataclass
class PageScore:
    pdf: Path
    page: int          # 1-indexed
    fig_area: float    # somme des aires d'image / aire de la page


def _page_scores(path: Path) -> list[PageScore]:
    """Compute per-page figure area ratio for a single PDF."""
    scores: list[PageScore] = []
    try:
        with pdfplumber.open(path) as pdf:
            for i, page in enumerate(pdf.pages, start=1):
                page_area = page.width * page.height
                if page_area <= 0:
                    continue
                fig_area = 0.0
                for im in page.images:
                    try:
                        x0 = float(im["x0"])
                        x1 = float(im["x1"])
                        top = float(im["top"])
                        bottom = float(im["bottom"])
                        area = abs(x1 - x0) * abs(bottom - top)
                        fig_area += area / page_area
                    except (TypeError, ValueError, AttributeError):
                        continue
                fig_area = min(fig_area, 1.0)
                if fig_area >= 0.05:
                    scores.append(PageScore(pdf=path, page=i, fig_area=fig_area))
    except Exception as e:
        print(f"WARN {path.name}: {e}", file=sys.stderr)
        return []
    return scores


def _top_pages(pdfs: list[Path], per_pdf: int) -> list[PageScore]:
    """Select top pages per PDF by figure area, sorted descending."""
    all_scores: list[PageScore] = []
    for pdf in pdfs:
        all_scores.extend(_page_scores(pdf))

    # Group by pdf and keep top per_pdf for each
    from collections import defaultdict
    by_pdf: dict[Path, list[PageScore]] = defaultdict(list)
    for s in all_scores:
        by_pdf[s.pdf].append(s)

    selected: list[PageScore] = []
    for pdf, scores in by_pdf.items():
        scores.sort(key=lambda x: x.fig_area, reverse=True)
        selected.extend(scores[:per_pdf])

    selected.sort(key=lambda x: x.fig_area, reverse=True)
    return selected


def _render(score: PageScore, out_dir: Path, dpi: int) -> Path:
    """Render a single page to PNG and return the output path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{score.pdf.stem[:40]}_p{score.page}.png"
    images = convert_from_path(
        str(score.pdf), dpi=dpi, first_page=score.page, last_page=score.page
    )
    if not images:
        raise RuntimeError(f"render failed: {score.pdf}#{score.page}")
    img = images[0]
    try:
        img.save(out_path, format="PNG")
    finally:
        img.close()
    return out_path


def _ask_ollama(png: Path, model: str, prompt: str) -> tuple[str, float]:
    """Send a PNG to the Ollama VLM and return (response, elapsed_seconds)."""
    b64 = base64.b64encode(png.read_bytes()).decode("ascii")
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "images": [b64],
        "stream": False,
        "think": False,
        "options": {
            "num_ctx": 8192,
            "temperature": 0.0,
            "num_predict": 1500,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        elapsed = time.monotonic() - t0
        return data["response"], elapsed
    except Exception as e:
        elapsed = time.monotonic() - t0
        return f"ERROR: {type(e).__name__}: {e}", elapsed


def _ask_anthropic(png: Path, model: str, prompt: str) -> tuple[str, float]:
    """Send a PNG to the Anthropic API and return (response, elapsed_seconds)."""
    global _anthropic_client

    t0 = time.monotonic()
    try:
        # Client construction and file read live inside the try so a missing
        # ANTHROPIC_API_KEY or an unreadable PNG returns the error string this
        # function promises, instead of killing the whole probe loop.
        if _anthropic_client is None:
            _anthropic_client = anthropic.Anthropic()
        b64 = base64.b64encode(png.read_bytes()).decode("ascii")
        response = _anthropic_client.messages.create(
            model=model,
            max_tokens=4000,
            messages=[{
                "role": "user",
                "content": [
                    {"type": "image",
                     "source": {"type": "base64",
                                "media_type": "image/png",
                                "data": b64}},
                    {"type": "text", "text": prompt},
                ],
            }],
        )
        elapsed = time.monotonic() - t0
        text = "".join(b.text for b in response.content if b.type == "text")
        text += f"\n[usage] in={response.usage.input_tokens} out={response.usage.output_tokens}"
        return text, elapsed
    except Exception as e:
        elapsed = time.monotonic() - t0
        return f"ERROR: {type(e).__name__}: {e}", elapsed


def main(argv: list[str] | None = None) -> int:
    """Entry point for the VLM figure probe script."""
    parser = argparse.ArgumentParser(description="Probe VLM on figured PDF pages.")
    parser.add_argument("paths", nargs="*", default=["uploads"],
                        help="PDF files or directories (non-recursive)")
    parser.add_argument("--model", default=None)
    parser.add_argument("--per-pdf", type=int, default=1)
    parser.add_argument("--limit", type=int, default=4)
    parser.add_argument("--dpi", type=int, default=RENDER_DPI)
    parser.add_argument("--out", default="out/vlm_probe")
    parser.add_argument("--render-only", action="store_true")
    parser.add_argument("--backend", choices=["ollama", "anthropic"], default="ollama")
    args = parser.parse_args(argv)

    if args.model is None:
        if args.backend == "ollama":
            args.model = DEFAULT_MODEL
        else:
            args.model = ANTHROPIC_MODEL

    if args.backend == "anthropic" and not _ANTHROPIC_AVAILABLE:
        print("anthropic SDK not installed")
        return 1

    # Collect PDF files
    pdfs: list[Path] = []
    for p in args.paths:
        path = Path(p)
        if path.is_file() and path.suffix.lower() == ".pdf":
            pdfs.append(path)
        elif path.is_dir():
            for f in sorted(path.iterdir()):
                if f.is_file() and f.suffix.lower() == ".pdf":
                    pdfs.append(f)

    if not pdfs:
        print("No figured pages found.")
        return 1

    scores = _top_pages(pdfs, args.per_pdf)[:args.limit]

    if not scores:
        print("No figured pages found.")
        return 1

    out_dir = Path(args.out)
    total_model_time = 0.0
    n_pages = 0

    for score in scores:
        try:
            png = _render(score, out_dir, args.dpi)
        except Exception as e:
            print(f"SKIP {score.pdf.name} p{score.page}: {e}")
            continue

        size_ko = png.stat().st_size / 1024
        print(f"=== {score.pdf.name} page {score.page}  fig_area={score.fig_area:.2f}  -> {png} ({size_ko:.0f} Ko)")

        if not args.render_only:
            if args.backend == "ollama":
                response, elapsed = _ask_ollama(png, args.model, PROMPT)
            else:
                response, elapsed = _ask_anthropic(png, args.model, PROMPT)
            total_model_time += elapsed
            print(f"--- {args.backend}/{args.model} in {elapsed:.1f}s ---")
            print(response)

        n_pages += 1

    print(f"TOTAL {n_pages} pages, {total_model_time:.1f}s de modèle ({args.backend}/{args.model})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
