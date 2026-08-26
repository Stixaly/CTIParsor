from __future__ import annotations

import argparse
import dataclasses
import json
import re
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Ensure the project root is on sys.path so `pipeline.*` is importable when this
# script is run directly from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.stage1_ingestion import chunk_text, ingest
from pipeline.web_capture import _PLAYWRIGHT_AVAILABLE, _USER_AGENT, CaptureError, capture_url_to_pdf

# A spread of real CTI publishing stacks, chosen because they fail differently:
# WordPress with a table of contents, a vendor blog behind a CDN, a static site
# generator, and a government advisory in plain HTML.  If capture only works on
# one of these, the feature does not work.
_DEFAULT_URLS = (
    "https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a",
    "https://unit42.paloaltonetworks.com/muddled-libra/",
    "https://securelist.com/apt-trends-report-q1-2024/112473/",
)

# Deliberately loose patterns.  This script measures whether an observable
# SURVIVES the PDF round-trip, not whether it is a true positive — a defanged
# form counts, because the pipeline defangs later anyway.
_IOC_PATTERNS = (
    ("ipv4",   r"\b(?:\d{1,3}[\[\(]?\.[\]\)]?){3}\d{1,3}\b"),
    ("sha256", r"\b[A-Fa-f0-9]{64}\b"),
    ("md5",    r"\b[A-Fa-f0-9]{32}\b"),
    ("domain", r"\b(?:[a-zA-Z0-9-]+[\[\(]?\.[\]\)]?)+(?:com|net|org|ru|cn|io|xyz|top|info)\b"),
    ("cve",    r"\bCVE-\d{4}-\d{4,7}\b"),
    ("attack", r"\bT\d{4}(?:\.\d{3})?\b"),
)

_IOC_RE = tuple((name, re.compile(pattern)) for name, pattern in _IOC_PATTERNS)


@dataclass
class Measurement:
    url: str
    ok: bool
    error: str = ""
    capture_s: float = 0.0
    ingest_s: float = 0.0
    pdf_bytes: int = 0
    blocked: int = 0
    title: str = ""
    dom_chars: int = 0
    pdf_chars: int = 0
    retention: float = 0.0
    chunks: int = 0
    iocs_dom: int = 0
    iocs_pdf: int = 0
    iocs_lost: int = 0


def _extract_iocs(text: str) -> set[str]:
    """Extract and normalize IOCs from text using pre-compiled patterns."""
    found: set[str] = set()
    for _name, pattern in _IOC_RE:
        for match in pattern.finditer(text):
            cleaned = match.group(0).lower().replace("[", "").replace("]", "").replace("(", "").replace(")", "")
            found.add(cleaned)
    return found


def _read_dom_text(url: str, timeout_ms: int = 30_000) -> str:
    """
    Read visible text from the DOM as the reference the PDF is measured against.

    JavaScript is disabled here for the same reason `capture_url_to_pdf` disables
    it — and reading it *with* JS makes the comparison meaningless, because the
    two sides then load different pages.  It is not a hypothetical: on
    unit42.paloaltonetworks.com the JS-enabled body is **0 characters** (bot
    protection blanks the page for a headless browser) against 25,909 with JS
    off, which silently scored two rows at 0% retention.

    The failure reason is printed rather than swallowed: a reference that
    quietly returns "" makes every derived number wrong in a way that looks like
    data.
    """
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                context = browser.new_context(
                    java_script_enabled=False,
                    user_agent=_USER_AGENT,
                )
                page = context.new_page()
                page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                return page.inner_text("body")
            finally:
                browser.close()
    except Exception as exc:
        print(f"  [dom-read failed] {url}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return ""


def measure_one(url: str, workdir: Path, *, enable_js: bool, timeout_ms: int) -> Measurement:
    """Measure the PDF capture and ingestion quality for a single URL."""
    dest = workdir / f"{abs(hash(url))}.pdf"

    try:
        start = time.perf_counter()
        result = capture_url_to_pdf(url, dest, enable_js=enable_js, timeout_ms=timeout_ms)
        capture_s = time.perf_counter() - start
    except CaptureError as exc:
        return Measurement(url=url, ok=False, error=str(exc))

    try:
        start = time.perf_counter()
        pdf_text = ingest(str(dest))
        ingest_s = time.perf_counter() - start
    except Exception as exc:
        return Measurement(url=url, ok=False, error=f"ingest failed: {exc}")

    dom_text = _read_dom_text(url, timeout_ms)

    dom_chars = len(dom_text)
    pdf_chars = len(pdf_text)
    retention = pdf_chars / dom_chars if dom_chars else 0.0
    chunks = len(chunk_text(pdf_text))

    dom_set = _extract_iocs(dom_text)
    pdf_set = _extract_iocs(pdf_text)
    iocs_dom = len(dom_set)
    iocs_pdf = len(pdf_set)
    iocs_lost = len(dom_set - pdf_set)

    return Measurement(
        url=url,
        ok=True,
        capture_s=capture_s,
        ingest_s=ingest_s,
        pdf_bytes=result.bytes_written,
        blocked=result.blocked_requests,
        title=result.title,
        dom_chars=dom_chars,
        pdf_chars=pdf_chars,
        retention=retention,
        chunks=chunks,
        iocs_dom=iocs_dom,
        iocs_pdf=iocs_pdf,
        iocs_lost=iocs_lost,
    )


def _fmt_table(rows: list[Measurement]) -> str:
    """Format measurements into a fixed-width text table."""
    headers = ["HOST", "CAP s", "ING s", "PDF KB", "BLK", "DOM ch", "PDF ch", "KEEP", "CHK", "IOC D/P", "LOST"]
    widths = [26, 6, 6, 7, 4, 8, 8, 6, 4, 9, 5]

    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, widths))
    sep_line = "-+-".join("-" * w for w in widths)

    lines = [header_line, sep_line]

    for row in rows:
        host = urlparse(row.url).hostname or row.url
        host = host[:26]

        if not row.ok:
            error_msg = row.error[:60]
            line = host.ljust(26) + " | " + error_msg
            lines.append(line)
            continue

        cap_s = f"{row.capture_s:.1f}"
        ing_s = f"{row.ingest_s:.1f}"
        pdf_kb = str(row.pdf_bytes // 1024)
        blk = str(row.blocked)
        dom_ch = str(row.dom_chars)
        pdf_ch = str(row.pdf_chars)
        keep = f"{row.retention * 100:.0f}%"
        chk = str(row.chunks)
        ioc_dp = f"{row.iocs_dom}/{row.iocs_pdf}"
        lost = str(row.iocs_lost)

        values = [host, cap_s, ing_s, pdf_kb, blk, dom_ch, pdf_ch, keep, chk, ioc_dp, lost]
        line = " | ".join(v.ljust(w) for v, w in zip(values, widths))
        lines.append(line)

    return "\n".join(lines)


def _fmt_summary(rows: list[Measurement]) -> str:
    """Generate a summary of the measurements and a verdict."""
    successful = [r for r in rows if r.ok]
    total = len(rows)
    captured = len(successful)

    lines = []
    lines.append(f"captured: {captured}/{total}")

    retentions = [r.retention for r in successful if r.dom_chars > 0]
    if retentions:
        median_retention = statistics.median(retentions)
        lines.append(f"median retention: {median_retention * 100:.1f}%")
    else:
        median_retention = 0.0
        lines.append("median retention: n/a")

    if successful:
        median_cap = statistics.median([r.capture_s for r in successful])
        median_ing = statistics.median([r.ingest_s for r in successful])
        lines.append(f"median capture: {median_cap:.1f}s")
        lines.append(f"median ingest: {median_ing:.1f}s")
    else:
        lines.append("median capture: n/a")
        lines.append("median ingest: n/a")

    total_iocs_dom = sum(r.iocs_dom for r in successful)
    total_iocs_lost = sum(r.iocs_lost for r in successful)
    lines.append(f"IOCs lost in the PDF round-trip: {total_iocs_lost} of {total_iocs_dom}")

    total_blocked = sum(r.blocked for r in successful)
    lines.append(f"blocked subrequests: {total_blocked}")

    # The verdict is driven by IOC survival, not by character retention.
    # Retention was the first cut and it lied: on the COLDRIVER report it read
    # 98% while 9 of 12 SHA-256 hashes were destroyed — the IOC table renders in
    # a narrow column, so each 64-char hash wraps into 24-char fragments that the
    # PDF text layer then interleaves with the neighbouring cells.  A report's
    # IOC table is the part an analyst came for; losing it while keeping the
    # prose is the worst possible trade, and only this ratio sees it.
    ioc_kept = (total_iocs_dom - total_iocs_lost) / total_iocs_dom if total_iocs_dom else None
    if ioc_kept is not None:
        lines.append(f"IOC survival: {ioc_kept * 100:.1f}%  (chars: {median_retention * 100:.1f}%)")

    if ioc_kept is None:
        verdict = "no IOCs in the reference — inconclusive, re-run on pages with an IOC table"
    elif ioc_kept >= 0.95:
        verdict = "PDF round-trip is faithful — keep ingesting the PDF"
    elif ioc_kept >= 0.80:
        verdict = "PDF round-trip is lossy — check which observable types are dropping"
    else:
        verdict = "PDF round-trip destroys observables — ingest the DOM text, keep the PDF for display"

    lines.append(verdict)

    return "\n".join(lines)


def main() -> int:
    """Main entry point for the web capture measurement script."""
    if not _PLAYWRIGHT_AVAILABLE:
        print(
            "Playwright is not installed. Run:\n"
            "  pip install playwright\n"
            "  python -m playwright install chromium\n"
            "  sudo python -m playwright install-deps chromium",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(description="Measure PDF capture and ingestion quality")
    parser.add_argument("urls", nargs="*", default=_DEFAULT_URLS)
    parser.add_argument("--enable-js", action="store_true")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--json", type=str, default=None)
    parser.add_argument("--keep", action="store_true")

    args = parser.parse_args()

    if args.keep:
        workdir = Path("output/web_capture_samples")
        workdir.mkdir(parents=True, exist_ok=True)
        temp_dir = None
    else:
        temp_dir = tempfile.TemporaryDirectory()
        workdir = Path(temp_dir.name)

    rows: list[Measurement] = []
    n = len(args.urls)

    for i, url in enumerate(args.urls):
        print(f"[{i+1}/{n}] {url}", file=sys.stderr, flush=True)
        row = measure_one(url, workdir, enable_js=args.enable_js, timeout_ms=args.timeout_ms)
        rows.append(row)

    print(_fmt_table(rows))
    print()
    print(_fmt_summary(rows))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([dataclasses.asdict(r) for r in rows], f, indent=2)

    if temp_dir:
        temp_dir.cleanup()

    return 0 if any(r.ok for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
