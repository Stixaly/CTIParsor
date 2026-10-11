"""Regenerate tests/fixtures/pdf_tables/: a report whose IoCs sit in a narrow
table column, printed to PDF by Chromium (audit B 8.1.5, its annex A.11).

    python scripts/make_pdf_table_fixtures.py

Needs Playwright's Chromium (`playwright install chromium`), which CI does not
have: the PDFs are committed, and tests/test_pdf_table_cells.py reads them.
The value column is 38 % or 20 % of the table with `word-break: break-all`,
so hashes and URLs wrap over two or three lines inside their cell.
"""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "pdf_tables"
WIDTHS = {"ioc_table_38pct.pdf": "38%", "ioc_table_20pct.pdf": "20%"}


def _values() -> dict[str, list[str]]:
    rng = random.Random(11)
    words = ["update", "cdn", "secure", "login", "portal", "static", "files", "sync", "cloud", "mail"]
    tlds = ["com", "net", "org", "info", "xyz", "top", "online", "site"]
    return {
        "sha256": [hashlib.sha256(f"sample-{i}".encode()).hexdigest() for i in range(12)],
        "domain": [f"{rng.choice(words)}-{rng.choice(words)}{i}.{tlds[i]}" for i in range(8)],
        "ipv4": [f"{rng.randint(23, 220)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
                 for _ in range(8)],
        "url": [f"https://{rng.choice(words)}-{rng.choice(words)}{i}.com/{rng.choice(words)}/"
                f"{rng.choice(words)}{i}.php?id={rng.randint(1000, 99999)}" for i in range(6)],
    }


def _defang(value: str) -> str:
    return value.replace("https://", "hxxps://").replace(".", "[.]")


def _html(values: dict[str, list[str]], width: str) -> str:
    rows = ([("SHA-256", h, "Loader sample") for h in values["sha256"]]
            + [("Domain", _defang(d), "C2 server") for d in values["domain"]]
            + [("IPv4", _defang(ip), "Staging host") for ip in values["ipv4"]]
            + [("URL", _defang(u), "Payload download") for u in values["url"]])
    random.Random(11).shuffle(rows)
    body = "".join(f'<tr><td>{t}</td><td class="v">{v}</td><td>{d}</td></tr>' for t, v, d in rows)
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
body {{ font-family: Arial, sans-serif; font-size: 10pt; margin: 2cm; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #888; padding: 4px; vertical-align: top; }}
td.v {{ width: {width}; word-break: break-all; font-family: monospace; }}
</style></head><body>
<h1>Threat report: Operation Example</h1>
<p>The actor delivered a loader by email. The indicators of compromise are listed below.</p>
<h2>Indicators of compromise</h2>
<table><tr><th>Type</th><th>Value</th><th>Description</th></tr>{body}</table>
<p>End of report.</p></body></html>"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    values = _values()
    (OUT / "truth.json").write_text(json.dumps(values, indent=1) + "\n", encoding="utf-8")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        for name, width in WIDTHS.items():
            page.set_content(_html(values, width))
            page.pdf(path=str(OUT / name), format="A4")
        browser.close()
    print(f"written {', '.join(WIDTHS)} and truth.json in {OUT}")


if __name__ == "__main__":
    main()
