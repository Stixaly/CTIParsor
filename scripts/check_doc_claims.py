"""Documentation drift guard.

Recalculates every precise number claimed in README.md from the source of
truth (JSON data files and Python module constants) and reports any
discrepancy.

Usage:
    python scripts/check_doc_claims.py
    python scripts/check_doc_claims.py --readme docs/README.md --quiet

Exit codes:
    0  all checks OK or SKIP
    1  at least one FAIL
    2  README file not found
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"

_NUM = "[\\d\\u202f\\u00a0, ]+"


@dataclass(frozen=True)
class Claim:
    """One documented number, and how to recompute it from the source of truth."""
    label: str
    readme_pattern: str
    actual: Callable[[], float | int | None]
    tolerance: float = 0.0


def _json(path: Path) -> Any | None:
    """Load a JSON file, returning None if absent or unreadable."""
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _gazetteer_variants() -> int | None:
    """Count entries in pipeline/data/gazetteer.json."""
    data = _json(ROOT / "pipeline" / "data" / "gazetteer.json")
    if not isinstance(data, list):
        return None
    return len(data)


def _gazetteer_canonicals() -> int | None:
    """Count distinct canonical names in the gazetteer."""
    data = _json(ROOT / "pipeline" / "data" / "gazetteer.json")
    if not isinstance(data, list):
        return None
    canonicals = set()
    for entry in data:
        if isinstance(entry, dict) and "canonical" in entry:
            canonicals.add(str(entry["canonical"]).lower())
    return len(canonicals)


def _embed_total() -> int | None:
    """Count entries in pipeline/data/mitre_embeddings_meta.json."""
    data = _json(ROOT / "pipeline" / "data" / "mitre_embeddings_meta.json")
    if not isinstance(data, list):
        return None
    return len(data)


def _embed_attack() -> int | None:
    """Count ATT&CK entries (id starts with 'T') in the embeddings meta."""
    data = _json(ROOT / "pipeline" / "data" / "mitre_embeddings_meta.json")
    if not isinstance(data, list):
        return None
    count = 0
    for entry in data:
        if isinstance(entry, dict) and "id" in entry:
            eid = str(entry["id"])
            if eid.upper().startswith("T"):
                count += 1
    return count


def _attack_pairs() -> int | None:
    """Length of the 'pairs' list in pipeline/data/attack_relationships.json."""
    data = _json(ROOT / "pipeline" / "data" / "attack_relationships.json")
    if not isinstance(data, dict):
        return None
    pairs = data.get("pairs")
    if not isinstance(pairs, list):
        return None
    return len(pairs)


def _country_names() -> int | None:
    """Count ISO country pairs in _COUNTRY_ISO in stage4_stix_mapping.py."""
    path = ROOT / "pipeline" / "stage4_stix_mapping.py"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if "_COUNTRY_ISO: dict[str, str] = {" in line:
            start = i
            break
    if start is None:
        return None

    block_lines = []
    for line in lines[start + 1:]:
        if line.strip() == "}":
            break
        block_lines.append(line)
    block = "\n".join(block_lines)

    # The literal packs several pairs per physical line, so the pattern must not
    # be line-anchored — counting one match per line undercounts it by ~4x.
    pattern = re.compile(r'"[^"]+"\s*:\s*"[A-Z]{2}"')
    return len(pattern.findall(block))


def _src_const(rel_path: str, name: str) -> float | None:
    """Extract a numeric constant from a Python source file.

    Looks for lines like:
        <name> = <number>
        <name>: <annotation> = <number>
    """
    path = ROOT / rel_path
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None

    # Pattern: name = number  OR  name: annotation = number
    # A trailing `# comment` is common on these constants, so it must be allowed
    # before the end of line — anchoring on the number alone makes every
    # commented constant silently unreadable (reported as SKIP, not FAIL).
    pattern = re.compile(
        r"^\s*" + re.escape(name)
        + r"\s*(?::\s*[^=]+)?=\s*(\d+(?:\.\d+)?)\s*(?:#.*)?$",
        re.MULTILINE,
    )
    m = pattern.search(text)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


CLAIMS: list[Claim] = [
    Claim("gazetteer name variants",
          r"Aho-Corasick scan over (" + _NUM + r") name variants",
          _gazetteer_variants),
    Claim("gazetteer unique canonicals",
          r"name variants \((" + _NUM + r") unique malware",
          _gazetteer_canonicals),
    Claim("semantic corpus: ATT&CK entries",
          r"ATT&CK-only by default \((" + _NUM + r") of " + _NUM + r"\)",
          _embed_attack),
    Claim("semantic corpus: total entries",
          r"ATT&CK-only by default \(" + _NUM + r" of (" + _NUM + r")\)",
          _embed_total),
    Claim("ATT&CK curated grounding pairs",
          r"MITRE-curated edges \((" + _NUM + r") G/S/T pairs\)",
          _attack_pairs),
    Claim("targeted-country ISO table size",
          r"ISO 3166-1 lookup, (" + _NUM + r")\+ nations",
          _country_names,
          tolerance=40.0),
    # Anchored on each tier's length prefix, not on the number itself: a pattern
    # that hardcodes "92%" stops matching the moment the number drifts, which
    # reports SKIP ("not found") instead of the FAIL the drift deserves.
    Claim("hallucination filter: short-name threshold",
          r"≤ 5 chars.*?(\d+)% similarity threshold",
          lambda: _src_const("pipeline/stage3b_validate.py", "_THRESHOLD_SHORT")),
    Claim("hallucination filter: medium-name threshold",
          r"6–9 chars.*?(\d+)% similarity threshold",
          lambda: _src_const("pipeline/stage3b_validate.py", "_THRESHOLD_MEDIUM")),
    Claim("hallucination filter: long-name threshold",
          r"≥ 10 chars.*?(\d+)% similarity threshold",
          lambda: _src_const("pipeline/stage3b_validate.py", "_THRESHOLD_LONG")),
    Claim("MITRE normalisation: high-confidence score",
          r"Score ≥ (\d+) : canonical name",
          lambda: _src_const("pipeline/stage3c_mitre.py", "_HIGH_CONF")),
    Claim("MITRE normalisation: medium-confidence floor",
          r"Score (\d+)–84: keep LLM phrasing",
          lambda: _src_const("pipeline/stage3c_mitre.py", "_MEDIUM_CONF")),
]


def _to_number(raw: str) -> float | None:
    """Convert a raw number string (with thousands separators) to float.

    Strips U+202F, U+00A0, regular space, and comma before conversion.
    Returns None if the result is not a valid number.
    """
    cleaned = raw.replace("\u202f", "").replace("\u00a0", "").replace(" ", "").replace(",", "")
    try:
        return float(cleaned)
    except ValueError:
        return None


def _fmt(n: float) -> str:
    """Format a number without a superfluous decimal part."""
    if n == int(n):
        return str(int(n))
    return str(n)


def check_all(readme_text: str) -> list[tuple[str, str, str, str]]:
    """Run every claim. Returns rows of (status, label, documented, actual).

    status is one of "OK", "FAIL", "SKIP".
    """
    rows: list[tuple[str, str, str, str]] = []
    for claim in CLAIMS:
        m = re.search(claim.readme_pattern, readme_text)
        if m is None:
            rows.append(("SKIP", claim.label, "not found in README", ""))
            continue

        # Extract the documented number
        if m.groups():
            raw = m.group(1)
        else:
            num_match = re.search(r"\d+(?:\.\d+)?", m.group(0))
            if num_match is None:
                rows.append(("SKIP", claim.label, "not found in README", ""))
                continue
            raw = num_match.group(0)

        documented = _to_number(raw)
        if documented is None:
            rows.append(("SKIP", claim.label, raw, ""))
            continue

        actual = claim.actual()
        if actual is None:
            rows.append(("SKIP", claim.label, _fmt(documented), "source unavailable"))
            continue

        if abs(documented - actual) <= claim.tolerance:
            status = "OK"
        else:
            status = "FAIL"
        rows.append((status, claim.label, _fmt(documented), _fmt(float(actual))))
    return rows


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Check README.md numbers against the source of truth."
    )
    parser.add_argument(
        "--readme",
        type=Path,
        default=README,
        help="Path to the README file to check (default: %(default)s)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print FAIL lines and the final summary.",
    )
    args = parser.parse_args()

    readme_path: Path = args.readme
    if not readme_path.is_file():
        print(f"error: README not found: {readme_path}", file=sys.stderr)
        return 2

    try:
        readme_text = readme_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {readme_path}: {exc}", file=sys.stderr)
        return 2

    rows = check_all(readme_text)

    # Compute column widths
    headers = ("STATUS", "CLAIM", "DOCUMENTED", "ACTUAL")
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def _print_row(cells: tuple[str, ...]) -> None:
        parts = [cell.ljust(col_widths[i]) for i, cell in enumerate(cells)]
        print("  ".join(parts).rstrip())

    if not args.quiet:
        _print_row(headers)

    for row in rows:
        if args.quiet and row[0] != "FAIL":
            continue
        _print_row(row)

    ok_count = sum(1 for r in rows if r[0] == "OK")
    fail_count = sum(1 for r in rows if r[0] == "FAIL")
    skip_count = sum(1 for r in rows if r[0] == "SKIP")
    total = len(rows)
    print(f"{total} checks - {ok_count} OK, {fail_count} FAIL, {skip_count} SKIP")

    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
