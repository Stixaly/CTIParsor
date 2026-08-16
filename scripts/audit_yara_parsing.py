"""Read-only audit harness for ADR-0015 YARA parsing.

This script validates the project's YARA parser against real rule corpora
and measures three suspected defects:
  1. Escape corruption: parsed string values containing literal newlines/tabs.
  2. Private prefix: rules declared with two or more prefixes (e.g. "global private rule X").
  3. Section false positive: "meta:" or "strings:" markers found mid-line.

It does not modify any files.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.detection.yara_atoms import _strip_comments, split_rules

_RE_MULTI_PREFIX = re.compile(
    r"(?m)^[ \t]*((?:(?:private|global)[ \t]+){2,})rule[ \t]+(\w+)"
)


def iter_yara_files(root: Path, limit: int | None = None) -> Iterator[Path]:
    """Yield YARA files under root, skipping .git directories."""
    count = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".yar", ".yara", ".rule"):
            continue
        if ".git" in path.parts:
            continue
        yield path
        count += 1
        if limit is not None and count >= limit:
            break


def check_escape_corruption(rules: list, path: Path) -> list[dict]:
    """Report parsed string values containing literal newlines or tabs."""
    findings = []
    for rule in rules:
        for ident, kind, value in rule.strings:
            if kind != "text":
                continue
            if "\n" in value or "\t" in value:
                findings.append({
                    "file": str(path),
                    "rule": rule.name,
                    "ident": ident,
                    "value": value.replace("\n", "<NL>").replace("\t", "<TAB>")[:120],
                    "kind": "escape",
                })
    return findings


def check_private_prefix(text: str, path: Path) -> list[dict]:
    """Report rules declared with two or more prefixes."""
    findings = []
    stripped = _strip_comments(text)
    for m in _RE_MULTI_PREFIX.finditer(stripped):
        findings.append({
            "file": str(path),
            "rule": m.group(2),
            "prefix": m.group(1).strip(),
            "kind": "private_prefix",
        })
    return findings


def check_section_false_positive(rules: list, path: Path) -> list[dict]:
    """Report meta:/strings: markers found mid-line in rule bodies."""
    findings = []
    for rule in rules:
        body = rule.body
        for marker in ("meta:", "strings:"):
            idx = body.find(marker)
            if idx == -1:
                continue
            line_start = body.rfind("\n", 0, idx) + 1
            prefix = body[line_start:idx]
            if prefix.strip() != "":
                findings.append({
                    "file": str(path),
                    "rule": rule.name,
                    "marker": marker,
                    "line_prefix": prefix.strip()[:80],
                    "kind": "section",
                })
    return findings


def main() -> int:
    """Run the audit and print a report."""
    parser = argparse.ArgumentParser(description="YARA parsing audit harness")
    parser.add_argument("--root", default="corpora", type=str, help="Directory to walk")
    parser.add_argument("--limit", default=None, type=int, help="Max files to scan")
    parser.add_argument("--show", default=5, type=int, help="Findings to print per kind")
    args = parser.parse_args()

    root = Path(args.root)
    files_scanned = 0
    unreadable = 0
    crashed = 0
    rules_seen = 0
    crashes: list[tuple[str, str]] = []
    escape_findings: list[dict] = []
    prefix_findings: list[dict] = []
    section_findings: list[dict] = []

    for path in iter_yara_files(root, args.limit):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable += 1
            continue

        files_scanned += 1
        try:
            rules = split_rules(text)
            rules_seen += len(rules)
            escape_findings.extend(check_escape_corruption(rules, path))
            prefix_findings.extend(check_private_prefix(text, path))
            section_findings.extend(check_section_false_positive(rules, path))
        except Exception as exc:
            crashed += 1
            crashes.append((str(path), str(exc)))
            continue

    print("=== YARA parsing audit ===")
    print(f"files scanned   : {files_scanned}")
    print(f"unreadable      : {unreadable}")
    print(f"crashed         : {crashed}")
    print(f"rules parsed    : {rules_seen}")
    print()

    escape_files = {f["file"] for f in escape_findings}
    prefix_files = {f["file"] for f in prefix_findings}
    section_files = {f["file"] for f in section_findings}

    print(f"escape corruption : {len(escape_findings)} findings in {len(escape_files)} distinct files")
    print(f"private prefix    : {len(prefix_findings)} findings in {len(prefix_files)} distinct files")
    print(f"section marker    : {len(section_findings)} findings in {len(section_files)} distinct files")
    print()

    print(f"--- escape corruption (first {args.show}) ---")
    if not escape_findings:
        print("  (none)")
    else:
        for f in escape_findings[:args.show]:
            print(f"{f['file']}  {f['rule']}  {f['ident']}  {f['value']}")
    print()

    print(f"--- private prefix (first {args.show}) ---")
    if not prefix_findings:
        print("  (none)")
    else:
        for f in prefix_findings[:args.show]:
            print(f"{f['file']}  {f['rule']}  {f['prefix']}")
    print()

    print(f"--- section marker (first {args.show}) ---")
    if not section_findings:
        print("  (none)")
    else:
        for f in section_findings[:args.show]:
            print(f"{f['file']}  {f['rule']}  {f['marker']}  {f['line_prefix']}")
    print()

    print(f"--- crashes (first {args.show}) ---")
    if not crashes:
        print("  (none)")
    else:
        for file, exc in crashes[:args.show]:
            print(f"{file}  {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
