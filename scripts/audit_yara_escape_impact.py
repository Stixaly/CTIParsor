"""Read-only measurement harness quantifying the ADR-0015 YARA unescape-order defect."""

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.detection.yara_atoms import (
    _RE_STRING_DECL,
    _classify_literal,
    _normalize,
    split_rules,
)


def unescape_buggy(val: str) -> str:
    """Reproduce the current buggy unescape behaviour."""
    val = val.replace('\\"', '"').replace("\\\\", "\\")
    val = val.replace("\\n", "\n").replace("\\t", "\t")
    return val


def unescape_correct(val: str) -> str:
    """Perform a correct single-pass left-to-right unescape."""
    parts = []
    i = 0
    n = len(val)
    while i < n:
        if val[i] == "\\" and i + 1 < n:
            c = val[i + 1]
            if c == "n":
                parts.append("\n")
            elif c == "t":
                parts.append("\t")
            elif c == "r":
                parts.append("\r")
            elif c == '"':
                parts.append('"')
            elif c == "\\":
                parts.append("\\")
            else:
                parts.append("\\")
                parts.append(c)
            i += 2
        else:
            parts.append(val[i])
            i += 1
    return "".join(parts)


def raw_literals(text: str) -> list[tuple[str, str]]:
    """Recover raw escaped text string literals from YARA rule text."""
    results = []
    for rule in split_rules(text):
        for line in rule.body.splitlines():
            m = _RE_STRING_DECL.match(line)
            if not m:
                continue
            raw_val = m.group(2).strip()
            if not raw_val.startswith('"'):
                continue
            k = 1
            end = -1
            while k < len(raw_val):
                if raw_val[k] == "\\":
                    k += 2
                    continue
                if raw_val[k] == '"':
                    end = k
                    break
                k += 1
            body = raw_val[1:end] if end != -1 else raw_val[1:]
            results.append((rule.name, body))
    return results


def atoms_for(value: str) -> list[tuple[str, str]]:
    """Classify and normalize a literal value into atom tuples."""
    cls = _classify_literal(value)
    return [(cls, v) for v in _normalize(cls, value)]


def main() -> int:
    """Entry point for the audit script."""
    parser = argparse.ArgumentParser(description="Measure YARA escape-order defect impact")
    parser.add_argument("--root", default="corpora")
    parser.add_argument("--show", type=int, default=12)
    args = parser.parse_args()

    files_scanned = 0
    unreadable = 0
    crashed = 0
    crash_details = []
    literals = 0
    differing = 0
    impacted = 0
    gained_by_fix = Counter()
    lost_by_fix = Counter()
    samples = []
    impacted_files = set()

    root = Path(args.root)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        if path.suffix.lower() not in (".yar", ".yara"):
            continue

        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable += 1
            continue

        try:
            for rule_name, raw in raw_literals(text):
                literals += 1
                buggy = unescape_buggy(raw)
                correct = unescape_correct(raw)
                if buggy == correct:
                    continue
                differing += 1
                a_buggy = atoms_for(buggy)
                a_correct = atoms_for(correct)
                if a_buggy == a_correct:
                    continue
                impacted += 1
                buggy_set = set(a_buggy)
                correct_set = set(a_correct)
                for cls, _v in a_correct:
                    if (cls, _v) not in buggy_set:
                        gained_by_fix[cls] += 1
                for cls, _v in a_buggy:
                    if (cls, _v) not in correct_set:
                        lost_by_fix[cls] += 1
                if len(samples) < 400:
                    samples.append({
                        "file": str(path),
                        "rule": rule_name,
                        "raw": raw[:90],
                        "buggy": repr(buggy)[:90],
                        "correct": repr(correct)[:90],
                        "atoms_buggy": str(a_buggy)[:90],
                        "atoms_correct": str(a_correct)[:90],
                    })
                impacted_files.add(str(path))
        except Exception as exc:
            crashed += 1
            crash_details.append((str(path), str(exc)))
            continue

    print("=== YARA escape-order impact ===")
    print(f"files scanned      : {files_scanned}")
    print(f"unreadable         : {unreadable}")
    print(f"crashed            : {crashed}")
    print(f"text literals      : {literals}")
    print(f"literals differing : {differing}")
    print(f"atoms changed      : {impacted}   (in {len(impacted_files)} distinct files)")
    print()

    print("atom classes RECOVERED by the fix:")
    if gained_by_fix:
        for cls, count in sorted(gained_by_fix.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {cls} : {count}")
    else:
        print("  (none)")

    print("atom classes LOST by the fix:")
    if lost_by_fix:
        for cls, count in sorted(lost_by_fix.items(), key=lambda x: (-x[1], x[0])):
            print(f"  {cls} : {count}")
    else:
        print("  (none)")

    print()
    print(f"--- samples (first {args.show}) ---")
    for s in samples[:args.show]:
        print(f"{s['file']}")
        print(f"  rule    : {s['rule']}")
        print(f"  raw     : {s['raw']}")
        print(f"  buggy   : {s['buggy']}")
        print(f"  correct : {s['correct']}")
        print(f"  atoms b : {s['atoms_buggy']}")
        print(f"  atoms c : {s['atoms_correct']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
