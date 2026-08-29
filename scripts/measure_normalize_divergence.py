"""Measure the real-world impact of known divergences between the three
Sigma / Suricata / YARA atom normalizers.

Reads ``rule_atoms`` joined to ``detection_rules.format`` and, for each
divergence in ``_DIVERGENCES``, counts how many stored atoms trigger it.
This is a measurement script, not a test: it never modifies the database
and always exits 0.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.detection.tlds import looks_like_domain  # noqa: E402


@dataclass(frozen=True)
class _Divergence:
    """One rule that two of the three normalizers disagree on."""
    key: str          # short identifier, printed
    atom_class: str   # the rule_atoms.atom_class it applies to
    formats: tuple[str, ...]   # formats whose atoms are tested
    question: str     # what the count means, in one line

#: Every point where the three `_normalize` implementations disagree, as of
#: 2026-08-29.  `predicate` is looked up in _PREDICATES by `key`.
_DIVERGENCES: tuple[_Divergence, ...] = (
    _Divergence(
        "domain.www", "domain", ("sigma",),
        "Sigma domain atoms starting with 'www.' — suricata and yara strip it, sigma does not"),
    _Divergence(
        "domain.wildcard", "domain", ("suricata", "yara"),
        "suricata/yara domain atoms starting with '*.' — sigma strips it, they do not"),
    _Divergence(
        "domain.trailing_dot", "domain", ("sigma", "suricata", "yara"),
        "domain atoms still ending in '.' — all three claim to strip it"),
    _Divergence(
        "domain.not_a_domain", "domain", ("sigma", "yara"),
        "domain atoms failing looks_like_domain — suricata requires it, sigma and yara do not"),
    _Divergence(
        "ip.not_dotted_quad", "ip", ("sigma",),
        "Sigma ip atoms that are not a valid 0-255 dotted quad — sigma does not validate at all"),
    _Divergence(
        "url.short", "url", ("sigma",),
        "Sigma url atoms shorter than 8 chars — yara requires 8, suricata 6"),
    _Divergence(
        "url.no_separator", "url", ("sigma", "yara"),
        "url atoms with neither '/' nor '://' — suricata drops these as SQLi keywords"),
    _Divergence(
        "path.untrimmed", "file", ("sigma", "yara"),
        "file atoms with leading or trailing whitespace — sigma strips the basename, yara does not"),
    _Divergence(
        "path.backslash", "file", ("sigma", "yara"),
        "file atoms still containing a backslash — both claim to convert to '/'"),
    _Divergence(
        "value.uppercase", "", ("sigma", "suricata", "yara"),
        "atoms of any class containing an uppercase letter — all three lowercase"),
)


def _is_dotted_quad(value: str) -> bool:
    """Return True if *value* is a valid 0-255 dotted-quad IPv4 address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) > 255:
            return False
    return True


_PREDICATES: dict[str, Callable[[str], bool]] = {
    "domain.www": lambda v: v.startswith("www."),
    "domain.wildcard": lambda v: v.startswith("*."),
    "domain.trailing_dot": lambda v: v.endswith("."),
    "domain.not_a_domain": lambda v: not looks_like_domain(v),
    "ip.not_dotted_quad": lambda v: not _is_dotted_quad(v),
    "url.short": lambda v: len(v) < 8,
    "url.no_separator": lambda v: "/" not in v and "://" not in v,
    "path.untrimmed": lambda v: v != v.strip(),
    "path.backslash": lambda v: "\\" in v,
    "value.uppercase": lambda v: v != v.lower(),
}


def _load_atoms(conn: sqlite3.Connection) -> dict[tuple[str, str], list[str]]:
    """Load all atom values grouped by ``(format, atom_class)``.

    A single query is issued to avoid 30+ table scans over 363 166 rows.
    Rows whose ``value`` is not a ``str`` are silently skipped.
    """
    atoms: dict[tuple[str, str], list[str]] = defaultdict(list)
    cur = conn.execute(
        "SELECT d.format, a.atom_class, a.value "
        "FROM rule_atoms a JOIN detection_rules d ON d.id = a.rule_id"
    )
    for fmt, atom_class, value in cur:
        if not isinstance(value, str):
            continue
        atoms[(fmt, atom_class)].append(value)
    return dict(atoms)


def _measure(
    atoms: dict[tuple[str, str], list[str]],
    div: _Divergence,
    n_examples: int = 5,
) -> tuple[int, int, list[str]]:
    """Count atoms that trigger *div* and collect up to *n_examples* examples.

    Returns ``(n_hits, n_total, examples)`` where ``n_total`` is the number
    of atoms examined for this divergence and ``examples`` are the first
    *n_examples* triggering values, sorted.
    """
    predicate = _PREDICATES[div.key]
    n_hits = 0
    n_total = 0
    examples: list[str] = []

    for (fmt, atom_class), values in atoms.items():
        if fmt not in div.formats:
            continue
        if div.atom_class and atom_class != div.atom_class:
            continue
        for value in values:
            n_total += 1
            if predicate(value):
                n_hits += 1
                if len(examples) < n_examples:
                    examples.append(value)

    examples.sort()
    return n_hits, n_total, examples


def _print_report(
    results: list[tuple[_Divergence, int, int, list[str]]],
    total_atoms: int,
) -> None:
    """Print the per-divergence report and the summary line."""
    # Sort by n_hits descending
    results.sort(key=lambda r: r[1], reverse=True)

    for div, n_hits, n_total, examples in results:
        fmts = " ".join(div.formats)
        print(f"{div.key:<30s}  {fmts}")
        if n_total == 0:
            pct = "0.00%"
        else:
            pct = f"{(n_hits / n_total) * 100:.2f}%"
        if n_hits == 0:
            print(f"  {n_hits} / {n_total}  — no divergence")
        else:
            print(f"  {n_hits} / {n_total}  ({pct})")
        print(f"  what: {div.question}")
        if examples:
            print(f"  e.g.: {', '.join(examples)}")
        print()

    n_with_hits = sum(1 for _, h, _, _ in results if h > 0)
    print(
        f"TOTAL: {total_atoms} atoms, {len(results)} divergences measured, "
        f"{n_with_hits} with at least one hit"
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, open DB read-only, measure, print, exit 0."""
    parser = argparse.ArgumentParser(
        description="Measure the impact of known normalizer divergences."
    )
    parser.add_argument("--db", default="cti_stix.db", help="Path to the SQLite database")
    parser.add_argument("--examples", type=int, default=5, help="Max examples per divergence")
    args = parser.parse_args(argv)

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        atoms = _load_atoms(conn)
        total_atoms = sum(len(v) for v in atoms.values())

        results: list[tuple[_Divergence, int, int, list[str]]] = []
        for div in _DIVERGENCES:
            n_hits, n_total, examples = _measure(atoms, div, args.examples)
            results.append((div, n_hits, n_total, examples))

        _print_report(results, total_atoms)
    finally:
        if conn is not None:
            conn.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
