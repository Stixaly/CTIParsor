#!/usr/bin/env python3
"""Measure corpus ingestion performance and statistics.

This script ingests a subset of detection rule corpora into a disposable
PostgreSQL schema and prints per-corpus and per-format statistics. It
validates YARA/Suricata ingestion (ADR-0015) without touching the real rule
store (ADR-0053: the store is PostgreSQL, so "disposable" now means a
throwaway schema on the same server rather than a separate file).

Requires DATABASE_URL (or --postgres) pointing at a reachable PostgreSQL
server; the schema is created before the run and dropped after, unless
--keep is passed.

Usage:
    python scripts/measure_corpus_ingest.py [--config detection_corpora.yaml]
                                            [--postgres URL]
                                            [--formats yara,suricata]
                                            [--corpora et-open,tbg-hunting]
                                            [--keep]
"""
from __future__ import annotations

import argparse
import collections
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import yaml  # noqa: E402

import api.db as dbmod  # noqa: E402
from api.db_backend import DBConnection  # noqa: E402
from pipeline.detection.builder import rebuild_store  # noqa: E402
from pipeline.detection.registry import load_corpora  # noqa: E402


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Measure corpus ingestion performance and statistics."
    )
    parser.add_argument(
        "--config",
        type=str,
        default=str(_ROOT / "detection_corpora.yaml"),
        help="Path to detection corpora config (default: detection_corpora.yaml)",
    )
    parser.add_argument(
        "--postgres",
        type=str,
        default=None,
        help="Target PostgreSQL URL (default: $DATABASE_URL)",
    )
    parser.add_argument(
        "--formats",
        type=str,
        default="",
        help="Comma-separated list of adapters (e.g., yara,suricata); empty = all",
    )
    parser.add_argument(
        "--corpora",
        type=str,
        default="",
        help="Comma-separated list of corpus names; empty = all",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep the disposable schema after the run instead of dropping it",
    )
    return parser.parse_args()


def _select_corpora(config: str | Path, formats: set[str], names: set[str]) -> list[dict]:
    """Select corpora matching the given format and name filters."""
    all_corpora = load_corpora(config)
    selected = [
        c
        for c in all_corpora
        if (not formats or c.get("adapter") in formats)
        and (not names or c.get("name") in names)
    ]
    return selected


def _write_temp_config(selected: list[dict]) -> Path:
    """Write the selected corpora to a temporary YAML file and return its path."""
    tmp = tempfile.NamedTemporaryFile(
        "w", suffix=".yaml", delete=False, encoding="utf-8"
    )
    try:
        yaml.safe_dump({"corpora": selected}, tmp, sort_keys=False)
        tmp.flush()
        tmp.close()
        return Path(tmp.name)
    except Exception:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        raise


def _report(
    conn: DBConnection,
    summary: dict,
    elapsed_by_corpus: dict[str, float],
    total_s: float,
    schema: str,
) -> None:
    """Print the ingestion report."""
    sep = "-" * 60

    # a. Per corpus
    print(sep)
    print("Per corpus")
    print(sep)
    for row in summary.get("counts", []):
        corpus = row.get("corpus", "")
        license_ = row.get("license", "")
        rules = row.get("rules", 0)
        canonical = row.get("canonical", 0)
        elapsed = elapsed_by_corpus.get(corpus)
        elapsed_str = f"{elapsed:.1f}s" if elapsed is not None else "-"
        print(f"  {corpus:<20} {license_:<15} rules={rules:>6} canonical={canonical:>6} {elapsed_str}")
    if summary.get("skipped"):
        print(f"  skipped: {', '.join(summary['skipped'])}")

    # b. Per format
    print()
    print(sep)
    print("Per format")
    print(sep)

    # rules and canonical
    cur = conn.execute(
        "SELECT format, COUNT(*), SUM(is_canonical) FROM detection_rules GROUP BY format"
    )
    rules_by_fmt: dict[str, int] = {}
    canonical_by_fmt: dict[str, int] = {}
    for fmt, cnt, canon in cur.fetchall():
        rules_by_fmt[fmt] = cnt
        canonical_by_fmt[fmt] = canon

    # tagged and techniques
    cur = conn.execute(
        """
        SELECT d.format,
               COUNT(DISTINCT t.rule_id),
               COUNT(DISTINCT t.technique_id)
        FROM rule_techniques t
        JOIN detection_rules d ON d.id = t.rule_id
        GROUP BY d.format
        """
    )
    tagged_by_fmt: dict[str, int] = {}
    techniques_by_fmt: dict[str, int] = {}
    for fmt, tagged, techniques in cur.fetchall():
        tagged_by_fmt[fmt] = tagged
        techniques_by_fmt[fmt] = techniques

    # atoms and rules_with_atoms
    cur = conn.execute(
        """
        SELECT d.format,
               COUNT(*),
               COUNT(DISTINCT a.rule_id)
        FROM rule_atoms a
        JOIN detection_rules d ON d.id = a.rule_id
        GROUP BY d.format
        """
    )
    atoms_by_fmt: dict[str, int] = {}
    rules_with_atoms_by_fmt: dict[str, int] = {}
    for fmt, atoms, rwa in cur.fetchall():
        atoms_by_fmt[fmt] = atoms
        rules_with_atoms_by_fmt[fmt] = rwa

    all_formats = sorted(set(rules_by_fmt) | set(tagged_by_fmt) | set(atoms_by_fmt))
    for fmt in all_formats:
        print(
            f"  {fmt:<12} rules={rules_by_fmt.get(fmt, 0):>6} "
            f"canonical={canonical_by_fmt.get(fmt, 0):>6} "
            f"tagged={tagged_by_fmt.get(fmt, 0):>6} "
            f"techniques={techniques_by_fmt.get(fmt, 0):>6} "
            f"atoms={atoms_by_fmt.get(fmt, 0):>6} "
            f"rules_with_atoms={rules_with_atoms_by_fmt.get(fmt, 0):>6}"
        )

    # c. Top 10 techniques per format
    print()
    print(sep)
    print("Top 10 techniques per format")
    print(sep)
    for fmt in all_formats:
        cur = conn.execute(
            """
            SELECT t.technique_id, COUNT(*)
            FROM rule_techniques t
            JOIN detection_rules d ON d.id = t.rule_id
            WHERE d.format = ?
            GROUP BY t.technique_id
            ORDER BY 2 DESC, 1
            LIMIT 10
            """,
            (fmt,),
        )
        rows = cur.fetchall()
        if rows:
            parts = [f"{tid} ({cnt})" for tid, cnt in rows]
            print(f"  {fmt}: {', '.join(parts)}")
        else:
            print(f"  {fmt}: (none)")

    # d. Atoms by class per format
    print()
    print(sep)
    print("Atoms by class per format")
    print(sep)
    cur = conn.execute(
        """
        SELECT d.format, a.atom_class, COUNT(*)
        FROM rule_atoms a
        JOIN detection_rules d ON d.id = a.rule_id
        GROUP BY 1, 2
        ORDER BY 1, 3 DESC
        """
    )
    atoms_by_class: dict[str, list[tuple[str, int]]] = collections.defaultdict(list)
    for fmt, atom_class, cnt in cur.fetchall():
        atoms_by_class[fmt].append((atom_class, cnt))
    for fmt in all_formats:
        if fmt in atoms_by_class:
            parts = [f"{cls} {cnt:,}" for cls, cnt in atoms_by_class[fmt]]
            print(f"  {fmt}: {' | '.join(parts)}")
        else:
            print(f"  {fmt}: (none)")

    # e. Dedup
    print()
    print(sep)
    print("Dedup")
    print(sep)
    dedup = summary.get("dedup", {})
    for k, v in dedup.items():
        print(f"  {k}: {v}")

    # f. Final line
    print()
    print(sep)
    print(f"[measure] {summary['total']:,} rules in {total_s:.1f}s -> schema {schema}")
    print(sep)


def main() -> int:
    """Main entry point."""
    args = _parse_args()

    formats = {s.strip() for s in args.formats.split(",") if s.strip()}
    names = {s.strip() for s in args.corpora.split(",") if s.strip()}

    url = args.postgres or os.getenv("DATABASE_URL")
    if not url:
        print("[measure] --postgres or DATABASE_URL is required", file=sys.stderr)
        return 2

    # A disposable schema, not a disposable database file (ADR-0053): the
    # rule store is PostgreSQL, and a measurement run must not touch the
    # real corpus -- same isolation technique as tests/conftest.py::temp_db.
    import psycopg

    schema = "measure_" + uuid.uuid4().hex[:12]
    admin = psycopg.connect(url, autocommit=True)
    admin.execute(f'CREATE SCHEMA "{schema}"')
    admin.close()

    dbmod.DATABASE_URL = url
    dbmod._PG_SCHEMA = schema
    dbmod.reset_connections()

    try:
        dbmod.init_db()
        conn = dbmod.get_rule_conn()

        # Select corpora
        selected = _select_corpora(args.config, formats, names)
        if not selected:
            print("[measure] no corpus matches the filters")
            return 1

        # Make paths absolute
        for c in selected:
            p = Path(c.get("path", ""))
            if not p.is_absolute():
                c["path"] = str((_ROOT / p).resolve())

        # Write temp config
        temp_config = _write_temp_config(selected)

        # Progress callback
        elapsed_by_corpus: dict[str, float] = {}
        start_times: dict[str, float] = {}

        def _progress(name: str, count: int | None) -> None:
            if count is None:
                start_times[name] = time.perf_counter()
                if name == "dedup":
                    print("[measure] dedup...", flush=True)
            else:
                elapsed = time.perf_counter() - start_times.get(name, time.perf_counter())
                elapsed_by_corpus[name] = elapsed
                print(f"[measure] {name:<20} {count:>7} rules  {elapsed:6.1f}s", flush=True)

        # Run rebuild
        t0 = time.perf_counter()
        try:
            summary = rebuild_store(conn, temp_config, on_progress=_progress)
        finally:
            Path(temp_config).unlink(missing_ok=True)
        total_s = time.perf_counter() - t0

        # Report
        _report(conn, summary, elapsed_by_corpus, total_s, schema)
    finally:
        dbmod.reset_connections()
        if not args.keep:
            admin = psycopg.connect(url, autocommit=True)
            try:
                admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
            finally:
                admin.close()
        else:
            print(f"[measure] kept schema {schema!r} — drop it manually when done")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
