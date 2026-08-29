from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    name: str
    severity: str
    count: int
    total: int
    detail: str
    status: str


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    """Check if a table or view exists in the database."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names for a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r["name"] for r in rows}


def _sample(rows: list, n: int = 3) -> str:
    """Join up to n elements with ', ', each truncated to 40 chars via repr()."""
    parts = []
    for r in rows[:n]:
        s = repr(r)
        if len(s) > 40:
            s = s[:37] + "..."
        parts.append(s)
    return ", ".join(parts)


def _cluster_roots(conn: sqlite3.Connection) -> tuple[dict[str, str], dict[str, int]]:
    """Rebuild the dedup clusters exactly as `dedupe_store` elects them.

    Union-find over BOTH axes: `dedup_key` first, then the ADR-0017 provenance
    edges.  Grouping on `dedup_key` alone is wrong — provenance folds rules that
    do NOT share a key, so a key group with no canonical member is the normal
    outcome, not a fault.  Measured on the live store, that naive form reported
    5,036 false failures against 0 real ones.
    """
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if ra < rb:
            parent[rb] = ra
        else:
            parent[ra] = rb

    canon: dict[str, int] = {}
    by_key: dict[str, list[str]] = {}
    for rid, corpus_key, content_hash, is_canon in conn.execute(
        "SELECT id, dedup_key, content_hash, is_canonical FROM detection_rules"
    ):
        parent[rid] = rid
        canon[rid] = 1 if is_canon == 1 else 0
        by_key.setdefault(corpus_key or f"raw:{content_hash or rid}", []).append(rid)

    for members in by_key.values():
        for m in members[1:]:
            union(members[0], m)

    if _table_exists(conn, "rule_related"):
        native: dict[str, list[str]] = {}
        for nk, rid in conn.execute("SELECT native_key, id FROM detection_rules"):
            native.setdefault(nk, []).append(rid)
        for rid, related_key, rel_type in conn.execute(
            "SELECT rule_id, related_key, rel_type FROM rule_related"
        ):
            if not isinstance(rel_type, str) or not isinstance(related_key, str):
                continue
            if rel_type.strip().lower() not in ("derived", "renamed"):
                continue
            for tgt in native.get(related_key, ()):
                if tgt != rid and tgt in parent and rid in parent:
                    union(rid, tgt)

    return {rid: find(rid) for rid in parent}, canon


def check_dedup_cluster_canonical(conn: sqlite3.Connection) -> Finding:
    """Verify each dedup CLUSTER — not each dedup_key — has exactly one canonical."""
    try:
        if not _table_exists(conn, "detection_rules"):
            return Finding("dedup.cluster_canonical", "error", 0, 0, "table missing", "SKIP")
        cols = _columns(conn, "detection_rules")
        if "dedup_key" not in cols or "is_canonical" not in cols:
            return Finding("dedup.cluster_canonical", "error", 0, 0, "columns missing", "SKIP")

        roots, canon = _cluster_roots(conn)
        per_cluster: dict[str, int] = {}
        for rid, root in roots.items():
            per_cluster[root] = per_cluster.get(root, 0) + canon[rid]

        total = len(per_cluster)
        zero = sum(1 for n in per_cluster.values() if n == 0)
        multi = sum(1 for n in per_cluster.values() if n > 1)
        count = zero + multi
        if count == 0:
            return Finding("dedup.cluster_canonical", "error", 0, total,
                           f"{total} clusters, each with exactly 1 canonical", "OK")
        examples = [r for r, n in per_cluster.items() if n != 1][:3]
        detail = f"zero={zero} multi={multi} e.g. {_sample(examples)}"
        return Finding("dedup.cluster_canonical", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("dedup.cluster_canonical", "error", 0, 0, str(e)[:160], "SKIP")


@dataclass(frozen=True)
class _OrphanSpec:
    """One "rows whose foreign key resolves to nothing" invariant."""
    severity: str      # "error" or "warn"
    child: str         # table whose rows are counted
    fk: str            # column of `child` holding the reference
    parent: str        # table the reference must resolve in
    key: str           # column of `parent` the fk must match
    ok_detail: str     # Finding.detail when nothing is orphaned
    fail_label: str    # prefix of the FAIL detail

#: The six orphan invariants, previously six near-identical functions.
#: `rule_bytes.missing` runs the relation the other way round — rules
#: with no bytes row — but it is the same query shape, so it belongs
#: here rather than in a copy of its own.
_ORPHAN_SPECS: dict[str, _OrphanSpec] = {
    "atoms.orphan": _OrphanSpec(
        "error", "rule_atoms", "rule_id", "detection_rules", "id",
        "no orphan atoms", "orphan rule_ids"),
    "techniques.orphan": _OrphanSpec(
        "error", "rule_techniques", "rule_id", "detection_rules", "id",
        "no orphan techniques", "orphan rule_ids"),
    "related.orphan": _OrphanSpec(
        "error", "rule_related", "rule_id", "detection_rules", "id",
        "no orphan related", "orphan rule_ids"),
    "rule_bytes.missing": _OrphanSpec(
        "warn", "detection_rules", "id", "rule_bytes", "rule_id",
        "all rules have bytes", "missing rule_ids"),
    "entity.orphan_job": _OrphanSpec(
        "error", "entities", "job_id", "jobs", "id",
        "no orphan entities", "orphan job_ids"),
    "relationship.orphan_job": _OrphanSpec(
        "error", "relationships", "job_id", "jobs", "id",
        "no orphan relationships", "orphan job_ids"),
}

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def _check_orphan(conn: sqlite3.Connection, name: str) -> Finding:
    """Generic orphan check driven by _ORPHAN_SPECS."""
    spec = _ORPHAN_SPECS[name]
    # SQLite does not support parameter binding for table/column names,
    # so we must validate identifiers to prevent SQL injection.
    for ident in (spec.child, spec.fk, spec.parent, spec.key):
        if not _IDENT_RE.match(ident):
            return Finding(name, spec.severity, 0, 0, "invalid identifier", "SKIP")
    try:
        if not _table_exists(conn, spec.child) or not _table_exists(conn, spec.parent):
            return Finding(name, spec.severity, 0, 0, "table missing", "SKIP")
        total = conn.execute(f"SELECT COUNT(*) AS c FROM {spec.child}").fetchone()["c"]
        count = conn.execute(f"""
            SELECT COUNT(*) AS c FROM {spec.child} a
            WHERE NOT EXISTS (SELECT 1 FROM {spec.parent} b WHERE b.{spec.key} = a.{spec.fk})
        """).fetchone()["c"]
        if count == 0:
            return Finding(name, spec.severity, 0, total, spec.ok_detail, "OK")
        examples = [r["v"] for r in conn.execute(f"""
            SELECT a.{spec.fk} AS v FROM {spec.child} a
            WHERE NOT EXISTS (SELECT 1 FROM {spec.parent} b WHERE b.{spec.key} = a.{spec.fk})
            LIMIT 3
        """).fetchall()]
        detail = f"{spec.fail_label}: {_sample(examples)}"
        return Finding(name, spec.severity, count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding(name, spec.severity, 0, 0, str(e)[:160], "SKIP")


def check_rule_bytes_zero(conn: sqlite3.Connection) -> Finding:
    """Check for rule_bytes with bytes<=0 while raw is non-empty."""
    try:
        if not _table_exists(conn, "detection_rules") or not _table_exists(conn, "rule_bytes"):
            return Finding("rule_bytes.zero", "warn", 0, 0, "table missing", "SKIP")
        cols = _columns(conn, "detection_rules")
        if "raw" not in cols:
            return Finding("rule_bytes.zero", "warn", 0, 0, "raw column missing", "SKIP")
        total = conn.execute("SELECT COUNT(*) AS c FROM rule_bytes").fetchone()["c"]
        count = conn.execute("""
            SELECT COUNT(*) AS c FROM rule_bytes rb
            JOIN detection_rules dr ON dr.id = rb.rule_id
            WHERE rb.bytes <= 0 AND length(dr.raw) > 0
        """).fetchone()["c"]
        if count == 0:
            return Finding("rule_bytes.zero", "warn", 0, total, "no zero-byte rules with raw", "OK")
        examples = [r["rule_id"] for r in conn.execute("""
            SELECT rb.rule_id FROM rule_bytes rb
            JOIN detection_rules dr ON dr.id = rb.rule_id
            WHERE rb.bytes <= 0 AND length(dr.raw) > 0
            LIMIT 3
        """).fetchall()]
        detail = f"zero-byte rule_ids: {_sample(examples)}"
        return Finding("rule_bytes.zero", "warn", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("rule_bytes.zero", "warn", 0, 0, str(e)[:160], "SKIP")


def check_atom_value_normalised(conn: sqlite3.Connection) -> Finding:
    """Verify rule_atoms.value is lowercase, trimmed, non-empty — and Sigma-wildcard-free.

    The "wildcard-free" half of the contract is a SIGMA rule: `atoms._normalize`
    drops any value holding `*` or `?` because a Sigma wildcard means the rule
    matches a shape, not a literal.  YARA and Suricata atoms carry `*` and `?` as
    ordinary characters of a literal string — `select * from moz_logins` and
    `?a=img` are content — so applying it to them reported 9,242 false failures.
    It is therefore scoped to `format='sigma'`.
    """
    try:
        if not _table_exists(conn, "rule_atoms"):
            return Finding("atoms.value_normalised", "error", 0, 0, "table missing", "SKIP")
        wildcard_expr = (
            "(instr(value,'*')>0 OR instr(value,'?')>0) AND EXISTS ("
            " SELECT 1 FROM detection_rules dr"
            " WHERE dr.id = rule_atoms.rule_id AND dr.format='sigma')"
        )
        row = conn.execute(f"""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN value != lower(value) THEN 1 ELSE 0 END) AS upper,
                   SUM(CASE WHEN {wildcard_expr} THEN 1 ELSE 0 END) AS wildcard,
                   SUM(CASE WHEN value != trim(value) THEN 1 ELSE 0 END) AS untrimmed,
                   SUM(CASE WHEN value IS NULL OR value = '' THEN 1 ELSE 0 END) AS empty
            FROM rule_atoms
        """).fetchone()
        total = row["total"]
        upper = row["upper"] or 0
        wildcard = row["wildcard"] or 0
        untrimmed = row["untrimmed"] or 0
        empty = row["empty"] or 0
        count = conn.execute(f"""
            SELECT COUNT(*) AS c FROM rule_atoms
            WHERE value != lower(value)
               OR ({wildcard_expr})
               OR value != trim(value)
               OR value IS NULL OR value = ''
        """).fetchone()["c"]
        if count == 0:
            return Finding("atoms.value_normalised", "error", 0, total, "all values normalised", "OK")
        detail = f"upper={upper} wildcard={wildcard} untrimmed={untrimmed} empty={empty}"
        return Finding("atoms.value_normalised", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("atoms.value_normalised", "error", 0, 0, str(e)[:160], "SKIP")


def check_atom_value_too_short(conn: sqlite3.Connection) -> Finding:
    """Check for rule_atoms.value with length 1."""
    try:
        if not _table_exists(conn, "rule_atoms"):
            return Finding("atoms.value_too_short", "warn", 0, 0, "table missing", "SKIP")
        total = conn.execute("SELECT COUNT(*) AS c FROM rule_atoms").fetchone()["c"]
        count = conn.execute("SELECT COUNT(*) AS c FROM rule_atoms WHERE length(value) = 1").fetchone()["c"]
        if count == 0:
            return Finding("atoms.value_too_short", "warn", 0, total, "no single-char values", "OK")
        examples = [r["value"] for r in conn.execute(
            "SELECT value FROM rule_atoms WHERE length(value) = 1 LIMIT 3"
        ).fetchall()]
        detail = f"single-char values: {_sample(examples)}"
        return Finding("atoms.value_too_short", "warn", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("atoms.value_too_short", "warn", 0, 0, str(e)[:160], "SKIP")


def check_dedup_key_absent(conn: sqlite3.Connection) -> Finding:
    """Check for detection_rules with empty or NULL dedup_key."""
    try:
        if not _table_exists(conn, "detection_rules"):
            return Finding("dedup.key_absent", "warn", 0, 0, "table missing", "SKIP")
        cols = _columns(conn, "detection_rules")
        if "dedup_key" not in cols:
            return Finding("dedup.key_absent", "warn", 0, 0, "dedup_key column missing", "SKIP")
        total = conn.execute("SELECT COUNT(*) AS c FROM detection_rules").fetchone()["c"]
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM detection_rules WHERE dedup_key IS NULL OR dedup_key = ''"
        ).fetchone()["c"]
        if count == 0:
            return Finding("dedup.key_absent", "warn", 0, total, "all rules have dedup_key", "OK")
        examples = [r["id"] for r in conn.execute(
            "SELECT id FROM detection_rules WHERE dedup_key IS NULL OR dedup_key = '' LIMIT 3"
        ).fetchall()]
        detail = f"missing dedup_key: {_sample(examples)}"
        return Finding("dedup.key_absent", "warn", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("dedup.key_absent", "warn", 0, 0, str(e)[:160], "SKIP")


def check_figure_span_bounds(conn: sqlite3.Connection) -> Finding:
    """Verify report_figures char_start/char_end are within report_text bounds."""
    try:
        if not _table_exists(conn, "report_figures") or not _table_exists(conn, "jobs"):
            return Finding("figure.span_bounds", "error", 0, 0, "table missing", "SKIP")
        total = conn.execute("SELECT COUNT(*) AS c FROM report_figures").fetchone()["c"]
        row = conn.execute("""
            SELECT
                SUM(CASE WHEN rf.char_start < 0 THEN 1 ELSE 0 END) AS negative,
                SUM(CASE WHEN rf.char_end <= rf.char_start THEN 1 ELSE 0 END) AS inverted,
                SUM(CASE WHEN j.report_text IS NOT NULL
                          AND rf.char_end > length(j.report_text)
                         THEN 1 ELSE 0 END) AS past_end
            FROM report_figures rf
            JOIN jobs j ON j.id = rf.job_id
        """).fetchone()
        negative = row["negative"] or 0
        inverted = row["inverted"] or 0
        past_end = row["past_end"] or 0
        count = conn.execute("""
            SELECT COUNT(*) AS c FROM report_figures rf
            JOIN jobs j ON j.id = rf.job_id
            WHERE rf.char_start < 0
               OR rf.char_end <= rf.char_start
               OR (j.report_text IS NOT NULL AND rf.char_end > length(j.report_text))
        """).fetchone()["c"]
        if count == 0:
            return Finding("figure.span_bounds", "error", 0, total, "all spans valid", "OK")
        detail = f"negative={negative} inverted={inverted} past_end={past_end}"
        return Finding("figure.span_bounds", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("figure.span_bounds", "error", 0, 0, str(e)[:160], "SKIP")


def check_figure_span_overlap(conn: sqlite3.Connection) -> Finding:
    """Check for overlapping figure spans within the same job."""
    try:
        if not _table_exists(conn, "report_figures"):
            return Finding("figure.span_overlap", "error", 0, 0, "table missing", "SKIP")
        rows = conn.execute("""
            SELECT job_id, char_start, char_end
            FROM report_figures
            WHERE char_start IS NOT NULL AND char_end IS NOT NULL
            ORDER BY job_id, char_start
        """).fetchall()
        total = len(rows)
        count = 0
        examples: list[str] = []
        prev_job: str | None = None
        prev_end: int | None = None
        for r in rows:
            if r["job_id"] == prev_job and prev_end is not None and r["char_start"] < prev_end:
                count += 1
                if len(examples) < 3:
                    examples.append(f"{r['job_id']}:{r['char_start']}-{r['char_end']}")
            prev_job = r["job_id"]
            prev_end = r["char_end"]
        if count == 0:
            return Finding("figure.span_overlap", "error", 0, total, "no overlaps", "OK")
        detail = f"overlapping spans: {_sample(examples)}"
        return Finding("figure.span_overlap", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("figure.span_overlap", "error", 0, 0, str(e)[:160], "SKIP")


def check_entity_evidence_offset(conn: sqlite3.Connection) -> Finding:
    """Verify [evidence_start, evidence_end) is a valid span of the report text.

    Deliberately NOT `report_text[start:start + len(evidence_text)] == evidence_text`.
    `evidence_text` is the model's wording; the offsets come from
    `evidence_span.locate`, which matches through a normalisation that folds
    curly quotes and whitespace runs.  The two therefore differ in LENGTH, and
    the naive form failed for 68 of 313 rows without a single wrong offset among
    them.  The real invariant is that the span delimits something.

    Rows written before `evidence_end` existed carry a start and no end; they are
    reported as `legacy` rather than as failures, since nothing can be checked.
    """
    try:
        if not _table_exists(conn, "entities") or not _table_exists(conn, "jobs"):
            return Finding("entity.evidence_offset", "error", 0, 0, "table missing", "SKIP")
        has_end = "evidence_end" in _columns(conn, "entities")
        end_col = "evidence_end" if has_end else "NULL AS evidence_end"
        rows = conn.execute(f"""
            SELECT job_id, evidence_start, {end_col}
            FROM entities
            WHERE evidence_start IS NOT NULL
              AND evidence_text IS NOT NULL AND evidence_text != ''
        """).fetchall()
        total = len(rows)
        if not total:
            return Finding("entity.evidence_offset", "error", 0, 0, "no entities to check", "OK")
        lengths = {
            r["id"]: len(r["report_text"])
            for r in conn.execute(
                "SELECT id, report_text FROM jobs WHERE report_text IS NOT NULL"
            )
        }
        count = 0
        legacy = 0
        examples: list[str] = []
        for r in rows:
            n = lengths.get(r["job_id"])
            if n is None:
                continue
            start, end = r["evidence_start"], r["evidence_end"]
            if end is None:
                legacy += 1
                continue
            if not (0 <= start < end <= n):
                count += 1
                if len(examples) < 3:
                    examples.append(f"{r['job_id'][:8]}@[{start},{end}) of {n}")
        if count == 0:
            return Finding("entity.evidence_offset", "error", 0, total,
                           f"all spans valid ({legacy} legacy rows without an end)", "OK")
        detail = f"invalid spans={count} legacy={legacy} e.g. {_sample(examples)}"
        return Finding("entity.evidence_offset", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("entity.evidence_offset", "error", 0, 0, str(e)[:160], "SKIP")


def check_json_columns(conn: sqlite3.Connection) -> Finding:
    """Verify JSON columns contain valid JSON when non-empty."""
    try:
        checks: list[tuple[str, str]] = [
            ("jobs", "bundle_json"),
            ("jobs", "llm_result_json"),
            ("jobs", "run_config_json"),
            ("detection_rules", "data_sources"),
            ("progress_events", "data"),
            ("figure_reads", "read_json"),
        ]
        bad: list[str] = []
        for table, col in checks:
            if not _table_exists(conn, table):
                continue
            cols = _columns(conn, table)
            if col not in cols:
                continue
            rows = conn.execute(
                f"SELECT {col} AS v FROM {table} WHERE {col} IS NOT NULL AND {col} != ''"
            ).fetchall()
            n_bad = 0
            for r in rows:
                try:
                    json.loads(r["v"])
                except (json.JSONDecodeError, TypeError):
                    n_bad += 1
            if n_bad > 0:
                bad.append(f"{table}.{col}={n_bad}")
        if not bad:
            return Finding("json.invalid", "error", 0, 0, "all JSON valid", "OK")
        count = sum(int(x.split("=")[1]) for x in bad)
        detail = ", ".join(bad)
        return Finding("json.invalid", "error", count, 0, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("json.invalid", "error", 0, 0, str(e)[:160], "SKIP")


def check_figure_bbox_format(conn: sqlite3.Connection) -> Finding:
    """Verify report_figures.bbox has exactly 4 comma-separated floats."""
    try:
        if not _table_exists(conn, "report_figures"):
            return Finding("figure.bbox_format", "error", 0, 0, "table missing", "SKIP")
        cols = _columns(conn, "report_figures")
        if "bbox" not in cols:
            return Finding("figure.bbox_format", "error", 0, 0, "bbox column missing", "SKIP")
        rows = conn.execute("SELECT bbox FROM report_figures WHERE bbox IS NOT NULL AND bbox != ''").fetchall()
        total = len(rows)
        count = 0
        examples: list[str] = []
        for r in rows:
            parts = r["bbox"].split(",")
            if len(parts) != 4:
                count += 1
                if len(examples) < 3:
                    examples.append(r["bbox"])
                continue
            try:
                for p in parts:
                    float(p.strip())
            except ValueError:
                count += 1
                if len(examples) < 3:
                    examples.append(r["bbox"])
        if count == 0:
            return Finding("figure.bbox_format", "error", 0, total, "all bboxes valid", "OK")
        detail = f"invalid bboxes: {_sample(examples)}"
        return Finding("figure.bbox_format", "error", count, total, detail[:160], "FAIL")
    except sqlite3.Error as e:
        return Finding("figure.bbox_format", "error", 0, 0, str(e)[:160], "SKIP")


def run_all(conn: sqlite3.Connection) -> list[Finding]:
    """Run all invariant checks and return findings."""
    return [
        check_dedup_cluster_canonical(conn),
        _check_orphan(conn, "atoms.orphan"),
        _check_orphan(conn, "techniques.orphan"),
        _check_orphan(conn, "related.orphan"),
        _check_orphan(conn, "rule_bytes.missing"),
        check_rule_bytes_zero(conn),
        check_atom_value_normalised(conn),
        check_atom_value_too_short(conn),
        check_dedup_key_absent(conn),
        check_figure_span_bounds(conn),
        check_figure_span_overlap(conn),
        check_entity_evidence_offset(conn),
        _check_orphan(conn, "entity.orphan_job"),
        _check_orphan(conn, "relationship.orphan_job"),
        check_json_columns(conn),
        check_figure_bbox_format(conn),
    ]


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, open DB read-only, run checks, print table."""
    parser = argparse.ArgumentParser(description="Audit store invariants (read-only).")
    parser.add_argument("db", nargs="?", default="cti_stix.db", help="Path to SQLite database")
    args = parser.parse_args(argv)

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"error: database file not found: {db_path}", file=sys.stderr)
        return 2

    uri = f"file:{db_path.resolve()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        findings = run_all(conn)
    finally:
        conn.close()

    print(f"{'STATUS':<6} {'SEVERITY':<8} {'NAME':<30} {'COUNT/TOTAL':<14} DETAIL")
    for f in findings:
        ct = f"{f.count}/{f.total}"
        print(f"{f.status:<6} {f.severity:<8} {f.name:<30} {ct:<14} {f.detail}")

    n = len(findings)
    ok = sum(1 for f in findings if f.status == "OK")
    fail = sum(1 for f in findings if f.status == "FAIL")
    skip = sum(1 for f in findings if f.status == "SKIP")
    print(f"\n{n} invariants — {ok} OK, {fail} FAIL, {skip} SKIP")

    if any(f.status == "FAIL" and f.severity == "error" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
