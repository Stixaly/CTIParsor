"""Rebuild the detection-rule store from local corpus clones (ADR-0006/0007).

Shared by the CLI (scripts/build_detection_index.py) and the settings API so the
ingest logic lives in one place.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from api.db import transaction
from pipeline.detection.brands import rebuild_rule_text
from pipeline.detection.dedup import dedupe_store
from pipeline.detection.registry import _ADAPTERS, _merged, corpus_root, load_corpora
from pipeline.detection.store import corpus_counts, replace_corpus_rules

if TYPE_CHECKING:  # the rule-store connection type (ADR-0053); annotation only
    from api.db_backend import DBConnection


def _collect_file_errors(errors: list[dict], root: Path) -> Callable[[Path, str], None]:
    """A `on_file_error` callback that files each error under its path relative to `root`."""
    def on_file_error(path: Path, message: str) -> None:
        errors.append({"path": path.relative_to(root).as_posix(), "error": message})
    return on_file_error


def _missing_root_reason(corpus: dict) -> str:
    """Why a corpus whose folder does not exist was skipped (#374).

    With a `subdir`, the parent folder (`path`) is what the clone left behind: when it
    is there, the subdir is the mistake and is named; when it is not, nothing was
    downloaded yet."""
    path = str(corpus.get("path") or "")
    subdir = str(corpus.get("subdir") or "").strip()
    if subdir and Path(path).is_dir():
        return f"subdir '{subdir}' not found under {path}"
    return f"{path} does not exist (not downloaded yet)"


def rebuild_store(
    conn: DBConnection,
    config_path: str | Path,
    on_progress: Callable[[str, int | None], None] | None = None,
) -> dict:
    """Parse every enabled corpus's local clone and replace its rules in the store,
    then run the cross-corpus dedup pass (ADR-0010), then rebuild the rule_text
    title index over the canonical rules that pass elected (ADR-0031, #363).

    The index is rebuilt last because replacing a corpus deletes its rules and
    their rule_text rows (foreign key), and nothing else refills them: without
    this step a rebuild erased the title and description matches (CVE and brand
    evidence) until someone ran scripts/build_rule_text.py.

    Returns a summary: rules written per corpus, corpora skipped (missing clone /
    unknown adapter), corpora removed (disabled or no longer in the registry,
    their rules deleted), the grand total, the dedup result, the rule_text bilan
    (`rows` written, `empty_bodies` skipped, see rebuild_rule_text), and per-corpus
    counts (each now carrying a `canonical` figure alongside the raw `rules` total).
    `skipped` is the list of those corpus names; `skip_reasons` maps each of them
    to a message that says why (#374): no path configured, unknown adapter (named),
    a `subdir` missing under an existing `path`, or a `path` not downloaded yet.
    `file_errors` maps each corpus whose files were not fully read to a list of
    `{"path": <relative to the corpus root>, "error": <message>}` (#373): a file
    that is unreadable, not UTF-8, or broken YAML past its first documents. Such a
    corpus is still replaced by what was read, so the total is short by those
    rules and this is where the caller learns it. The dict is empty when every
    file was read.

    `on_progress(name, count)` is called with `count=None` before a corpus is
    parsed and with the rule count after it is written; `name="dedup"` marks the
    final pass. It exists because this job reads ~14,000 files and printed
    nothing until all of them were done, which reads as a hang. The callback
    rather than a print keeps the settings API, which shares this function, from
    writing to stdout.
    """
    written: dict[str, int] = {}
    skipped: list[str] = []
    skip_reasons: dict[str, str] = {}
    file_errors: dict[str, list[dict]] = {}
    priority: dict[str, int] = {}
    for corpus in load_corpora(config_path):
        name = corpus.get("name", "?")
        priority[name] = int(corpus.get("priority", 1000))
        adapter = _ADAPTERS.get(corpus.get("adapter", ""))
        try:
            root = corpus_root(corpus)
        except ValueError:          # no path: one bad entry must not stop the rebuild
            skipped.append(name)
            skip_reasons[name] = "no path configured in the registry"
            continue
        if adapter is None:
            skipped.append(name)
            skip_reasons[name] = f"unknown adapter '{corpus.get('adapter', '')}'"
            continue
        if not root.exists():
            skipped.append(name)
            skip_reasons[name] = _missing_root_reason(corpus)
            continue
        if on_progress:
            on_progress(name, None)
        errors: list[dict] = []
        rules = list(adapter.parse(
            root,
            corpus=name,
            license=corpus.get("license", "unknown"),
            on_file_error=_collect_file_errors(errors, root),
        ))
        written[name] = replace_corpus_rules(conn, name, rules)
        if errors:
            file_errors[name] = errors
        if on_progress:
            on_progress(name, written[name])

    # A corpus disabled or removed from the registry keeps no rules: they would
    # still be canonical, proposed and exported after the rebuild (#302).  An
    # enabled corpus whose clone is missing keeps the rules it had.  No
    # registry at all purges nothing: that is a wrong path, not an empty list.
    removed: list[str] = []
    if _merged(Path(config_path)):
        active = {c.get("name") for c in load_corpora(config_path)}
        stored = [r[0] for r in conn.execute("SELECT DISTINCT corpus FROM detection_rules").fetchall()]
        for name in sorted(set(stored) - active):
            replace_corpus_rules(conn, name, [])
            removed.append(name)

    # Cross-corpus dedup runs once the whole store is rebuilt — it can't be done
    # per corpus (replace_corpus_rules sees only one corpus at a time).
    if on_progress:
        on_progress("dedup", None)
    dedup = dedupe_store(conn, priority)
    # One transaction, so a failure leaves the previous index in place rather
    # than an empty one. dedupe_store has already committed, so the canonical
    # flags read here are the elected ones.
    with transaction(conn):
        rule_text = rebuild_rule_text(conn)
    return {
        "written": written,
        "skipped": skipped,
        "skip_reasons": skip_reasons,
        "removed": removed,
        "file_errors": file_errors,
        "total": sum(written.values()),
        "dedup": dedup,
        "rule_text": rule_text,
        "counts": corpus_counts(conn),
    }
