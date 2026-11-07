"""Corpus registry — reads the two-tier detection_corpora.yaml and dispatches to adapters.

A committed `detection_corpora.yaml` holds public corpuses (reproducible); an
optional gitignored `detection_corpora.local.yaml` overlay holds private corpuses
and local overrides. The overlay is merged over the committed file (override by
`name`, append new). Corpuses are local clones; fetching is a separate sync step
(scripts/sync_corpora.py), so git credentials never enter CTIParsor (ADR-0006).
"""
from __future__ import annotations

import fcntl
import os
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

import yaml

from api.logging_config import get_logger
from models.detection import DetectionRule
from pipeline.detection.base import RuleCorpusAdapter
from pipeline.detection.sigma import SigmaAdapter
from pipeline.detection.suricata import SuricataAdapter
from pipeline.detection.yara import YaraAdapter

logger = get_logger(__name__)

# format key → adapter instance.  Register new formats here (the ADR-0006 seam).
# This dict is also what the settings API reports as "available" (ADR-0019), so
# adding a line here is what makes a format ingestible *and* visible in the UI.
_ADAPTERS: dict[str, RuleCorpusAdapter] = {
    SigmaAdapter.format: SigmaAdapter(),
    SuricataAdapter.format: SuricataAdapter(),
    YaraAdapter.format: YaraAdapter(),
}


def corpus_root(corpus: dict) -> Path:
    """Directory the adapter parses for one corpus: `path`, narrowed to `subdir`
    when set. `subdir` scopes a large clone to its rule subtree (e.g. hayabusa's
    `sigma/` Sigma-compatible subset) without re-cloning — ADR-0010."""
    root = Path(str(corpus.get("path") or ""))
    if str(root) in ("", "."):
        raise ValueError("no path configured")
    subdir = str(corpus.get("subdir") or "").strip()
    return root / subdir if subdir else root


def _read_corpora(path: Path) -> list[dict]:
    """Read the `corpora:` list from one registry file (empty if missing/bad).

    A root that is not a mapping, or a `corpora:` that is not a list, makes the
    whole file unreadable, as a YAML error does (#436). Inside the list, an entry
    that is not a mapping is skipped with a warning and the others still load."""
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        logger.error(f"[detection] could not parse {path}: {e}")
        return []
    if not isinstance(data, dict):
        logger.error(f"[detection] could not parse {path}: the root is not a mapping")
        return []
    corpora = data.get("corpora") or []
    if not isinstance(corpora, list):
        logger.error(f"[detection] could not parse {path}: 'corpora' is not a list")
        return []
    entries = []
    for entry in corpora:
        if isinstance(entry, dict):
            entries.append(entry)
        else:
            logger.warning(f"[detection] {path}: entry {entry!r} is not a mapping — skipped")
    return entries


def _local_overlay_path(config_path: Path) -> Path:
    """`detection_corpora.yaml` → `detection_corpora.local.yaml` (gitignored overlay)."""
    return config_path.with_name(f"{config_path.stem}.local{config_path.suffix}")


#: The keys that name where a corpus's files come from. An overlay that names one
#: of them replaces the committed source (#368); the other one is dropped.
_SOURCE_KEYS = ("git", "tarball")


def _merged(path: Path) -> list[dict]:
    """Committed registry with the local overlay merged over it (override by
    `name`, append new). Includes disabled entries. See ADR-0006 Rev 3.

    An overlay entry that names a source (`git` or `tarball`) chooses the source of
    the merged entry: a source key the overlay does not set is dropped from the
    committed entry, so the merged corpus never carries two URLs (#368). An overlay
    with no source (e.g. `{"name": X, "enabled": False}`) keeps the committed source."""
    merged: dict[str, dict] = {}
    order: list[str] = []
    for entry in [*_read_corpora(path), *_read_corpora(_local_overlay_path(path))]:
        name = entry.get("name")
        if not name:
            continue
        if name in merged:
            if any(entry.get(k) for k in _SOURCE_KEYS):
                for k in _SOURCE_KEYS:
                    if not entry.get(k):
                        merged[name].pop(k, None)
            merged[name].update(entry)   # local overrides committed by name
        else:
            merged[name] = dict(entry)
            order.append(name)
    return [merged[n] for n in order]


def merged_corpora(config_path: str | Path) -> list[dict]:
    """All corpora incl. disabled — for the settings UI."""
    return _merged(Path(config_path))


def load_corpora(config_path: str | Path) -> list[dict]:
    """Enabled corpus entries (merged committed + overlay)."""
    items = _merged(Path(config_path))
    if not items:
        logger.warning(f"[detection] no corpus registry at {config_path} (or its .local overlay)")
    return [c for c in items if c.get("enabled", True)]


# ── Overlay writes (settings UI, ADR-0007) — only ever touch the gitignored overlay ──

#: Serialises the read-modify-write of the overlay (#371). The RLock covers the
#: threads of this process; the flock in `_overlay_lock` covers other uvicorn
#: workers (API_WORKERS > 1), which have their own RLock.
_OVERLAY_LOCK = threading.RLock()
_HELD = threading.local()   # this thread's nesting depth inside _overlay_lock


@contextmanager
def _overlay_lock(config_path: Path) -> Iterator[None]:
    """Hold the overlay lock for a whole read-modify-write. The flock is taken on
    the registry's directory, not on a `.lock` file, so no untracked file appears
    beside the gitignored overlay. Closing the descriptor releases the flock.
    A flock on a second descriptor would wait on the first even in the same
    thread, so a nested call (holding the RLock already) takes only the RLock."""
    with _OVERLAY_LOCK:
        if getattr(_HELD, "depth", 0):
            _HELD.depth += 1
            try:
                yield
            finally:
                _HELD.depth -= 1
            return
        fd = os.open(config_path.parent, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _HELD.depth = 1
            try:
                yield
            finally:
                _HELD.depth = 0
        finally:
            os.close(fd)


def _write_overlay_file(config_path: str | Path, corpora: list[dict]) -> None:
    """Replace the overlay in one step: write a sibling `.tmp`, then `os.replace` it
    over the overlay, so a reader or a crash never sees half a file. The caller
    holds `_overlay_lock`.

    The path is resolved first (#371). In the Docker image the overlay is a symlink
    into the state volume (`/app/detection_corpora.local.yaml` → `/app/state/...`),
    and `/app` is read-only: a `.tmp` beside the link would fail, and `os.replace`
    over the link would turn it into a plain file that never reaches the volume. So
    the `.tmp` sits beside the real file, and the replace stays atomic on one
    filesystem. `resolve()` also follows a link whose target does not exist yet."""
    overlay = _local_overlay_path(Path(config_path)).resolve()
    tmp = overlay.with_name(overlay.name + ".tmp")
    tmp.write_text(
        yaml.safe_dump({"corpora": corpora}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    os.replace(tmp, overlay)


def write_overlay(config_path: str | Path, corpora: list[dict]) -> None:
    """Replace the overlay under `_overlay_lock`. Read-modify-write callers must
    hold the lock themselves across the read (see add_corpus)."""
    with _overlay_lock(Path(config_path)):
        _write_overlay_file(config_path, corpora)


def add_corpus(config_path: str | Path, entry: dict) -> list[dict]:
    """Add/replace a corpus in the local overlay (by `name`). Returns the overlay list.
    The read, the change and the write form one locked section (#371)."""
    with _overlay_lock(Path(config_path)):
        overlay = [c for c in _read_corpora(_local_overlay_path(Path(config_path)))
                   if c.get("name") != entry.get("name")]
        overlay.append(entry)
        _write_overlay_file(config_path, overlay)
    return overlay


def remove_corpus(config_path: str | Path, name: str) -> list[dict]:
    """Remove a corpus. If it's defined in the committed registry, write a disable
    override into the overlay instead (we never edit the committed file).
    The read, the change and the write form one locked section (#371)."""
    path = Path(config_path)
    with _overlay_lock(path):
        overlay = [c for c in _read_corpora(_local_overlay_path(path)) if c.get("name") != name]
        if any(c.get("name") == name for c in _read_corpora(path)):
            overlay.append({"name": name, "enabled": False})   # disable a committed corpus
        _write_overlay_file(config_path, overlay)
    return overlay


def iter_rules(config_path: str | Path) -> Iterable[DetectionRule]:
    """Parse every enabled corpus into normalized DetectionRule records."""
    for corpus in load_corpora(config_path):
        name = corpus.get("name", "?")
        adapter = _ADAPTERS.get(corpus.get("adapter", ""))
        if adapter is None:
            logger.warning(f"[detection] corpus '{name}': unknown adapter '{corpus.get('adapter')}' — skipped")
            continue
        try:
            root = corpus_root(corpus)
        except ValueError as e:
            logger.warning(f"[detection] corpus '{name}': {e} — skipped")
            continue
        if not root.exists():
            logger.warning(f"[detection] corpus '{name}': path '{root}' missing — run sync_corpora first")
            continue
        yield from adapter.parse(
            root,
            corpus=name,
            license=corpus.get("license", "unknown"),
        )
