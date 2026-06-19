"""Corpus registry — reads the two-tier detection_corpora.yaml and dispatches to adapters.

A committed `detection_corpora.yaml` holds public corpuses (reproducible); an
optional gitignored `detection_corpora.local.yaml` overlay holds private corpuses
and local overrides. The overlay is merged over the committed file (override by
`name`, append new). Corpuses are local clones; fetching is a separate sync step
(scripts/sync_corpora.py), so git credentials never enter CTIParsor (ADR-0006).
"""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from api.logging_config import get_logger
from models.detection import DetectionRule
from pipeline.detection.base import RuleCorpusAdapter
from pipeline.detection.sigma import SigmaAdapter

logger = get_logger(__name__)

# format key → adapter instance.  Register new formats here (the ADR-0006 seam).
_ADAPTERS: dict[str, RuleCorpusAdapter] = {
    SigmaAdapter.format: SigmaAdapter(),
}


def _read_corpora(path: Path) -> list[dict]:
    """Read the `corpora:` list from one registry file (empty if missing/bad)."""
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        logger.error(f"[detection] could not parse {path}: {e}")
        return []
    return data.get("corpora") or []


def _local_overlay_path(config_path: Path) -> Path:
    """`detection_corpora.yaml` → `detection_corpora.local.yaml` (gitignored overlay)."""
    return config_path.with_name(f"{config_path.stem}.local{config_path.suffix}")


def _merged(path: Path) -> list[dict]:
    """Committed registry with the local overlay merged over it (override by
    `name`, append new). Includes disabled entries. See ADR-0006 Rev 3."""
    merged: dict[str, dict] = {}
    order: list[str] = []
    for entry in [*_read_corpora(path), *_read_corpora(_local_overlay_path(path))]:
        name = entry.get("name")
        if not name:
            continue
        if name in merged:
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

def write_overlay(config_path: str | Path, corpora: list[dict]) -> None:
    _local_overlay_path(Path(config_path)).write_text(
        yaml.safe_dump({"corpora": corpora}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def add_corpus(config_path: str | Path, entry: dict) -> list[dict]:
    """Add/replace a corpus in the local overlay (by `name`). Returns the overlay list."""
    overlay = [c for c in _read_corpora(_local_overlay_path(Path(config_path)))
               if c.get("name") != entry.get("name")]
    overlay.append(entry)
    write_overlay(config_path, overlay)
    return overlay


def remove_corpus(config_path: str | Path, name: str) -> list[dict]:
    """Remove a corpus. If it's defined in the committed registry, write a disable
    override into the overlay instead (we never edit the committed file)."""
    path = Path(config_path)
    overlay = [c for c in _read_corpora(_local_overlay_path(path)) if c.get("name") != name]
    if any(c.get("name") == name for c in _read_corpora(path)):
        overlay.append({"name": name, "enabled": False})   # disable a committed corpus
    write_overlay(config_path, overlay)
    return overlay


def iter_rules(config_path: str | Path) -> Iterable[DetectionRule]:
    """Parse every enabled corpus into normalized DetectionRule records."""
    for corpus in load_corpora(config_path):
        name = corpus.get("name", "?")
        adapter = _ADAPTERS.get(corpus.get("adapter", ""))
        if adapter is None:
            logger.warning(f"[detection] corpus '{name}': unknown adapter '{corpus.get('adapter')}' — skipped")
            continue
        root = Path(corpus.get("path", ""))
        if not root.exists():
            logger.warning(f"[detection] corpus '{name}': path '{root}' missing — run sync_corpora first")
            continue
        yield from adapter.parse(
            root,
            corpus=name,
            license=corpus.get("license", "unknown"),
        )
