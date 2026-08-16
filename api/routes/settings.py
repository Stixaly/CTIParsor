"""Settings API (ADR-0007, ADR-0019) — Slice 1: detection-corpora management.

No secrets here. Adds/removes operate on the gitignored local overlay
(detection_corpora.local.yaml); the committed registry is never edited by the app.
The LLM-keys panel (Slice 2) is intentionally not implemented yet — it needs the
secret-storage + loopback-guard work from ADR-0007.

ADR-0019: Multi-format support (sigma/suricata/yara). Format availability is
derived from the pipeline detection registry adapters (_ADAPTERS).
"""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import get_conn
from pipeline.detection.builder import rebuild_store
from pipeline.detection.registry import _ADAPTERS, add_corpus, merged_corpora, remove_corpus
from pipeline.detection.store import corpus_counts
from pipeline.detection.sync import sync_corpus

router = APIRouter(prefix="/api/settings", tags=["settings"])

_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _ROOT / "detection_corpora.yaml"

#: Formats this project recognises, independent of whether a parser is compiled in.
#:
#: Configuring and *ingesting* are deliberately separate. `_ADAPTERS` says what can
#: be parsed today; this says what may be written to the registry. Gating creation
#: on `_ADAPTERS` alone would be incoherent — the committed registry already holds
#: seven suricata/yara corpora (ADR-0015), so the API would refuse to create what
#: the config already contains, and a user could never stage a repo ahead of its
#: adapter shipping. A corpus whose adapter is missing is accepted, flagged
#: `adapter_available: false`, and simply contributes no rules until it lands.
KNOWN_FORMATS: frozenset[str] = frozenset({"sigma", "suricata", "yara"})


class CorpusIn(BaseModel):
    name: str
    adapter: str = "sigma"
    git: str | None = None
    tarball: str | None = None
    path: str | None = None
    subdir: str | None = None
    license: str = "unknown"
    priority: int | None = None
    private: bool = False
    enabled: bool = True


class CorpusPatch(BaseModel):
    enabled: bool


def _with_counts() -> list[dict]:
    items = merged_corpora(_CONFIG)
    with get_conn() as conn:
        counts = {c["corpus"]: c["rules"] for c in corpus_counts(conn)}
    for it in items:
        it["rules"] = counts.get(it.get("name"), 0)
        it["enabled"] = it.get("enabled", True)
        it["adapter"] = it.get("adapter", "sigma")
        it["adapter_available"] = it["adapter"] in _ADAPTERS
    return items


@router.get("/corpora")
def list_corpora():
    """List all configured corpora with their rule counts and adapter availability."""
    return {"corpora": _with_counts()}


@router.get("/formats")
def list_formats():
    """List all known formats (compiled adapters + configured corpora) with stats."""
    items = _with_counts()
    # Union of: what can be parsed, what the project recognises, and what is
    # actually configured — so a corpus for an uncompiled format stays visible
    # instead of silently vanishing from the UI.
    formats = set(_ADAPTERS) | set(KNOWN_FORMATS)
    for it in items:
        if it.get("adapter"):
            formats.add(it["adapter"])

    result = []
    for f in sorted(formats):
        corpus_list = [it for it in items if it.get("adapter") == f]
        result.append({
            "format": f,
            "available": f in _ADAPTERS,
            "corpora": len(corpus_list),
            "rules": sum(it.get("rules", 0) for it in corpus_list),
        })
    return {"formats": result}


@router.post("/corpora")
def create_corpus(body: CorpusIn):
    """Add a new corpus to the local overlay. Validates adapter against available parsers."""
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")

    adapter = (body.adapter or "").strip().lower()
    if adapter not in KNOWN_FORMATS:
        known = ", ".join(sorted(KNOWN_FORMATS))
        raise HTTPException(400, f"unknown format '{adapter}' — known formats: {known}")

    if body.git and body.tarball:
        raise HTTPException(400, "provide either 'git' or 'tarball', not both")

    entry = body.model_dump()
    entry["name"] = name
    entry["adapter"] = adapter

    # `path` is always required: it is where the clone/extraction LIVES locally,
    # not an alternative to `git`/`tarball`. Every entry in the committed registry
    # carries both, and `corpus_root()` parses `path`, so defaulting it only for
    # sourceless corpora would leave a git corpus with nowhere to land.
    if not entry.get("path"):
        entry["path"] = f"./corpora/{name}"

    # Remove None values to avoid writing nulls to YAML
    entry = {k: v for k, v in entry.items() if v is not None}

    add_corpus(_CONFIG, entry)
    # Surface the "configured but not yet ingestible" case explicitly, so the UI
    # never has to infer it and the operator is told at the moment of creation.
    warning = (
        None if adapter in _ADAPTERS else
        f"'{adapter}' has no parser in this build — the repo is saved and will "
        f"ingest once its adapter ships. Available now: "
        f"{', '.join(sorted(_ADAPTERS)) or 'none'}."
    )
    return {"ok": True, "warning": warning, "corpora": _with_counts()}


@router.delete("/corpora/{name}")
def delete_corpus(name: str):
    """Remove a corpus from the local overlay."""
    remove_corpus(_CONFIG, name)
    return {"ok": True, "corpora": _with_counts()}


@router.patch("/corpora/{name}")
def patch_corpus(name: str, body: CorpusPatch):
    """Enable or disable a corpus without losing its configuration.

    This route exists because `remove_corpus` writes a deactivation override for
    committed registry corpora, but there was no way to re-enable them from the UI
    without manually editing the YAML. ADR-0015 shipped seven corpora disabled,
    making them inaccessible without this endpoint.
    """
    corpus = next((c for c in merged_corpora(_CONFIG) if c.get("name") == name), None)
    if corpus is None:
        raise HTTPException(404, f"unknown corpus '{name}'")

    entry = dict(corpus)
    entry.pop("rules", None)
    entry.pop("adapter_available", None)
    entry["enabled"] = body.enabled

    add_corpus(_CONFIG, entry)
    return {"ok": True, "corpora": _with_counts()}


@router.post("/corpora/{name}/sync")
def sync_one_corpus(name: str):
    """Clone/pull ONE public corpus's git remote, then re-ingest the store.

    This is the same networked step as `scripts/sync_corpora.py`, exposed per-row
    for the Settings "Redownload" button. Restricted to PUBLIC corpora: private
    ones must use the CLI so git credentials never flow through the app (ADR-0006).
    Cloning a large repo can take a while — the request blocks until git finishes.
    """
    corpus = next((c for c in merged_corpora(_CONFIG) if c.get("name") == name), None)
    if corpus is None:
        raise HTTPException(404, f"unknown corpus '{name}'")

    if corpus.get("tarball"):
        raise HTTPException(
            400,
            f"'{name}' is a tarball source — fetching it is not implemented yet "
            "(ADR-0019 leaves the tarball fetch to sync_corpora.py)",
        )

    if not corpus.get("git"):
        raise HTTPException(400, f"'{name}' has no git remote — its path is managed manually")

    if corpus.get("private"):
        raise HTTPException(
            400,
            f"'{name}' is private — fetch it with `python scripts/sync_corpora.py` "
            "so git credentials stay out of the app",
        )

    ok, detail = sync_corpus(corpus)
    if not ok:
        raise HTTPException(502, f"git sync failed: {detail}")

    with get_conn() as conn:
        rebuild_store(conn, _CONFIG)
    return {"ok": True, "detail": detail, "corpora": _with_counts()}


@router.post("/corpora/rebuild")
def rebuild_corpora():
    """Re-ingest all enabled corpora from their existing local clones into the store.

    Fetching new clones is still the CLI step `python scripts/sync_corpora.py`
    (a background git-sync endpoint is Slice-2 work).
    """
    with get_conn() as conn:
        return rebuild_store(conn, _CONFIG)
