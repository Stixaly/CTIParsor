"""Settings API (ADR-0007) — Slice 1: detection-corpora management.

No secrets here. Adds/removes operate on the gitignored local overlay
(detection_corpora.local.yaml); the committed registry is never edited by the app.
The LLM-keys panel (Slice 2) is intentionally not implemented yet — it needs the
secret-storage + loopback-guard work from ADR-0007.
"""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.db import get_conn
from pipeline.detection.builder import rebuild_store
from pipeline.detection.registry import add_corpus, merged_corpora, remove_corpus
from pipeline.detection.store import corpus_counts

router = APIRouter(prefix="/api/settings", tags=["settings"])

_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _ROOT / "detection_corpora.yaml"


class CorpusIn(BaseModel):
    name: str
    git: str | None = None
    path: str | None = None
    license: str = "unknown"
    private: bool = False
    enabled: bool = True
    adapter: str = "sigma"


def _with_counts() -> list[dict]:
    items = merged_corpora(_CONFIG)
    with get_conn() as conn:
        counts = {c["corpus"]: c["rules"] for c in corpus_counts(conn)}
    for it in items:
        it["rules"] = counts.get(it.get("name"), 0)
        it["enabled"] = it.get("enabled", True)
    return items


@router.get("/corpora")
def list_corpora():
    return {"corpora": _with_counts()}


@router.post("/corpora")
def create_corpus(body: CorpusIn):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "name is required")
    if body.adapter != "sigma":
        raise HTTPException(400, f"unsupported adapter '{body.adapter}' (only 'sigma' today)")
    entry = body.model_dump()
    entry["name"] = name
    if not entry.get("path"):
        entry["path"] = f"./corpora/{name}"
    add_corpus(_CONFIG, entry)
    return {"ok": True, "corpora": _with_counts()}


@router.delete("/corpora/{name}")
def delete_corpus(name: str):
    remove_corpus(_CONFIG, name)
    return {"ok": True, "corpora": _with_counts()}


@router.post("/corpora/rebuild")
def rebuild_corpora():
    """Re-ingest all enabled corpora from their existing local clones into the store.

    Fetching new clones is still the CLI step `python scripts/sync_corpora.py`
    (a background git-sync endpoint is Slice-2 work).
    """
    with get_conn() as conn:
        return rebuild_store(conn, _CONFIG)
