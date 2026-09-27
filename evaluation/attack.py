"""ATT&CK version mapping: gold labels from an older ATT&CK against today's.

AnnoCTR was annotated against the ATT&CK of 2022; the pipeline predicts ids
from its own index (pipeline/data/mitre_index.json).  Between the two,
techniques were revoked (merged into another id), deprecated, or split into
sub-techniques.  Without a mapping, a pipeline that answers with the current id
is scored as wrong — a taxonomy gap read as a model error.

`mapping(gold_ids)` gives, for every gold id: its status in the current bundle,
the id it resolves to (following `revoked-by` chains), and whether the pipeline
can emit it at all.  Gold ids that resolve to nothing the pipeline knows are
reported and left out of the primary score, never silently counted as misses.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE = _ROOT / "data" / "enterprise-attack.json"
PIPELINE_INDEX = _ROOT / "pipeline" / "data" / "mitre_index.json"

ACTIVE, REVOKED, DEPRECATED, UNKNOWN = "active", "revoked", "deprecated", "unknown"


def parent(tid: str) -> str:
    return tid.split(".", 1)[0].upper()


@dataclass
class Resolution:
    gold_id: str
    status: str                 # status of gold_id in the current bundle
    canonical: str | None       # the id to score against (None = out of scope)
    in_pipeline: bool           # can the pipeline emit `canonical`?

    def as_dict(self) -> dict:
        return {"gold_id": self.gold_id, "status": self.status,
                "canonical": self.canonical, "in_pipeline": self.in_pipeline}


class Catalogue:
    def __init__(self, bundle_path: Path = DEFAULT_BUNDLE, pipeline_index: Path = PIPELINE_INDEX):
        if not bundle_path.exists():
            raise FileNotFoundError(
                f"{bundle_path} missing — run: python scripts/download_attack.py")
        raw = bundle_path.read_bytes()
        self.bundle_sha256 = hashlib.sha256(raw).hexdigest()
        objects = json.loads(raw)["objects"]

        self.status: dict[str, str] = {}
        stix_to_tid: dict[str, str] = {}
        latest_modified = ""
        for o in objects:
            if o.get("type") != "attack-pattern":
                continue
            tid = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            tid = tid.upper()
            stix_to_tid[o["id"]] = tid
            latest_modified = max(latest_modified, o.get("modified", ""))
            if o.get("revoked"):
                self.status[tid] = REVOKED
            elif o.get("x_mitre_deprecated"):
                self.status[tid] = DEPRECATED
            else:
                self.status.setdefault(tid, ACTIVE)
        self.latest_modified = latest_modified

        self.revoked_by: dict[str, str] = {}
        for o in objects:
            if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
                src, dst = stix_to_tid.get(o.get("source_ref", "")), stix_to_tid.get(o.get("target_ref", ""))
                if src and dst:
                    self.revoked_by[src] = dst

        index = json.loads(pipeline_index.read_text(encoding="utf-8"))
        self.pipeline_ids = {t["id"].upper() for t in index.get("techniques", [])
                             if str(t.get("id", "")).upper().startswith("T")}

    def resolve(self, gold_id: str) -> Resolution:
        gid = gold_id.upper()
        status = self.status.get(gid, UNKNOWN)
        canonical: str | None = gid
        seen = set()
        while canonical in self.revoked_by and canonical not in seen:
            seen.add(canonical)
            canonical = self.revoked_by[canonical]
        if status == DEPRECATED or (status == REVOKED and canonical == gid):
            canonical = None
        if status == UNKNOWN:
            # Not in the current bundle at all; the pipeline may still know it.
            canonical = gid if gid in self.pipeline_ids else None
        return Resolution(gid, status, canonical,
                          canonical is not None and canonical in self.pipeline_ids)

    def mapping(self, gold_ids: set[str]) -> dict[str, Resolution]:
        return {g: self.resolve(g) for g in sorted(gold_ids)}

    def summary(self) -> dict:
        return {"bundle_sha256": self.bundle_sha256[:16],
                "bundle_latest_modified": self.latest_modified,
                "pipeline_index_ids": len(self.pipeline_ids)}
