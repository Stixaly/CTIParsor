"""
The mapping ledger: what Stage 4 did with each thing it was given (ADR-0061).

The review graph shows the job store's rows; the bundle is built from those rows
and then differs from them — edges are added (IoC plumbing, policy pins, graph
completion), verbs are rewritten (a pinned rule, a verb STIX does not suggest
for the pair), observable endpoints are routed through their Indicator, and
some rows never make it at all (an endpoint that resolves to nothing, a
self-loop created by alias resolution, a country with no ISO code).  Every one
of those decisions used to be silent.

`build_stix_bundle` records them here as it makes them, so the graph can show
the analyst the bundle that actually ships *and* what happened to each row on
the way.  The ledger is stored beside the bundle (`jobs.bundle_ledger_json`),
never inside it: it describes the build, it is not STIX content.

Shape of `to_dict()` (version 1):

    objects        {stix_id: {"origin": str, ...}}   why each object/SRO exists
    entities       [{value, entity_type, outcome, stix_id?, reason?, ...}]
    relationships  [{source_value, relationship_type, target_value, outcome,
                     stix_id?, final_type?, source_ref?, target_ref?,
                     changes: [...], reason?, merged_with?}]
    removed        [{stix_id, kind, reason, replaced_by?}]   removed after creation

Outcomes: "emitted" (this input produced the object), "merged" (it resolved to
an object or edge that already existed — `stix_id` / `merged_with` names it),
"dropped" (not in the bundle — `reason` says why).
"""
from __future__ import annotations

from typing import Any

from pipeline.stix_access import field as stix_field

LEDGER_VERSION = 1

# Relationship origins that do not come from a job-store row.  An SRO with no
# recorded origin is classified from its own provenance properties (ADR-0024).
ORIGIN_EXTRACTED = "extracted"          # a relationships row (LLM or analyst)


def _rel_origin_from_props(rel: Any) -> str:
    rule = stix_field(rel, "x_inference_rule") or ""
    if isinstance(rule, str):
        if rule.startswith("attack-reference"):
            return "completion_reference"
        if rule.startswith("transitive"):
            return "completion_transitive"
        if rule == "long-distance":
            return "completion_long_distance"
    if stix_field(rel, "x_policy_rule"):
        return "policy_pin"
    return "unknown"


class MappingLedger:
    """Collects Stage 4's per-input decisions.  Cheap: a few dicts per input."""

    def __init__(self) -> None:
        self.objects: dict[str, dict] = {}
        self.entities: list[dict] = []
        self.relationships: list[dict] = []
        self.removed: list[dict] = []

    # ── objects ──────────────────────────────────────────────────────────────
    def object(self, obj: Any, origin: str, **info: Any) -> None:
        """Record why `obj` exists.  First writer wins: an object is created
        once, and a later call for the same id is a reuse, not a new origin."""
        oid = getattr(obj, "id", None)
        if oid and oid not in self.objects:
            self.objects[oid] = {"origin": origin, **_clean(info)}

    def annotate(self, stix_id: str | None, **info: Any) -> None:
        """Add facts to an already-recorded object (an IoC with no Indicator)."""
        if stix_id is not None and stix_id in self.objects:
            self.objects[stix_id].update(_clean(info))

    # ── entities ─────────────────────────────────────────────────────────────
    def entity(
        self, value: str, entity_type: str, outcome: str, *,
        obj: Any = None, reason: str | None = None, **info: Any,
    ) -> None:
        entry: dict = {"value": value, "entity_type": entity_type, "outcome": outcome}
        if obj is not None:
            entry["stix_id"] = obj.id
            entry["stix_type"] = stix_field(obj, "type")
            name = stix_field(obj, "name")
            if name:
                entry["stix_name"] = name
        if reason:
            entry["reason"] = reason
        entry.update(_clean(info))
        self.entities.append(entry)

    # ── relationships (job-store rows) ───────────────────────────────────────
    def relationship(self, rel_in: Any, outcome: str, **info: Any) -> dict:
        """Record one input relationship.  Returns the entry so the caller can
        amend it (a later duplicate that replaces this edge, for instance)."""
        entry: dict = {
            "source_value": rel_in.source_value,
            "relationship_type": rel_in.relationship_type,
            "target_value": rel_in.target_value,
            "outcome": outcome,
            "changes": [],
        }
        entry.update(_clean(info))
        self.relationships.append(entry)
        return entry

    def replace_relationship(self, old_id: str, new_rel: Any) -> None:
        """A later copy of the same edge replaced `old_id` in the bundle (it
        carried start/stop times the first did not).  Entries that pointed at
        the old SRO now point at the one that ships."""
        for e in self.relationships:
            if e.get("stix_id") == old_id:
                e["outcome"] = "merged"
                e["merged_with"] = new_rel.id
                e["stix_id"] = new_rel.id
        origin = self.objects.pop(old_id, None)
        if origin is not None:
            self.objects[new_rel.id] = origin

    # ── Stage 4b alias merge ─────────────────────────────────────────────────
    def apply_alias_merge(self, merged_ids: dict[str, str], removed_rels: list[dict],
                          remapped_rels: dict[str, tuple[str, str]],
                          merged_names: dict[str, str] | None = None) -> None:
        """Carry Stage 4b's destructive alias merge into the ledger: objects it
        absorbed, SROs it dropped (self-loops / duplicates it created) and the
        endpoints it rewrote."""
        for dup, canon in merged_ids.items():
            self.removed.append(_clean({"stix_id": dup, "kind": "object",
                                        "reason": "alias_merge", "replaced_by": canon,
                                        "name": (merged_names or {}).get(dup)}))
            self.objects.pop(dup, None)
            for e in self.entities:
                if e.get("stix_id") == dup:
                    e["outcome"] = "merged"
                    e["reason"] = "alias_merge"
                    e["stix_id"] = canon
        for r in removed_rels:
            self.removed.append({"stix_id": r["id"], "kind": "relationship",
                                 "reason": r["reason"], "replaced_by": r.get("kept")})
            self.objects.pop(r["id"], None)
            for e in self.relationships:
                if e.get("stix_id") != r["id"]:
                    continue
                if r.get("kept"):
                    e["outcome"] = "merged"
                    e["merged_with"] = r["kept"]
                    e["stix_id"] = r["kept"]
                else:
                    e["outcome"] = "dropped"
                    e["reason"] = r["reason"]
                    e.pop("stix_id", None)
        for rid, (src, tgt) in remapped_rels.items():
            for e in self.relationships:
                if e.get("stix_id") == rid:
                    e["source_ref"], e["target_ref"] = src, tgt

    # ── finish ───────────────────────────────────────────────────────────────
    def finalize(self, stix_objects: list) -> None:
        """Classify every SRO nobody recorded (policy pins, graph completion)
        from its own provenance properties."""
        for o in stix_objects:
            if stix_field(o, "type") != "relationship":
                continue
            if o.id not in self.objects:
                self.objects[o.id] = {"origin": _rel_origin_from_props(o)}

    def to_dict(self) -> dict:
        return {
            "version": LEDGER_VERSION,
            "objects": self.objects,
            "entities": self.entities,
            "relationships": self.relationships,
            "removed": self.removed,
        }


def _clean(info: dict) -> dict:
    """Drop None values so the stored JSON only says what is known."""
    return {k: v for k, v in info.items() if v is not None}
