"""
Stage 4b — STIX graph completion (edge enrichment).

Motivation
----------
Stages 3/3d/3f only emit a relationship when the LLM finds an *explicit*
statement AND can quote a supporting sentence.  That gate is what keeps precision
high — and it is also why the graph is sparse: two objects that clearly belong
together but were never described in one sentence get no edge, and aliasing
("APT29" vs "Cozy Bear") fragments the graph into disconnected islands.

This stage adds edges *after* the precision-gated extraction, without touching
it, through three append-only / non-speculative mechanisms (design: ADR-0013,
inspired by CTINexus, arXiv:2410.21060):

1. Alias merge          — FALLBACK, default OFF.  ``pipeline/aliases.py`` (ADR-0012)
   (default off)          already canonicalises MITRE-known aliases at SDO-creation
                          time in Stage 4, so "APT34"/"OilRig" never become two
                          nodes in the first place — the better fix, since it
                          prevents the split rather than repairing it.  This pass
                          only helps for aliases *absent from the gazetteer*
                          (novel or report-specific names), and for the opt-in
                          ``fuzzy_alias`` / ``semantic_alias`` matchers.  It is the
                          only destructive step, so it is off unless asked for;
                          IOC-bearing SCOs are never merged (deterministic value
                          identity already dedups them, and near-identical IOCs
                          are *distinct*).
2. Transitive inference — compose two verified edges along a fixed, spec-safe
                          rule table (A--v1-->B, B--v2-->C  ⟹  A--v3-->C).  Every
                          candidate is guarded by ``rel_is_suggested`` and dropped
                          if the composed verb is not a *suggested* STIX 2.1
                          relationship for the (src-type → tgt-type) pair, so no
                          invalid or speculative edge ever ships.
3. Long-distance         — connect leftover disconnected sub-graphs by asking an
   (opt-in)              injected LLM inferer for the relation between each
                          sub-graph's central node and the report's topic node
                          (CTINexus Phase 3).  Off unless a callable is supplied.

Accuracy guarantee
------------------
Every inferred edge is tagged ``x_evidence_label="inferred"`` (weakest grade),
carries ``x_inference_rule`` and ``x_inferred_from`` (the premise edge ids) for
provenance, and — for the deterministic step — is *only* emitted when it is a
suggested relationship.  Nothing here loosens the extraction gate.

Policy — "user specifies vs. tool decides"
-----------------------------------------
Controlled by an optional ``completion`` block on the relationship policy::

    "completion": {
        "transitive":    true,     # step 2 (default on)
        "reference":     true,     # ATT&CK curated-edge grounding (default on)
        "alias":         false,    # step 1 fallback — aliases.py handles the
                                   #   MITRE-known case at SDO-creation time
        "long_distance": false,    # step 3 (default off; needs an LLM inferer)
        "fuzzy_alias":   false,    # allow rapidfuzz name matching, not just norm-eq
        "semantic_alias": false,   # embedding cosine >= 0.6 matching (needs model)
        "max_new_edges": 200       # safety cap on added-edge output
    }

A pinned rule ("mode":"pin") always wins: an inferred verb is overridden by the
analyst's pinned verb for that type-pair, so the tool never contradicts an
explicit human decision.
"""
from __future__ import annotations

import functools
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import stix2

from api.logging_config import get_logger
from models.schemas import STIX_RELATIONSHIP_TYPES
from pipeline.stix_rel_spec import rel_is_suggested

logger = get_logger(__name__)

VALID_REL_TYPES = STIX_RELATIONSHIP_TYPES

# ── Defaults for the policy "completion" block ────────────────────────────────
_DEFAULTS = {
    "transitive": True,
    # Off by default: pipeline/aliases.py (ADR-0012) canonicalises MITRE-known
    # aliases at SDO-creation time, so this post-hoc merge is only a fallback for
    # names absent from the gazetteer.  It is also the only destructive engine.
    "alias": False,
    "reference": True,        # ATT&CK curated-edge grounding
    "long_distance": False,
    "fuzzy_alias": False,
    "semantic_alias": False,  # embedding-based alias matching (needs the model)
    "max_new_edges": 200,
}

# Fuzzy alias threshold (rapidfuzz ratio, 0-100) when fuzzy_alias is on.
_FUZZY_THRESHOLD = 93

# Cosine threshold for embedding-based alias matching (semantic_alias) — the
# value CTINexus found optimal (tested 0.4/0.5/0.6/0.7; arXiv:2410.21060 §5.4.1).
_SEMANTIC_THRESHOLD = 0.6

# SDO types that carry an ``aliases`` list and denote a single actor/thing, so
# collapsing same-real-world duplicates is meaningful.  SCOs are excluded on
# purpose — their identity is their value, and look-alikes are distinct.
_ALIASABLE_TYPES: frozenset[str] = frozenset(
    {"threat-actor", "intrusion-set", "malware", "campaign", "tool"}
)

# Regexes for IOC-shaped names we must never merge even if they look similar
# (CTINexus' "IOC protection": CVE-2023-23397 vs CVE-2023-23392 are distinct).
_IOC_GUARD = re.compile(
    r"(?i)\b(?:CVE-\d{4}-\d+|[0-9a-f]{32,64}|(?:\d{1,3}\.){3}\d{1,3})\b"
)

# ── Deterministic transitive composition table (ADR-0013) ─────────────────────
# (verb_ab, verb_bc) -> verb_ac.  Every emission is still guarded by
# rel_is_suggested(type_a, verb_ac, type_c); a composed verb that is not a
# suggested relationship for the actual type pair is skipped, never downgraded.
_TRANSITIVE_RULES: dict[tuple[str, str], str] = {
    ("uses", "uses"): "uses",                    # actor uses malware, malware uses TTP -> actor uses TTP
    ("attributed-to", "attributed-to"): "attributed-to",
    ("attributed-to", "uses"): "uses",           # campaign->intrusion-set->malware ⟹ campaign uses malware
    ("uses", "variant-of"): "uses",
    ("variant-of", "uses"): "uses",
    ("variant-of", "variant-of"): "variant-of",
    ("uses", "exploits"): "targets",             # actor uses malware, malware exploits vuln ⟹ actor targets vuln
    ("indicates", "uses"): "indicates",          # indicator->malware->TTP ⟹ indicator indicates TTP
    ("indicates", "variant-of"): "indicates",
}


@dataclass
class InferredEdge:
    """Return type for a long-distance LLM inferer (step 3)."""

    source_id: str
    verb: str
    target_id: str
    confidence: float = 0.5
    evidence_text: str = ""   # supporting sentence quoted from the report


@dataclass
class CompletionStats:
    aliases_merged: int = 0
    reference_added: int = 0
    transitive_added: int = 0
    long_distance_added: int = 0
    skipped_not_suggested: int = 0
    capped: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def total_added(self) -> int:
        return self.reference_added + self.transitive_added + self.long_distance_added


# ── small STIX-object helpers ─────────────────────────────────────────────────
def _otype(obj) -> str:
    if hasattr(obj, "get"):
        return obj.get("type") or ""
    return getattr(obj, "type", "") or ""


def _is_rel(obj) -> bool:
    return _otype(obj) == "relationship"


def _rel_triple(rel) -> tuple[str, str, str]:
    return (rel.get("source_ref"), rel.get("relationship_type"), rel.get("target_ref"))


def _clone_with(obj, **overrides):
    """Return a copy of a stix2 object with some properties replaced.

    stix2 objects are immutable; we round-trip through JSON so custom (x_) props
    and the original id/timestamps are preserved.  A property set to ``None`` in
    ``overrides`` is removed.
    """
    d = json.loads(obj.serialize())
    for k, v in overrides.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return stix2.parse(d, allow_custom=True)


def _norm_name(name: str) -> str:
    """Normalise a display name for alias equality: casefold, strip punctuation."""
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _completion_cfg(policy: Optional[dict]) -> dict:
    cfg = dict(_DEFAULTS)
    if policy and isinstance(policy.get("completion"), dict):
        cfg.update({k: v for k, v in policy["completion"].items() if k in _DEFAULTS})
    return cfg


def _pol_index(policy: Optional[dict]) -> dict[str, dict]:
    """Index pinned rules by 'srcType>tgtType' (mirrors build_stix_bundle)."""
    idx: dict[str, dict] = {}
    if policy and policy.get("global") != "auto":
        for rule in policy.get("rules", []):
            s, t = rule.get("src", ""), rule.get("tgt", "")
            if s and t:
                idx[f"{s}>{t}"] = rule
    return idx


def _apply_pin(verb: str, src_type: str, tgt_type: str, pol_index: dict) -> str:
    """A pinned, enabled rule for this type-pair overrides the inferred verb."""
    rule = pol_index.get(f"{src_type}>{tgt_type}")
    if rule and rule.get("enabled", True) and rule.get("mode") == "pin":
        pinned = rule.get("verb", verb)
        if pinned in VALID_REL_TYPES:
            return pinned
    return verb


# ── Step 1 — alias merge ──────────────────────────────────────────────────────
def _merge_aliases(stix_objects: list, cfg: dict, stats: CompletionStats) -> None:
    """Collapse same-type SDOs that denote the same object onto one canonical
    node, rewiring every relationship endpoint and dropping the duplicates.

    Grouping key: normalised name, plus any value in the object's ``aliases``
    list.  With ``fuzzy_alias`` on, remaining singletons are additionally matched
    by rapidfuzz ratio >= threshold within the same type.  IOC-shaped names are
    never merged.
    """
    # Build alias groups per type via union-find over normalised names/aliases.
    sdos = [o for o in stix_objects if _otype(o) in _ALIASABLE_TYPES]
    if len(sdos) < 2:
        return

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[find(a)] = find(b)

    # name/alias token -> list of (obj_id, type) that expose it
    token_owners: dict[tuple[str, str], list[str]] = {}
    for o in sdos:
        find(o.id)
        names = [o.get("name", "")] + list(o.get("aliases", []) or [])
        for nm in names:
            if not nm or _IOC_GUARD.search(nm):
                continue
            key = (_otype(o), _norm_name(nm))
            if not key[1]:
                continue
            token_owners.setdefault(key, []).append(o.id)

    for owners in token_owners.values():
        for other in owners[1:]:
            union(owners[0], other)

    # Optional fuzzy pass: match still-separate SDOs of the same type by name.
    if cfg.get("fuzzy_alias"):
        try:
            from rapidfuzz import fuzz

            by_type: dict[str, list] = {}
            for o in sdos:
                by_type.setdefault(_otype(o), []).append(o)
            for group in by_type.values():
                for i in range(len(group)):
                    ni = group[i].get("name", "")
                    if not ni or _IOC_GUARD.search(ni):
                        continue
                    for j in range(i + 1, len(group)):
                        nj = group[j].get("name", "")
                        if not nj or _IOC_GUARD.search(nj):
                            continue
                        if fuzz.ratio(ni.lower(), nj.lower()) >= _FUZZY_THRESHOLD:
                            union(group[i].id, group[j].id)
        except ImportError:
            stats.notes.append("fuzzy_alias requested but rapidfuzz missing")

    # Optional embedding pass (CTINexus fine-grained merging): match same-type
    # SDOs whose *names* are semantically equivalent even with no character
    # overlap ("the Dukes" ↔ "APT29").  Reuses the Stage 2c sentence-embedding
    # model; silently skipped when the model is unavailable (SKIP_HEAVY_MODELS).
    if cfg.get("semantic_alias"):
        try:
            _semantic_alias_pass(sdos, union, stats)
        except Exception as exc:
            stats.notes.append(f"semantic_alias failed: {exc}")

    # Resolve clusters → canonical node (highest degree, then longest name).
    degree: dict[str, int] = {}
    for o in stix_objects:
        if _is_rel(o):
            degree[o.get("source_ref")] = degree.get(o.get("source_ref"), 0) + 1
            degree[o.get("target_ref")] = degree.get(o.get("target_ref"), 0) + 1

    clusters: dict[str, list] = {}
    for o in sdos:
        clusters.setdefault(find(o.id), []).append(o)

    remap: dict[str, str] = {}   # dup id -> canonical id
    canonical_ids: set[str] = set()
    for members in clusters.values():
        if len(members) < 2:
            continue
        canonical = max(
            members, key=lambda m: (degree.get(m.id, 0), len(m.get("name", "")))
        )
        canonical_ids.add(canonical.id)
        merged_aliases = set(canonical.get("aliases", []) or [])
        for m in members:
            if m.id == canonical.id:
                continue
            remap[m.id] = canonical.id
            merged_aliases.add(m.get("name", ""))
            merged_aliases.update(m.get("aliases", []) or [])
            stats.aliases_merged += 1
        # Record the absorbed names as aliases on the canonical SDO.
        merged_aliases.discard(canonical.get("name", ""))
        if merged_aliases:
            new_can = _clone_with(canonical, aliases=sorted(a for a in merged_aliases if a))
            _replace_obj(stix_objects, canonical.id, new_can)

    if not remap:
        return

    # Drop merged duplicate SDOs and rewrite every relationship endpoint.
    _drop_ids(stix_objects, set(remap))
    _rewrite_refs(stix_objects, remap)


def _semantic_alias_pass(sdos: list, union: Callable[[str, str], None],
                         stats: CompletionStats) -> None:
    """Union same-type SDOs whose name embeddings exceed _SEMANTIC_THRESHOLD.

    Uses the Stage 2c sentence-embedding model (lazy, cached there).  No-ops
    when the model is unavailable — the caller treats this pass as optional.
    """
    from pipeline.stage2c_ttp_semantic import _load_model

    model = _load_model()
    if model is None:
        stats.notes.append("semantic_alias requested but embedding model unavailable")
        return

    import numpy as np

    by_type: dict[str, list] = {}
    for o in sdos:
        nm = o.get("name", "")
        if nm and not _IOC_GUARD.search(nm):
            by_type.setdefault(_otype(o), []).append(o)

    for group in by_type.values():
        if len(group) < 2:
            continue
        names = [o.get("name", "") for o in group]
        emb = np.asarray(model.encode(names))
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        emb = emb / norms
        sims = emb @ emb.T
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                if sims[i, j] >= _SEMANTIC_THRESHOLD:
                    union(group[i].id, group[j].id)


def _replace_obj(stix_objects: list, obj_id: str, new_obj) -> None:
    for i, o in enumerate(stix_objects):
        if getattr(o, "id", None) == obj_id:
            stix_objects[i] = new_obj
            return


def _drop_ids(stix_objects: list, ids: set[str]) -> None:
    stix_objects[:] = [o for o in stix_objects if getattr(o, "id", None) not in ids]


def _rewrite_refs(stix_objects: list, remap: dict[str, str]) -> None:
    """Point every relationship's source/target at the canonical id; drop the
    resulting self-loops and exact duplicates."""
    seen: set[tuple[str, str, str]] = set()
    out: list = []
    for o in stix_objects:
        if not _is_rel(o):
            out.append(o)
            continue
        src = remap.get(o.get("source_ref"), o.get("source_ref"))
        tgt = remap.get(o.get("target_ref"), o.get("target_ref"))
        if src == tgt:
            continue   # self-loop created by the merge
        key = (src, o.get("relationship_type"), tgt)
        if key in seen:
            continue
        seen.add(key)
        if src != o.get("source_ref") or tgt != o.get("target_ref"):
            o = _clone_with(o, source_ref=src, target_ref=tgt)
        out.append(o)
    stix_objects[:] = out


# ── Step 1b — ATT&CK reference grounding ──────────────────────────────────────
# Adds MITRE-curated edges (built by scripts/build_indexes.py from the ATT&CK
# STIX bundles) between report objects that both resolve to ATT&CK IDs.  These
# are expert-maintained facts, not inferences — labelled "reported" with the
# ATT&CK pair recorded in x_inference_rule for provenance.

_ATTACK_REL_PATH = Path(__file__).parent / "data" / "attack_relationships.json"


@functools.lru_cache(maxsize=1)
def _attack_pairs() -> dict[tuple[str, str], str]:
    """(src_attack_id, tgt_attack_id) → verb, or {} when the index is absent."""
    try:
        data = json.loads(_ATTACK_REL_PATH.read_text(encoding="utf-8"))
        return {(s, t): v for s, v, t in data.get("pairs", [])}
    except (OSError, ValueError):
        return {}


@functools.lru_cache(maxsize=1)
def _gazetteer_attack_ids() -> dict[str, str]:
    """lowercase gazetteer name → ATT&CK ID (G/S…), or {} when absent."""
    try:
        from pipeline.stage2b_gazetteer import _load

        return {
            e["name"]: e["mitre_id"]
            for e in _load()
            if e.get("mitre_id") and e.get("name")
        }
    except Exception:
        return {}


def _attack_id_for(obj) -> Optional[str]:
    """Resolve a report SDO to its ATT&CK external ID, or None."""
    otype = _otype(obj)
    # Techniques carry their T-id directly in external_references (Stage 4).
    if otype == "attack-pattern":
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None
    if otype not in ("threat-actor", "intrusion-set", "malware", "tool", "campaign"):
        return None
    gaz = _gazetteer_attack_ids()
    for nm in [obj.get("name", "")] + list(obj.get("aliases", []) or []):
        aid = gaz.get((nm or "").lower().strip())
        if aid:
            return aid
    return None


def _ground_reference(
    stix_objects: list, pol_index: dict, cfg: dict, stats: CompletionStats
) -> None:
    pairs = _attack_pairs()
    if not pairs:
        return

    resolved: list[tuple[object, str]] = []   # (sdo, attack_id)
    for o in stix_objects:
        if _is_rel(o) or not hasattr(o, "id"):
            continue
        aid = _attack_id_for(o)
        if aid:
            resolved.append((o, aid))
    if len(resolved) < 2:
        return

    existing = _existing_edges(stix_objects)
    for a, aid_a in resolved:
        for b, aid_b in resolved:
            if a.id == b.id:
                continue
            verb = pairs.get((aid_a, aid_b))
            if not verb:
                continue
            a_type, b_type = _otype(a), _otype(b)
            verb = _apply_pin(verb, a_type, b_type, pol_index)
            if not rel_is_suggested(a_type, verb, b_type):
                stats.skipped_not_suggested += 1
                continue
            key = (a.id, verb, b.id)
            if key in existing:
                continue
            if stats.total_added >= cfg["max_new_edges"]:
                stats.capped = True
                return
            stix_objects.append(
                _make_inferred_rel(
                    a, verb, b, 0.85,
                    f"attack-reference:{aid_a}>{aid_b}", [],
                    label="reported",
                )
            )
            existing.add(key)
            stats.reference_added += 1


# ── Step 2 — deterministic transitive inference ───────────────────────────────
def _existing_edges(stix_objects: list) -> set[tuple[str, str, str]]:
    return {_rel_triple(o) for o in stix_objects if _is_rel(o)}


def _make_inferred_rel(src, verb, tgt, confidence, rule_label, premises,
                       evidence_text="", label="inferred"):
    kwargs = dict(
        relationship_type=verb,
        source_ref=src.id,
        target_ref=tgt.id,
        confidence=max(0, min(100, int(confidence * 100))),
        allow_custom=True,
        x_evidence_label=label,
        x_inference_rule=rule_label,
        x_inferred_from=list(premises),
    )
    if evidence_text:
        kwargs["x_evidence_text"] = evidence_text[:500]
    return stix2.Relationship(**kwargs)


def _infer_transitive(
    stix_objects: list, pol_index: dict, cfg: dict, stats: CompletionStats
) -> None:
    id_to_obj = {o.id: o for o in stix_objects if hasattr(o, "id") and not _is_rel(o)}
    rels = [o for o in stix_objects if _is_rel(o)]

    # Adjacency: source_id -> list of (verb, target_id, rel_obj)
    out_edges: dict[str, list[tuple[str, str, object]]] = {}
    for r in rels:
        out_edges.setdefault(r.get("source_ref"), []).append(
            (r.get("relationship_type"), r.get("target_ref"), r)
        )

    existing = _existing_edges(stix_objects)
    new_objs: list = []

    for a_id, ab_list in out_edges.items():
        a = id_to_obj.get(a_id)
        if a is None:
            continue
        for v_ab, b_id, r_ab in ab_list:
            for v_bc, c_id, r_bc in out_edges.get(b_id, []):
                if c_id == a_id:
                    continue   # no 2-cycles back to source
                v_ac = _TRANSITIVE_RULES.get((v_ab, v_bc))
                if not v_ac:
                    continue
                c = id_to_obj.get(c_id)
                if c is None:
                    continue
                a_type, c_type = _otype(a), _otype(c)
                v_ac = _apply_pin(v_ac, a_type, c_type, pol_index)
                if not rel_is_suggested(a_type, v_ac, c_type):
                    stats.skipped_not_suggested += 1
                    continue
                key = (a_id, v_ac, c_id)
                if key in existing:
                    continue
                if stats.total_added >= cfg["max_new_edges"]:
                    stats.capped = True
                    stix_objects.extend(new_objs)
                    return
                conf = min(
                    r_ab.get("confidence", 50), r_bc.get("confidence", 50)
                ) / 100.0 * 0.9
                new_objs.append(
                    _make_inferred_rel(
                        a, v_ac, c, conf,
                        f"transitive:{v_ab}+{v_bc}",
                        [r_ab.id, r_bc.id],
                    )
                )
                existing.add(key)
                stats.transitive_added += 1

    stix_objects.extend(new_objs)


# ── Step 3 — long-distance relation prediction (opt-in, injected LLM) ──────────
def _connected_components(node_ids: set[str], rels: list) -> list[set[str]]:
    parent = {n: n for n in node_ids}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in rels:
        s, t = r.get("source_ref"), r.get("target_ref")
        if s in parent and t in parent:
            parent[find(s)] = find(t)
    comps: dict[str, set[str]] = {}
    for n in node_ids:
        comps.setdefault(find(n), set()).add(n)
    return list(comps.values())


def _degree_map(rels: list) -> dict[str, int]:
    deg: dict[str, int] = {}
    for r in rels:
        deg[r.get("source_ref")] = deg.get(r.get("source_ref"), 0) + 1
        deg[r.get("target_ref")] = deg.get(r.get("target_ref"), 0) + 1
    return deg


def _infer_long_distance(
    stix_objects: list,
    report_text: str,
    infer: Callable[[object, object, str], Optional[InferredEdge]],
    pol_index: dict,
    cfg: dict,
    stats: CompletionStats,
) -> None:
    """CTINexus Phase 3: pick a central node per disconnected sub-graph and ask
    ``infer`` for the relation to the report's topic node."""
    id_to_obj = {
        o.id: o for o in stix_objects if hasattr(o, "id") and not _is_rel(o)
    }
    rels = [o for o in stix_objects if _is_rel(o)]
    deg = _degree_map(rels)
    comps = _connected_components(set(id_to_obj), rels)
    if len(comps) < 2:
        return

    def central(comp: set[str]) -> str:
        return max(comp, key=lambda n: (deg.get(n, 0), n))

    centrals = [central(c) for c in comps]
    topic = max(centrals, key=lambda n: (deg.get(n, 0), n))
    existing = _existing_edges(stix_objects)

    for cnode in centrals:
        if cnode == topic:
            continue
        if stats.total_added >= cfg["max_new_edges"]:
            stats.capped = True
            return
        src_obj, tgt_obj = id_to_obj[cnode], id_to_obj[topic]
        try:
            edge = infer(src_obj, tgt_obj, report_text)
        except Exception as exc:  # an inferer error must not break mapping
            stats.notes.append(f"long_distance inferer error: {exc}")
            continue
        if not edge or edge.verb not in VALID_REL_TYPES:
            continue
        s = id_to_obj.get(edge.source_id)
        t = id_to_obj.get(edge.target_id)
        if s is None or t is None or s.id == t.id:
            continue
        verb = _apply_pin(edge.verb, _otype(s), _otype(t), pol_index)
        if not rel_is_suggested(_otype(s), verb, _otype(t)):
            stats.skipped_not_suggested += 1
            continue
        key = (s.id, verb, t.id)
        if key in existing:
            continue
        stix_objects.append(
            _make_inferred_rel(
                s, verb, t, edge.confidence, "long-distance", [],
                evidence_text=edge.evidence_text,
            )
        )
        existing.add(key)
        stats.long_distance_added += 1


# ── orchestrator ──────────────────────────────────────────────────────────────
def complete_graph(
    stix_objects: list,
    *,
    policy: Optional[dict] = None,
    report_text: str = "",
    long_distance_infer: Optional[
        Callable[[object, object, str], Optional[InferredEdge]]
    ] = None,
) -> CompletionStats:
    """Enrich ``stix_objects`` in place with alias merges + inferred edges.

    Runs before the Report SDO is built so new edges are wrapped in object_refs
    and provenance-stamped like any other object.  Returns a CompletionStats.
    """
    stats = CompletionStats()
    cfg = _completion_cfg(policy)
    pol_index = _pol_index(policy)

    if cfg["alias"]:
        try:
            _merge_aliases(stix_objects, cfg, stats)
        except Exception as exc:   # completion must never break the bundle
            stats.notes.append(f"alias merge failed: {exc}")

    # Reference grounding runs BEFORE transitive inference so curated edges can
    # also serve as premises for compositions.
    if cfg["reference"]:
        try:
            _ground_reference(stix_objects, pol_index, cfg, stats)
        except Exception as exc:
            stats.notes.append(f"reference grounding failed: {exc}")

    if cfg["transitive"]:
        try:
            _infer_transitive(stix_objects, pol_index, cfg, stats)
        except Exception as exc:
            stats.notes.append(f"transitive inference failed: {exc}")

    if cfg["long_distance"] and long_distance_infer is not None:
        try:
            _infer_long_distance(
                stix_objects, report_text, long_distance_infer,
                pol_index, cfg, stats,
            )
        except Exception as exc:
            stats.notes.append(f"long-distance inference failed: {exc}")

    logger.info(
        "[Stage 4b] graph completion: merged=%d, reference=+%d, transitive=+%d, "
        "long_distance=+%d, skipped_not_suggested=%d%s",
        stats.aliases_merged, stats.reference_added, stats.transitive_added,
        stats.long_distance_added, stats.skipped_not_suggested,
        " (capped)" if stats.capped else "",
    )
    return stats
