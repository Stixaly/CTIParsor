"""The in-house set: our own reports, annotated for what AnnoCTR lacks.

AnnoCTR scores reading a clean text.  This set scores the application on the
ORIGINAL file (PDF, DOCX, HTML), so ingestion losses count: IoCs in tables,
scanned pages, figures.  It also carries what AnnoCTR does not annotate — IoCs
and relationships — and negative cases: behaviours a report denies, defensive
recommendations, generic examples (docs/eval/annotation-guide.md).

Layout, one folder per report under data/eval/inhouse/:

    <doc_id>/source.pdf     the file as received (any supported extension)
    <doc_id>/gold.json      the annotation (format below)

gold.json:
    {"doc_id", "source_file", "annotator", "annotated_at", "guide_version",
     "status": "gold" | "pre-annotation",
     "layers": ["iocs", "entities", "techniques", "relations"],   # annotated exhaustively
     "iocs":       [{"type": "sha256", "value": "..."}],
     "observables": [{"type": "file", "value": "rundll32.exe", "quote": "...",
                      "why": "legitimate" | "no-ioc-type"}],
     "entities":   [{"type": "malware", "value": "SUNBURST", "aliases": ["Solorigate"]}],
     "techniques": [{"id": "T1566.001", "kind": "explicit" | "implicit", "quote": "..."}],
     "relations":  [{"source": "APT29", "type": "uses", "target": "SUNBURST", "quote": "..."}],
     "negatives":  [{"kind": "technique" | "relation", "id": "T1547", "triple": [s, t, o],
                     "quote": "...", "why": "negated" | "recommendation" | "generic"}]}

`observables` (optional, annotated with the `iocs` layer): what the report
names as an indicator but is not one (ADR-0095).  `legitimate`: a file or
registry key every system of its kind has (`rundll32.exe`, `.bash_history`,
a Run key); `no-ioc-type`: a value no IoC type fits (a
Telegram handle, a GUID, a device name), whatever free `type` it is given.  The
pipeline may extract one: it is neither a hit nor a false positive of the
`iocs` layer.  The bundle must not give it an Indicator: `observables` in the
score counts those it does (`as_indicator`; None for a run recorded without
`bundle_indicated`).

A layer missing from `layers` is not scored: an absent annotation is not an
absent fact.  A `pre-annotation` file is never scored — it is a draft built
from the pipeline's own output, and only a person turns it into gold.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from evaluation import metrics

ROOT = Path(__file__).resolve().parent.parent / "data" / "eval" / "inhouse"
LAYERS = ("iocs", "entities", "techniques", "relations")
IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "cve",
             "file", "registry_key", "mutex", "mac_addr", "asn"}
# The types the `entities` layer annotates (docs/eval/annotation-guide.md section 3).
ENTITY_LAYER_TYPES = {"malware", "tool", "threat_actor", "campaign"}


@dataclass
class InhouseDoc:
    doc_id: str
    source: Path
    gold: dict
    layers: frozenset[str] = field(default_factory=frozenset)


def load(root: Path = ROOT, include_drafts: bool = False) -> list[InhouseDoc]:
    docs = []
    for folder in sorted(p for p in root.glob("*") if p.is_dir()):
        gold_file = folder / "gold.json"
        sources = [p for p in folder.glob("source.*")]
        if not gold_file.exists() or not sources:
            continue
        gold = json.loads(gold_file.read_text(encoding="utf-8"))
        if gold.get("status") != "gold" and not include_drafts:
            continue
        docs.append(InhouseDoc(folder.name, sources[0], gold,
                               frozenset(gold.get("layers", [])) & frozenset(LAYERS)))
    return docs


def _ioc_norm(t: str, v: str) -> tuple[str, str]:
    from pipeline.stage2_extraction import refang
    v = refang(v.strip())
    if t == "cve":
        v = v.upper()
    elif t in ("md5", "sha1", "sha256", "domain", "email", "ipv6", "mac_addr"):
        v = v.lower()
    return t, v


def _obs_key(t: str, v: str) -> str:
    """An observable's value as both the gold and the bundle may spell it: a
    registry key without its hive, anything else as written, case ignored."""
    from pipeline.benign import registry_path
    v = v.strip()
    return registry_path(v) if t in ("registry_key", "windows-registry-key") else v.lower()


def _score_observables(g: dict, pred: dict) -> dict:
    gold_o = g.get("observables", [])
    indicated = pred.get("bundle_indicated")
    shipped = (None if indicated is None
               else {_obs_key(i["type"], i["value"]) for i in indicated})
    hits = ([] if shipped is None
            else [o for o in gold_o if _obs_key(o["type"], o["value"]) in shipped])
    return {"cases": len(gold_o), "as_indicator": None if shipped is None else len(hits),
            "items": hits}


def score(doc: InhouseDoc, pred: dict, canonical) -> dict:
    """`pred`: the evaluation runner's record for this document
    (evaluation.__main__._predictions)."""
    g = doc.gold
    out: dict = {"layers": sorted(doc.layers)}
    if "iocs" in doc.layers:
        gold_i = {_ioc_norm(i["type"], i["value"]) for i in g.get("iocs", [])}
        pred_i = {_ioc_norm(e["type"], e["value"]) for e in pred["entities"] if e["type"] in IOC_TYPES}
        # A gold observable the pipeline extracted is neither a hit nor a
        # false positive: extracting it is right, an Indicator on it is not.
        observable = {_obs_key(o["type"], o["value"]) for o in g.get("observables", [])}
        pred_i = {p for p in pred_i if p in gold_i or _obs_key(*p) not in observable}
        out["iocs"] = metrics.set_counts(pred_i, gold_i)
        out["observables"] = _score_observables(g, pred)
    if "entities" in doc.layers:
        gold_e = [(e["type"], e["value"], set(e.get("aliases", [])) | {e["value"]})
                  for e in g.get("entities", [])]
        # The layer is declared exhaustive over the types it annotates:
        # EVERY prediction of those types counts, including types with no gold
        # object (false positives, not to be filtered out by the gold's own
        # types).  Types the layer does not annotate (ipv4, location, ...) are
        # not predictions of this layer.
        pred_e = [(e["type"], e["value"]) for e in pred["entities"]
                  if e["type"] in ENTITY_LAYER_TYPES]
        out["entities"] = metrics.score_entities(pred_e, gold_e)
    if "techniques" in doc.layers:
        kinds: dict[str, set[str]] = {}
        for t in g.get("techniques", []):
            kinds.setdefault(t["id"].upper(), set()).add(t.get("kind", "explicit"))
        out["techniques"] = metrics.score_ttps(set(pred["ttp_ids"]), kinds, canonical)
    if "relations" in doc.layers:
        gold_r = {(r["source"], r["type"], r["target"]) for r in g.get("relations", [])}
        # What the bundle ships when there is one (4b / 4c edges included),
        # else Stage 3's own relationships.
        shipped = pred.get("bundle_relations")
        pred_r = {(r["source"], r["type"], r["target"])
                  for r in (shipped if shipped is not None else pred.get("relations", []))}
        out["relations"] = metrics.score_relations(pred_r, gold_r)

    # Negative cases: a technique or relation the report denies or only
    # recommends against must NOT come out.
    violations = []
    # Same canonical() and triple normalisation as the positive scores.
    pred_parents = {c.split(".", 1)[0] for t in pred["ttp_ids"] if (c := canonical(t)) is not None}
    # Same source as the positive relation score: what the bundle ships when
    # there is one, else Stage 3's own relationships.
    shipped = pred.get("bundle_relations")
    rel_source = shipped if shipped is not None else pred.get("relations", [])
    pred_triples = {metrics.norm_triple((r["source"], r["type"], r["target"])) for r in rel_source}
    for n in g.get("negatives", []):
        if n.get("kind") == "technique":
            c = canonical(n.get("id", "").upper())
            if c is not None and c.split(".", 1)[0] in pred_parents:
                violations.append(n)
        elif n.get("kind") == "relation" and metrics.norm_triple(n.get("triple", [])) in pred_triples:
            violations.append(n)
    out["negatives"] = {"cases": len(g.get("negatives", [])), "violated": len(violations),
                        "violations": violations}
    return out


def score_bundle(doc: InhouseDoc, projection: dict, canonical) -> dict:
    """`score`, from the bundle the release exports (evaluation.bundle.project)
    instead of the runner's record.  Same output shape, plus `unsupported_patterns`
    and `problems`."""
    g = doc.gold
    out: dict = {"layers": sorted(doc.layers)}
    gold_ents = [(e["type"], e["value"], [e["value"], *e.get("aliases", [])]) for e in g.get("entities", [])]
    # Every name a gold entity or IoC goes by -> the one name the relation ends meet on.
    names: dict[str, str] = {}

    def one(v: str) -> str:
        return next(iter(metrics.norm_forms([v])))

    for _, label, forms in gold_ents:
        for f in metrics.norm_forms(forms):
            names.setdefault(f, label)
    for i in g.get("iocs", []):
        names.setdefault(one(i["value"]), i["value"])

    def end(forms: list[str]) -> str:
        for f in forms:
            if (n := names.get(one(f))) is not None:
                return n
        return forms[0]

    def gold_end(v: str) -> str:
        return names.get(one(v), v)

    pred_r = {(end(r["source"]), r["type"], end(r["target"])) for r in projection["relations"]}
    if "iocs" in doc.layers:
        gold_i = {_ioc_norm(i["type"], i["value"]) for i in g.get("iocs", [])}
        pred_i = {_ioc_norm(i["type"], i["value"]) for i in projection["iocs"]}
        observable = {_obs_key(o["type"], o["value"]) for o in g.get("observables", [])}
        pred_i = {p for p in pred_i if p in gold_i or _obs_key(*p) not in observable}
        out["iocs"] = metrics.set_counts(pred_i, gold_i)
        out["observables"] = _score_observables(g, {"bundle_indicated": projection["indicated"]})
    if "entities" in doc.layers:
        pred_e = [(e["type"], metrics.norm_forms(e["forms"])) for e in projection["entities"]]
        gold_e = [(t, metrics.norm_forms(forms)) for t, _, forms in gold_ents]
        scored = metrics.score_entity_forms(pred_e, gold_e)
        # Exhaustive over its types: a type with nothing on either side is a row of zeros.
        out["entities"] = {t: scored.get(t, metrics.Counts()) for t in sorted(ENTITY_LAYER_TYPES)}
    if "techniques" in doc.layers:
        kinds: dict[str, set[str]] = {}
        for t in g.get("techniques", []):
            kinds.setdefault(t["id"].upper(), set()).add(t.get("kind", "explicit"))
        out["techniques"] = metrics.score_ttps(set(projection["techniques"]), kinds, canonical)
    if "relations" in doc.layers:
        gold_r = {(gold_end(r["source"]), r["type"], gold_end(r["target"])) for r in g.get("relations", [])}
        out["relations"] = metrics.score_relations(pred_r, gold_r)

    violations = []
    pred_parents = {c.split(".", 1)[0] for t in projection["techniques"] if (c := canonical(t)) is not None}
    pred_triples = {metrics.norm_triple(t) for t in pred_r}
    for n in g.get("negatives", []):
        if n.get("kind") == "technique":
            c = canonical(n.get("id", "").upper())
            if c is not None and c.split(".", 1)[0] in pred_parents:
                violations.append(n)
        elif n.get("kind") == "relation" and len(n.get("triple", [])) == 3:
            s, r, o = n["triple"]
            if metrics.norm_triple((gold_end(s), r, gold_end(o))) in pred_triples:
                violations.append(n)
    out["negatives"] = {"cases": len(g.get("negatives", [])), "violated": len(violations),
                        "violations": violations}
    out["unsupported_patterns"] = len(projection["unsupported_patterns"])
    out["problems"] = list(projection["problems"])
    return out


def draft_from_run(doc_id: str, source_file: str, pred: dict) -> dict:
    """A pre-annotation from the pipeline's own output — to be corrected, not scored."""
    return {
        "doc_id": doc_id, "source_file": source_file, "annotator": "", "annotated_at": "",
        "guide_version": "1", "status": "pre-annotation",
        "layers": [],
        "iocs": [{"type": e["type"], "value": e["value"]} for e in pred["entities"]
                 if e["type"] in IOC_TYPES],
        "entities": [{"type": e["type"], "value": e["value"], "aliases": []} for e in pred["entities"]
                     if e["type"] in ("malware", "threat_actor", "tool", "campaign")],
        "techniques": [{"id": t["mitre_id"], "kind": "", "quote": t.get("evidence_text") or ""}
                       for t in pred["ttps"]],
        "relations": [{"source": r["source"], "type": r["type"], "target": r["target"],
                       "quote": r.get("evidence_text") or ""} for r in pred.get("relations", [])],
        "negatives": [],
    }


def agreement(a: dict, b: dict) -> dict:
    """Two independent annotations of one report, layer by layer: F1 of `b`
    scored against `a` (symmetric for F1).  Only layers both annotated."""
    layers = set(a.get("layers", [])) & set(b.get("layers", [])) & set(LAYERS)
    out: dict[str, dict] = {}
    if "iocs" in layers:
        norm = lambda g: {_ioc_norm(i["type"], i["value"]) for i in g.get("iocs", [])}  # noqa: E731
        out["iocs"] = metrics.set_counts(norm(b), norm(a)).as_dict()
    if "entities" in layers:
        # Both sides with their aliases, so the match is symmetric (#482).
        forms = lambda g: [(e["type"], metrics.norm_forms([e["value"], *e.get("aliases", [])]))  # noqa: E731
                           for e in g.get("entities", [])]
        out["entities"] = metrics.micro(metrics.score_entity_forms(forms(b), forms(a)).values()).as_dict()
    if "techniques" in layers:
        ids = lambda g: {t["id"].upper().split(".", 1)[0] for t in g.get("techniques", [])}  # noqa: E731
        out["techniques"] = metrics.set_counts(ids(b), ids(a)).as_dict()
    if "relations" in layers:
        rel = lambda g: {(r["source"], r["type"], r["target"]) for r in g.get("relations", [])}  # noqa: E731
        out["relations"] = metrics.score_relations(rel(b), rel(a))["strict"].as_dict()
    return out
