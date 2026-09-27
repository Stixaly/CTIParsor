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
     "entities":   [{"type": "malware", "value": "SUNBURST", "aliases": ["Solorigate"]}],
     "techniques": [{"id": "T1566.001", "kind": "explicit" | "implicit", "quote": "..."}],
     "relations":  [{"source": "APT29", "type": "uses", "target": "SUNBURST", "quote": "..."}],
     "negatives":  [{"kind": "technique" | "relation", "id": "T1547", "triple": [s, t, o],
                     "quote": "...", "why": "negated" | "recommendation" | "generic"}]}

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
    return t, v.lower() if t in ("md5", "sha1", "sha256", "domain", "email") else v


def score(doc: InhouseDoc, pred: dict, canonical) -> dict:
    """`pred`: the evaluation runner's record for this document
    (evaluation.__main__._predictions)."""
    g = doc.gold
    out: dict = {"layers": sorted(doc.layers)}
    if "iocs" in doc.layers:
        gold_i = {_ioc_norm(i["type"], i["value"]) for i in g.get("iocs", [])}
        pred_i = {_ioc_norm(e["type"], e["value"]) for e in pred["entities"] if e["type"] in IOC_TYPES}
        out["iocs"] = metrics.set_counts(pred_i, gold_i)
    if "entities" in doc.layers:
        gold_e = [(e["type"], e["value"], set(e.get("aliases", [])) | {e["value"]})
                  for e in g.get("entities", [])]
        types = {e[0] for e in gold_e}
        pred_e = [(e["type"], e["value"]) for e in pred["entities"] if e["type"] in types]
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
    pred_parents = {t.split(".", 1)[0] for t in pred["ttp_ids"]}
    pred_triples = {(a.lower(), b.lower(), c.lower())
                    for a, b, c in ((r["source"], r["type"], r["target"]) for r in pred.get("relations", []))}
    for n in g.get("negatives", []):
        if n.get("kind") == "technique" and n.get("id", "").upper().split(".", 1)[0] in pred_parents:
            violations.append(n)
        elif n.get("kind") == "relation" and tuple(x.lower() for x in n.get("triple", [])) in pred_triples:
            violations.append(n)
    out["negatives"] = {"cases": len(g.get("negatives", [])), "violated": len(violations),
                        "violations": violations}
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
        gold = [(e["type"], e["value"], set(e.get("aliases", [])) | {e["value"]}) for e in a.get("entities", [])]
        pred = [(e["type"], e["value"]) for e in b.get("entities", [])]
        out["entities"] = metrics.micro(metrics.score_entities(pred, gold).values()).as_dict()
    if "techniques" in layers:
        ids = lambda g: {t["id"].upper().split(".", 1)[0] for t in g.get("techniques", [])}  # noqa: E731
        out["techniques"] = metrics.set_counts(ids(b), ids(a)).as_dict()
    if "relations" in layers:
        rel = lambda g: {(r["source"], r["type"], r["target"]) for r in g.get("relations", [])}  # noqa: E731
        out["relations"] = metrics.score_relations(rel(b), rel(a))["strict"].as_dict()
    return out
