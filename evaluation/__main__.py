"""python -m evaluation <command> — the ADR-0060 protocol, step by step.

  prepare         registry of annotated layers, ATT&CK mapping, near-duplicates
  run             run the application's pipeline on a split (resumable)
  score           score a run: TTPs, entities, evidence
  compare         paired bootstrap between two runs on the same documents
  retrieval       Stage 2c candidate recall at several k (no LLM)
  support-sample  CSV of quotes for a person to judge
  preannotate     draft gold.json for an in-house report (to be corrected by hand)
  inhouse-run     run the pipeline on the in-house reports, from their original files
  inhouse-score   score an in-house run: IoCs, entities, techniques, relations, negatives
  hard-docs       list what makes candidate reports hard to ingest (tables, scans, columns)
  agreement       two independent annotations of one report, layer by layer

Outputs go to data/eval/ (git-ignored).  Tune on `dev`; run `test` once per
frozen configuration (see docs/eval/README.md).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation import annoctr, attack, dedup, evidence, inhouse, metrics  # noqa: E402

OUT = _ROOT / "data" / "eval"
_LITERAL_ID = __import__("re").compile(r"\bT\d{4}(?:\.\d{3})?\b")
_TECH_ID = __import__("re").compile(r"^T\d{4}(?:\.\d{3})?$")


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _docs(split: str, limit: int | None = None) -> list[annoctr.AnnoctrDoc]:
    docs = [d for d in annoctr.load(splits=(split,)) if "cyber" in d.layers]
    return docs[:limit] if limit else docs


# ── prepare ──────────────────────────────────────────────────────────────────

def cmd_prepare(args) -> None:
    docs = annoctr.load(include_general_only=True)
    reg = annoctr.registry(docs)
    _write(OUT / "annoctr-registry.json", reg)

    cat = attack.Catalogue()
    gold = {t for d in docs for t in d.technique_ids}
    mapping = cat.mapping(gold)
    _write(OUT / "attack-mapping.json", {"catalogue": cat.summary(),
                                         "rows": [r.as_dict() for r in mapping.values()]})

    groups = {d.doc_id: (d.split, d.text) for d in docs}
    for extra in args.corpus or []:
        for p in sorted(Path(extra).glob("*.txt")):
            groups[f"{Path(extra).name}/{p.stem}"] = (Path(extra).name, p.read_text(encoding="utf-8"))
    dups = dedup.near_duplicates(groups, threshold=args.threshold)
    _write(OUT / "near-duplicates.json", dups)

    by_split: dict[str, int] = {}
    for row in reg:
        by_split[row["split"]] = by_split.get(row["split"], 0) + 1
    statuses: dict[str, int] = {}
    for res in mapping.values():
        statuses[res.status] = statuses.get(res.status, 0) + 1
    print(f"documents: {by_split}")
    print(f"gold technique ids: {len(gold)} — {statuses}; "
          f"not scorable: {sum(1 for res in mapping.values() if not res.in_pipeline)}")
    for res in mapping.values():
        if res.status != attack.ACTIVE:
            print(f"  {res.gold_id:<11} {res.status:<11} -> {res.canonical}")
    cross = [d for d in dups if d["cross"]]
    print(f"near-duplicate pairs (>= {args.threshold}): {len(dups)}, across groups: {len(cross)}")
    for d in cross[:10]:
        print(f"  {d['a']} [{d['group_a']}] ~ {d['b']} [{d['group_b']}] "
              f"jaccard={d['jaccard']} containment={d['containment']}")
    print(f"written to {OUT}")


# ── run ──────────────────────────────────────────────────────────────────────

def _predictions(result) -> dict:
    """What the application would show for this document."""
    from models.schemas import EntityType

    llm = result.llm_result
    ttp_ids = {(e.mitre_id or e.value).upper() for e in result.entities
               if e.entity_type == EntityType.TTP}
    ttps = []
    if llm is not None:
        for t in llm.ttps:
            if t.mitre_id:
                ttp_ids.add(t.mitre_id.upper())
                ttps.append({"mitre_id": t.mitre_id.upper(), "name": t.technique_name,
                             "evidence_text": t.evidence_text,
                             "evidence_label": getattr(t.evidence_label, "value", t.evidence_label)})
    entities = [{"type": e.entity_type.value, "value": e.value, "source": e.source,
                 "confidence": e.confidence, "mitre_id": e.mitre_id} for e in result.entities]
    if llm is not None:
        for etype, names in (("malware", llm.malware_families), ("threat_actor", llm.threat_actors),
                             ("tool", llm.tools), ("location", llm.targeted_countries),
                             ("identity", llm.targeted_sectors)):
            entities += [{"type": etype, "value": n, "source": "llm", "confidence": None,
                          "mitre_id": None} for n in names]
    relations = []
    if llm is not None:
        relations = [{"source": r.source_value, "type": r.relationship_type, "target": r.target_value,
                      "evidence_text": r.evidence_text,
                      "evidence_label": getattr(r.evidence_label, "value", r.evidence_label)}
                     for r in llm.relationships]
    return {"ttp_ids": sorted(i for i in ttp_ids if _TECH_ID.match(i)), "ttps": ttps,
            "entities": entities, "relations": relations,
            "bundle_relations": _bundle_relations(result.bundle)}


def _bundle_relations(bundle) -> list[dict] | None:
    """The relationships the bundle ships, endpoints resolved to names — what
    an analyst receives, 4b / 4c edges included.  None without a bundle."""
    if bundle is None:
        return None
    objs = json.loads(bundle.serialize())["objects"]

    def name(o):
        return o.get("name") or o.get("value") or o.get("pattern") or o.get("id")

    by_id = {o["id"]: name(o) for o in objs}
    return [{"source": by_id.get(o["source_ref"], o["source_ref"]), "type": o["relationship_type"],
             "target": by_id.get(o["target_ref"], o["target_ref"]),
             "evidence_label": o.get("x_evidence_label"), "policy_rule": o.get("x_policy_rule")}
            for o in objs if o.get("type") == "relationship"]


def cmd_run(args) -> None:
    from api.run_config import build_manifest
    from pipeline.orchestrator import Document, RunOptions, StageRequired, run_document

    disabled = {"1f", "4", "5"} | {s.strip() for s in (args.disable or "").split(",") if s.strip()}
    options = RunOptions.from_env(disabled=disabled,
                                  required=set() if args.allow_degraded else {"3"})
    run_dir = OUT / "runs" / args.name
    docs = _docs(args.split, args.limit)
    meta_path = run_dir / "run.json"
    if not meta_path.exists():
        _write(meta_path, {"name": args.name, "split": args.split, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
                           "disabled": sorted(options.disabled), "required": sorted(options.required),
                           "consensus": options.consensus, "document_relations": options.document_relations,
                           "manifest": build_manifest()})
    consecutive_required = 0
    for i, d in enumerate(docs, 1):
        out = run_dir / "docs" / f"{d.doc_id}.json"
        if out.exists():
            continue
        t0 = time.monotonic()
        try:
            result = run_document(Document(text=d.text, original_filename=f"{d.doc_id}.txt"), options)
            record = {"doc_id": d.doc_id, "seconds": round(time.monotonic() - t0, 1),
                      "stages": result.stage_report(), **_predictions(result)}
            consecutive_required = 0
        except StageRequired as exc:
            # One report whose LLM answers were all unusable is recorded and
            # left out of the score; two in a row is the setup (a model name
            # the server does not serve, a server down): stop.
            record = {"doc_id": d.doc_id, "seconds": round(time.monotonic() - t0, 1),
                      "error": f"StageRequired: {exc}"}
            consecutive_required += 1
            if consecutive_required >= 2:
                _write(out, record)
                print(f"stopped: {exc}", file=sys.stderr)
                sys.exit(2)
        except Exception as exc:   # one bad document must not lose the run
            record = {"doc_id": d.doc_id, "seconds": round(time.monotonic() - t0, 1),
                      "error": f"{type(exc).__name__}: {exc}"}
        _write(out, record)
        print(f"[{i}/{len(docs)}] {d.doc_id} {record['seconds']}s "
              f"{'ERROR ' + record['error'] if 'error' in record else str(len(record['ttp_ids'])) + ' techniques'}",
              flush=True)


# ── score ────────────────────────────────────────────────────────────────────

def _load_run(name: str) -> tuple[dict, dict[str, dict]]:
    run_dir = OUT / "runs" / name
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    preds = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (run_dir / "docs").glob("*.json")}
    return meta, preds


def _canonical_fn():
    cat = attack.Catalogue()
    cache: dict[str, str | None] = {}

    def canonical(tid: str) -> str | None:
        if tid not in cache:
            r = cat.resolve(tid)
            cache[tid] = r.canonical if r.in_pipeline else None
        return cache[tid]
    return canonical, cat


def per_doc_scores(name: str) -> dict:
    meta, preds = _load_run(name)
    canonical, cat = _canonical_fn()
    docs = {d.doc_id: d for d in _docs(meta["split"])}
    rows = {}
    for doc_id, p in sorted(preds.items()):
        d = docs.get(doc_id)
        if d is None or "error" in p:
            continue
        ttp = metrics.score_ttps(set(p["ttp_ids"]), d.technique_kinds(), canonical)
        # Sensitivity check: AnnoCTR leaves most ids of a vendor's own ATT&CK
        # table unannotated (15 of 23 on dev), so an id the report writes out
        # counts as a false positive.  Same score with those ids added to gold.
        literal = {m.upper(): {"explicit"} for m in _LITERAL_ID.findall(d.text)}
        ttp_literal = metrics.score_ttps(set(p["ttp_ids"]), {**literal, **d.technique_kinds()}, canonical)
        gold_ents = [(e.etype, e.label, e.surfaces) for e in d.entities.values()]
        types = set(d.evaluable()["entity_types"])
        pred_ents = [(e["type"], e["value"]) for e in p["entities"] if e["type"] in types]
        rows[doc_id] = {
            "ttp": ttp,
            "ttp_with_literal_ids": ttp_literal,
            "entities_strict": metrics.score_entities(pred_ents, gold_ents),
            "entities_lenient": metrics.score_entities(pred_ents, gold_ents, lenient=True),
        }
    return {"meta": meta, "rows": rows, "preds": preds, "docs": docs, "canonical": canonical,
            "catalogue": cat}


def cmd_score(args) -> None:
    s = per_doc_scores(args.name)
    rows, preds, docs, canonical = s["rows"], s["preds"], s["docs"], s["canonical"]
    tech = [r["ttp"].technique for r in rows.values()]
    sub = [r["ttp"].subtechnique for r in rows.values()]
    exp = [r["ttp"].explicit_recall for r in rows.values()]
    imp = [r["ttp"].implicit_recall for r in rows.values()]

    ent_types = sorted({t for r in rows.values() for t in r["entities_strict"]})
    ents = {t: {"strict": metrics.micro(r["entities_strict"].get(t, metrics.Counts())
                                        for r in rows.values()).as_dict(),
                "lenient": metrics.micro(r["entities_lenient"].get(t, metrics.Counts())
                                         for r in rows.values()).as_dict()}
            for t in ent_types}

    ev_rows = []
    for doc_id in rows:
        d = docs[doc_id]
        spans: dict[str, list[tuple[int, int]]] = {}
        for m in d.techniques:
            c = canonical(m.label)
            if c and m.start is not None and m.end is not None:
                spans.setdefault(c.split(".", 1)[0], []).append((m.start, m.end))
        ev_rows += evidence.check(doc_id, d.text, preds[doc_id]["ttps"], spans, canonical)

    stages: dict[str, dict[str, int]] = {}
    llm_health: dict[str, int] = {}
    for p in preds.values():
        for o in p.get("stages", []):
            stages.setdefault(o["stage"], {}).setdefault(o["status"], 0)
            stages[o["stage"]][o["status"]] += 1
            if o["stage"] in ("3", "3d", "3f"):
                for k, v in o.get("counts", {}).items():
                    if k.startswith(("extraction_", "provider_", "ok", "unparsed", "failed")):
                        key = k if o["stage"] == "3" else f"{o['stage']}_{k}"
                        llm_health[key] = llm_health.get(key, 0) + v

    def ratio(pairs):
        found, gold = sum(a for a, _ in pairs), sum(b for _, b in pairs)
        return {"found": found, "gold": gold, "recall": round(found / gold, 4) if gold else None}

    report = {
        "run": args.name, "split": s["meta"]["split"], "documents_scored": len(rows),
        "documents_failed": sorted(k for k, p in preds.items() if "error" in p),
        "config": {k: s["meta"][k] for k in ("disabled", "consensus", "document_relations")},
        "llm": s["meta"]["manifest"].get("llm"),
        "ttp": {
            "technique_micro": metrics.micro(tech).as_dict(),
            "technique_per_document": metrics.macro(tech),
            "subtechnique_micro": metrics.micro(sub).as_dict(),
            "explicit_recall": ratio(exp), "implicit_only_recall": ratio(imp),
            "gold_dropped_by_mapping": sorted({g for r in rows.values() for g in r["ttp"].dropped_gold}),
            "technique_micro_gold_plus_literal_ids": metrics.micro(
                r["ttp_with_literal_ids"].technique for r in rows.values()).as_dict(),
        },
        "entities": ents,
        "evidence": evidence.summarise(ev_rows),
        "stages": stages,
        "llm_health": llm_health,
        "seconds_per_document": round(sum(p.get("seconds", 0) for p in preds.values()) / max(1, len(preds)), 1),
    }
    _write(OUT / "runs" / args.name / "score.json", report)
    t = report["ttp"]
    print(f"{args.name} [{report['split']}] {len(rows)} documents "
          f"({len(report['documents_failed'])} failed), {report['seconds_per_document']} s/doc")
    print(f"  TTP technique  micro P/R/F1 {t['technique_micro']['precision']:.3f} "
          f"{t['technique_micro']['recall']:.3f} {t['technique_micro']['f1']:.3f}   "
          f"per-document F1 {t['technique_per_document']['f1']:.3f}")
    print(f"  TTP recall     explicit {t['explicit_recall']['recall']}  implicit-only "
          f"{t['implicit_only_recall']['recall']}")
    lit = t["technique_micro_gold_plus_literal_ids"]
    print(f"  TTP technique  gold + ids written in the report: P/R/F1 {lit['precision']:.3f} "
          f"{lit['recall']:.3f} {lit['f1']:.3f}  (sensitivity check, not the primary score)")
    for et, v in ents.items():
        print(f"  {et:<13} strict P/R/F1 {v['strict']['precision']:.3f} {v['strict']['recall']:.3f} "
              f"{v['strict']['f1']:.3f}   lenient F1 {v['lenient']['f1']:.3f}")
    print(f"  evidence       {report['evidence']}")
    skipped = {k: v for k, v in stages.items() if set(v) - {"ran"}}
    if skipped:
        print(f"  stages not run: {skipped}")
    print(f"  LLM health     {llm_health}")


# ── compare ──────────────────────────────────────────────────────────────────

def cmd_compare(args) -> None:
    a, b = per_doc_scores(args.a), per_doc_scores(args.b)
    common = sorted(set(a["rows"]) & set(b["rows"]))
    if not common:
        sys.exit("no document scored in both runs")

    def series(s, doc_ids):
        if args.task == "ttp":
            return [s["rows"][d]["ttp"].technique for d in doc_ids]
        return [s["rows"][d]["entities_strict"].get(args.task, metrics.Counts()) for d in doc_ids]

    out = {"a": args.a, "b": args.b, "task": args.task, "documents": len(common), "results": {}}
    for m in ("f1", "precision", "recall"):
        out["results"][m] = metrics.paired_bootstrap(series(a, common), series(b, common), metric=m,
                                                     n=args.resamples)
    _write(OUT / "compare" / f"{args.a}__vs__{args.b}__{args.task}.json", out)
    print(f"{args.b} − {args.a} on {len(common)} documents ({args.task}):")
    for m, r in out["results"].items():
        print(f"  {m:<9} {r['observed_diff']:+.4f}  95% CI [{r['ci95'][0]:+.4f}, {r['ci95'][1]:+.4f}]  "
              f"P(not better) {r['p_not_better']}")


# ── retrieval ────────────────────────────────────────────────────────────────

def cmd_retrieval(args) -> None:
    from pipeline.stage2c_ttp_semantic import semantic_available, semantic_topk_ids

    if not semantic_available():
        sys.exit("Stage 2c is unavailable (SKIP_HEAVY_MODELS, embeddings or model missing)")
    canonical, _ = _canonical_fn()
    ks = sorted({int(k) for k in args.k.split(",")})
    docs = _docs(args.split, args.limit)
    table = []
    for k in ks:
        found = gold_n = cands = 0
        for d in docs:
            gold = {c.split(".", 1)[0] for g in d.technique_ids if (c := canonical(g))}
            got = {c.split(".", 1)[0] for t in semantic_topk_ids(d.text, k) if (c := canonical(t))}
            found += len(gold & got)
            gold_n += len(gold)
            cands += len(got)
        table.append({"k": k, "recall": round(found / gold_n, 4) if gold_n else None,
                      "mean_candidate_techniques": round(cands / len(docs), 1)})
        print(f"  k={k:<3} technique recall {table[-1]['recall']}  "
              f"mean candidates/doc {table[-1]['mean_candidate_techniques']}", flush=True)
    _write(OUT / f"retrieval-{args.split}.json", {"split": args.split, "documents": len(docs),
                                                  "unit": "top-k per candidate sentence, union per document",
                                                  "table": table})


# ── support-sample ───────────────────────────────────────────────────────────

def cmd_support_sample(args) -> None:
    s = per_doc_scores(args.name)
    rows = []
    for doc_id in s["rows"]:
        d = s["docs"][doc_id]
        spans: dict[str, list[tuple[int, int]]] = {}
        for m in d.techniques:
            c = s["canonical"](m.label)
            if c and m.start is not None and m.end is not None:
                spans.setdefault(c.split(".", 1)[0], []).append((m.start, m.end))
        rows += evidence.check(doc_id, d.text, s["preds"][doc_id]["ttps"], spans, s["canonical"])
    path = OUT / "runs" / args.name / "support-sample.csv"
    n = evidence.support_sample(rows, {k: v.text for k, v in s["docs"].items()}, path, n=args.n)
    print(f"{n} quotes to judge -> {path}")


# ── in-house set ─────────────────────────────────────────────────────────────

def _run_file(path: Path, disabled: set[str]):
    from pipeline.orchestrator import Document, RunOptions, run_document

    # Stage 4 stays on: relationships are scored as the bundle ships them,
    # graph completion (4b) and long-distance inference (4c) included.
    options = RunOptions.from_env(disabled={"5"} | disabled, required={"3"})
    return run_document(Document(file_path=str(path), original_filename=path.name), options)


def cmd_preannotate(args) -> None:
    import shutil

    src = Path(args.file)
    folder = inhouse.ROOT / args.doc_id
    gold = folder / "gold.json"
    if gold.exists():
        sys.exit(f"{gold} exists — not overwriting an annotation")
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"source{src.suffix.lower()}"
    shutil.copyfile(src, target)
    result = _run_file(target, set())
    _write(gold, inhouse.draft_from_run(args.doc_id, target.name, _predictions(result)))
    print(f"draft (status: pre-annotation) -> {gold}\n"
          "Correct it with docs/eval/annotation-guide.md, fill `layers`, then set status to gold.")


def cmd_inhouse_run(args) -> None:
    from api.run_config import build_manifest

    disabled = {s.strip() for s in (args.disable or "").split(",") if s.strip()}
    run_dir = OUT / "inhouse-runs" / args.name
    if not (run_dir / "run.json").exists():
        _write(run_dir / "run.json", {"name": args.name, "disabled": sorted(disabled),
                                      "manifest": build_manifest()})
    for d in inhouse.load():
        out = run_dir / "docs" / f"{d.doc_id}.json"
        if out.exists():
            continue
        t0 = time.monotonic()
        try:
            result = _run_file(d.source, disabled)
            record = {"doc_id": d.doc_id, "seconds": round(time.monotonic() - t0, 1),
                      "stages": result.stage_report(), **_predictions(result)}
        except Exception as exc:
            record = {"doc_id": d.doc_id, "error": f"{type(exc).__name__}: {exc}"}
        _write(out, record)
        print(f"{d.doc_id}: {'ERROR' if 'error' in record else 'ok'}", flush=True)


def cmd_inhouse_score(args) -> None:
    canonical, _ = _canonical_fn()
    run_dir = OUT / "inhouse-runs" / args.name
    docs = {d.doc_id: d for d in inhouse.load()}
    totals: dict[str, metrics.Counts] = {}
    negatives = [0, 0]
    per_doc = {}
    for p in sorted((run_dir / "docs").glob("*.json")):
        pred = json.loads(p.read_text(encoding="utf-8"))
        d = docs.get(p.stem)
        if d is None or "error" in pred:
            continue
        s = inhouse.score(d, pred, canonical)
        per_doc[d.doc_id] = s
        for layer in ("iocs",):
            if layer in s:
                totals[layer] = totals.get(layer, metrics.Counts()) + s[layer]
        if "techniques" in s:
            totals["techniques"] = totals.get("techniques", metrics.Counts()) + s["techniques"].technique
        if "relations" in s:
            totals["relations"] = totals.get("relations", metrics.Counts()) + s["relations"]["strict"]
        for et, c in s.get("entities", {}).items():
            totals[f"entity:{et}"] = totals.get(f"entity:{et}", metrics.Counts()) + c
        negatives[0] += s["negatives"]["cases"]
        negatives[1] += s["negatives"]["violated"]
    report = {"run": args.name, "documents": len(per_doc),
              "micro": {k: v.as_dict() for k, v in sorted(totals.items())},
              "negatives": {"cases": negatives[0], "violated": negatives[1]}}
    _write(run_dir / "score.json", report)
    print(json.dumps(report, indent=2))


def cmd_hard_docs(args) -> None:
    """Features that make a report hard to ingest, per file: pages scanned,
    tables, images, a second text column.  To pick the Phase 5 documents."""
    import pdfplumber

    from pipeline.stage1_ingestion import _page_is_scanned

    rows = []
    for folder in args.folders:
        for f in sorted(Path(folder).iterdir()):
            row: dict = {"file": str(f), "type": f.suffix.lower()}
            try:
                if f.suffix.lower() == ".pdf":
                    with pdfplumber.open(f) as pdf:
                        pages = pdf.pages
                        row["pages"] = len(pages)
                        row["scanned_pages"] = sum(1 for pg in pages if _page_is_scanned(pg))
                        row["tables"] = sum(len(pg.find_tables()) for pg in pages)
                        row["images"] = sum(len(pg.images) for pg in pages)
                        row["two_column_pages"] = sum(1 for pg in pages if _two_columns(pg))
                elif f.suffix.lower() == ".docx":
                    import docx
                    d = docx.Document(str(f))
                    row["tables"] = len(d.tables)
                    row["images"] = len(d.inline_shapes)
                else:
                    continue
            except Exception as exc:
                row["error"] = str(exc)
            row["hardness"] = (row.get("scanned_pages", 0) * 3 + row.get("tables", 0) * 2
                               + row.get("two_column_pages", 0) + min(row.get("images", 0), 10))
            rows.append(row)
    rows.sort(key=lambda r: -r["hardness"])
    _write(OUT / "hard-docs.json", rows)
    for r in rows:
        print(f"{r['hardness']:>4}  {r['file']}  " + ", ".join(
            f"{k}={v}" for k, v in r.items() if k not in ("file", "hardness", "type")))


def cmd_agreement(args) -> None:
    a = json.loads(Path(args.a).read_text(encoding="utf-8"))
    b = json.loads(Path(args.b).read_text(encoding="utf-8"))
    result = inhouse.agreement(a, b)
    if not result:
        sys.exit("no layer annotated in both files")
    for layer, c in result.items():
        print(f"  {layer:<11} F1 {c['f1']:.3f}  (both {c['tp']}, only b {c['fp']}, only a {c['fn']})")


def _two_columns(page) -> bool:
    """Most text lines start in two distinct horizontal bands."""
    words = page.extract_words()
    if len(words) < 80:
        return False
    mid = float(page.width) / 2
    left = sum(1 for w in words if float(w["x1"]) < mid - 10)
    right = sum(1 for w in words if float(w["x0"]) > mid + 10)
    return min(left, right) > 0.3 * len(words)


def main() -> None:
    ap = argparse.ArgumentParser(prog="python -m evaluation", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("prepare")
    p.add_argument("--corpus", action="append", help="extra folder of .txt reports to check for copies")
    p.add_argument("--threshold", type=float, default=0.5)
    p.set_defaults(fn=cmd_prepare)

    p = sub.add_parser("run")
    p.add_argument("--split", choices=annoctr.SPLITS, default="dev")
    p.add_argument("--name", required=True, help="run name, e.g. baseline-dev")
    p.add_argument("--disable", help="extra stage ids to turn off, e.g. 2d,2e")
    p.add_argument("--allow-degraded", action="store_true", help="score even if the LLM cannot run")
    p.add_argument("--limit", type=int)
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("score")
    p.add_argument("--name", required=True)
    p.set_defaults(fn=cmd_score)

    p = sub.add_parser("compare")
    p.add_argument("--a", required=True, help="reference run")
    p.add_argument("--b", required=True, help="candidate run")
    p.add_argument("--task", default="ttp", help="ttp, or an entity type (malware, threat_actor, ...)")
    p.add_argument("--resamples", type=int, default=2000)
    p.set_defaults(fn=cmd_compare)

    p = sub.add_parser("retrieval")
    p.add_argument("--split", choices=annoctr.SPLITS, default="dev")
    p.add_argument("--k", default="1,3,5,10,20")
    p.add_argument("--limit", type=int)
    p.set_defaults(fn=cmd_retrieval)

    p = sub.add_parser("support-sample")
    p.add_argument("--name", required=True)
    p.add_argument("--n", type=int, default=50)
    p.set_defaults(fn=cmd_support_sample)

    p = sub.add_parser("preannotate")
    p.add_argument("file")
    p.add_argument("--doc-id", required=True)
    p.set_defaults(fn=cmd_preannotate)

    p = sub.add_parser("inhouse-run")
    p.add_argument("--name", required=True)
    p.add_argument("--disable")
    p.set_defaults(fn=cmd_inhouse_run)

    p = sub.add_parser("inhouse-score")
    p.add_argument("--name", required=True)
    p.set_defaults(fn=cmd_inhouse_score)

    p = sub.add_parser("agreement")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(fn=cmd_agreement)

    p = sub.add_parser("hard-docs")
    p.add_argument("folders", nargs="+")
    p.set_defaults(fn=cmd_hard_docs)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
