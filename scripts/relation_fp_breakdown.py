"""Where the relation false positives of an in-house bundle run come from.

Reads one run folder (the one `inhouse-score --from bundle` reads: `run.json`,
`docs/<doc>.json`, `bundles/<doc>.json`, `score-bundle.json`) and writes a JSON
breakdown of the relation score: every found relation with its attributes and
its match against the gold, and every gold relation not found.

Reuse of the scorer: the gold comes from `evaluation.inhouse.load`; each
document's bundle is read by `evaluation.__main__._bundle_projection` (the checks
`inhouse-score --from bundle` applies); the projection and the relation counts
come from `evaluation.bundle.project` and `evaluation.inhouse.score_bundle`; the
comparison uses `evaluation.metrics.norm_triple`.  The name resolution of
`score_bundle` is a closure there, so it is repeated here (`gold_names`,
`end`, `gold_end_`).  The counts are checked against `score-bundle.json`: when
they differ the script exits 1 and names the difference.  It never adjusts a
figure to agree with the file.

A found relation is one distinct (source, type, target) triple, as the scorer
counts them.  Its attributes come from the first bundle relationship with that
triple, in bundle order; `raw_count` says how many bundle relationships share it.

Attributes: relationship_type, source_type, target_type, pair, evidence_label,
inference_rule (kind before ':'), inference_rule_full, has_evidence_text,
confidence (bucket), why (the producing method, from the description's
"**Why:**" line), stage3 (the pipeline's own row, see below), source_resolved,
target_resolved, gold_link (a false positive: the same pair in the gold under
another type, the reversed pair, or no gold link between the two names).

`stage3`: the bundle relationship's name triple equals a `relations` row of
docs/<doc>.json, or its x_evidence_text equals that row's evidence_text
("stage3 row").  The same for `rel_review` rows ("rel_review row").  The name
triple is the position-aligned `bundle_relations` row of docs/<doc>.json.

Usage:
    python scripts/relation_fp_breakdown.py --run-dir <run folder> [--gold-dir <inhouse folder>] [--out <file>]

Exit status: 0 when the counts equal score-bundle.json; 1 when they differ or
the run cannot be read.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluation import inhouse, metrics  # noqa: E402
from evaluation.__main__ import _bundle_projection  # noqa: E402
from evaluation.inhouse import score_bundle  # noqa: E402

SAMPLE_SEED = 13
SAMPLE_SIZE = 30

WHY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stated in the quoted sentence", re.compile(r"states this link in the sentence quoted above")),
    ("every threat actor x every target", re.compile(r"CTIParsor links every threat actor")),
    ("MITRE ATT&CK reference", re.compile(r"MITRE ATT&CK records this link")),
    ("transitive composition", re.compile(r"Inferred by composing two links")),
    ("indicator association", re.compile(r"associates the indicator value")),
    ("detection rule title", re.compile(r"names .{1,300} in its title")),
)
WHY_LINE = re.compile(r"\*\*Why:\*\* (.*)")


def _no_canonical(_: str) -> None:
    """`score_bundle` asks for a technique resolver; this script reads relations only."""
    return None


def why_text(description: object) -> str:
    text = str(description or "")
    m = WHY_LINE.search(text)
    return m.group(1) if m else ""


def why_class(description: object) -> str:
    line = why_text(description) or str(description or "")
    for name, rx in WHY_RULES:
        if rx.search(line):
            return name
    return "other"


def confidence_bucket(raw: dict) -> str:
    c = raw.get("confidence")
    if not isinstance(c, int | float) or isinstance(c, bool):
        return "none"
    if c < 70:
        return "<70"
    if c < 90:
        return "70-89"
    return "90-100"


def _one(v: str) -> str:
    return next(iter(metrics.norm_forms([v])))


def _pair(a: str, b: str) -> tuple[str, str]:
    """Two names as `metrics.score_relations` compares them (the type left out)."""
    t = metrics.norm_triple((a, "", b))
    return t[0], t[2]


def gold_names(gold: dict) -> dict[str, str]:
    """`inhouse.score_bundle`'s `names`: every normalised name a gold entity or IoC goes by -> its label."""
    names: dict[str, str] = {}
    for e in gold.get("entities", []):
        for f in metrics.norm_forms([e["value"], *e.get("aliases", [])]):
            names.setdefault(f, e["value"])
    for i in gold.get("iocs", []):
        names.setdefault(_one(i["value"]), i["value"])
    return names


def _end(names: dict[str, str], forms: list[str]) -> str:
    """`inhouse.score_bundle`'s `end`: the gold label of the first form that has one, else the first form."""
    for f in forms:
        if (n := names.get(_one(f))) is not None:
            return n
    return forms[0]


def gold_end(names: dict[str, str], v: str) -> str:
    """`inhouse.score_bundle`'s `gold_end`: the gold label of a name, else the name itself."""
    return names.get(_one(v), v)


def gold_end_types(gold: dict) -> dict[str, str]:
    """The gold type of each gold label (entity type, or IoC type)."""
    types = {i["value"]: i["type"] for i in gold.get("iocs", [])}
    types.update({e["value"]: e["type"] for e in gold.get("entities", [])})
    return types


def _rows(rec: dict, key: str) -> list[dict]:
    rows = rec.get(key)
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def _table(rows: list[dict], attr: str, fp_total: int) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        t = out.setdefault(str(r[attr]), {"found": 0, "tp": 0, "fp": 0})
        t["found"] += 1
        t["tp" if r["matched"] else "fp"] += 1
    for t in out.values():
        t["precision"] = round(t["tp"] / t["found"], 4) if t["found"] else 0.0
        t["share_of_fp"] = round(t["fp"] / fp_total, 4) if fp_total else 0.0
    return dict(sorted(out.items(), key=lambda kv: (-kv[1]["fp"], kv[0])))


def analyse(run_dir: Path, gold_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    score = json.loads((run_dir / "score-bundle.json").read_text(encoding="utf-8"))
    run_format = int(meta.get("format", 1))
    golds = {d.doc_id: d for d in inhouse.load(gold_dir)}

    found: list[dict] = []
    fn_rows: list[dict] = []
    per_doc: dict[str, dict[str, int]] = {}
    unscored: dict[str, str] = {}
    duplicates = 0
    raw_total = 0
    problems: list[str] = []

    # One pass per document. A document is skipped when it has no gold, and recorded as
    # unscored when its bundle projection cannot be built. The projection is the bundle's
    # relationships as the scorer sees them, so the breakdown below matches the score file.
    for p in sorted((run_dir / "docs").glob("*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        doc = p.stem
        d = golds.get(doc)
        if d is None:
            continue
        projection, reason = _bundle_projection(run_dir, rec, run_format)
        if projection is None:
            unscored[doc] = reason
            continue
        s = score_bundle(d, projection, _no_canonical)
        if "relations" not in s:
            continue
        g = d.gold
        names = gold_names(g)
        types = gold_end_types(g)

        # The bundle's relationships, in file order. `based-on` links are not counted as
        # relationships. Each bundle_relations row must describe the relationship at the
        # same position, and the projection must list them in the same order.
        bundle_file = (run_dir / str(rec["bundle_file"])).resolve()
        bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
        objs = [o for o in bundle["objects"] if isinstance(o, dict)]
        by_id = {o["id"]: o for o in objs if isinstance(o.get("id"), str)}
        all_rel = [o for o in objs if o.get("type") == "relationship"]
        raw_rels = [o for o in all_rel if o.get("relationship_type") != "based-on"]
        if len(raw_rels) != len(projection["relations"]):
            raise SystemExit(f"{doc}: {len(raw_rels)} relationships in the bundle, "
                             f"{len(projection['relations'])} in the projection")
        br = _rows(rec, "bundle_relations")
        if len(br) != len(all_rel):
            raise SystemExit(f"{doc}: bundle_relations has {len(br)} rows for {len(all_rel)} relationships")
        for o, row in zip(all_rel, br, strict=True):
            if row.get("type") != o.get("relationship_type") or row.get("evidence_label") != o.get("x_evidence_label"):
                raise SystemExit(f"{doc}: bundle_relations row does not match relationship {o.get('id')}")
        position = {id(o): i for i, o in enumerate(all_rel)}

        # The stage 3 rows that hold the same claim, by names and by quote, and the rows that
        # verification held back in rel_review. They tell which stage produced each found row.
        s3_names = {(r.get("source"), r.get("type"), r.get("target")) for r in _rows(rec, "relations")}
        s3_quotes = {r["evidence_text"] for r in _rows(rec, "relations") if r.get("evidence_text")}
        rv_names = {(r.get("source"), r.get("type"), r.get("target")) for r in _rows(rec, "rel_review")}
        rv_quotes = {r["evidence_text"] for r in _rows(rec, "rel_review") if r.get("evidence_text")}

        # Gold relations as normalised triples, and as unordered name pairs (for the
        # "same pair, other type" and "reversed pair" link checks further down).
        gold_norm = {metrics.norm_triple((gold_end(names, r["source"]), r["type"], gold_end(names, r["target"])))
                     for r in g.get("relations", [])}
        gold_pairs = {_pair(gold_end(names, r["source"]), gold_end(names, r["target"]))
                      for r in g.get("relations", [])}

        # Collapse duplicates: `firsts` keeps the first bundle relationship for each triple,
        # and `counts` holds how many relationships share it. Each extra copy is a duplicate.
        firsts: dict[tuple[str, str, str], dict[str, Any]] = {}
        counts: Counter[tuple[str, str, str]] = Counter()
        for raw, pr in zip(raw_rels, projection["relations"], strict=True):
            if pr["type"] != raw.get("relationship_type"):
                raise SystemExit(f"{doc}: projection order differs from the bundle at {raw.get('id')}")
            key = metrics.norm_triple((_end(names, pr["source"]), pr["type"], _end(names, pr["target"])))
            raw_total += 1
            counts[key] += 1
            if key not in firsts:
                firsts[key] = {"raw": raw, "pr": pr, "position": position[id(raw)]}
        duplicates += sum(c - 1 for c in counts.values())

        # Strict TP, FP and FN over the collapsed triples. The breakdown must agree with the
        # scorer's counts, or the run stops: a disagreement would make every table wrong.
        tp_keys = set(firsts) & gold_norm
        fp_keys = set(firsts) - gold_norm
        fn_keys = gold_norm - set(firsts)
        scorer = s["relations"]["strict"]
        if (scorer.tp, scorer.fp, scorer.fn) != (len(tp_keys), len(fp_keys), len(fn_keys)):
            raise SystemExit(f"{doc}: breakdown {(len(tp_keys), len(fp_keys), len(fn_keys))} differs from "
                             f"the scorer {(scorer.tp, scorer.fp, scorer.fn)}")
        per_doc[doc] = {"found": len(firsts), "tp": len(tp_keys), "fp": len(fp_keys),
                        "gold": len(gold_norm), "fn": len(fn_keys)}

        # One row per found triple, with the attributes the tables group by: the stage that
        # wrote it, how its endpoints relate to gold names, and how it links to gold.
        for key, f in firsts.items():
            raw, pr = f["raw"], f["pr"]
            st = str(by_id.get(raw.get("source_ref"), {}).get("type", "unknown"))
            tt = str(by_id.get(raw.get("target_ref"), {}).get("type", "unknown"))
            rule = raw.get("x_inference_rule")
            rule_s = rule if isinstance(rule, str) and rule else "none"
            quote = raw.get("x_evidence_text") if isinstance(raw.get("x_evidence_text"), str) else ""
            row = br[f["position"]]
            name_row = (row.get("source"), row.get("type"), row.get("target"))
            if name_row in s3_names or (quote and quote in s3_quotes):
                stage3 = "stage3 row"
            elif name_row in rv_names or (quote and quote in rv_quotes):
                stage3 = "rel_review row (quote not found)"
            else:
                stage3 = "no stage3 row"
            src_name, tgt_name = _end(names, pr["source"]), _end(names, pr["target"])
            src_is_gold = any(names.get(_one(f)) is not None for f in pr["source"])
            tgt_is_gold = any(names.get(_one(f)) is not None for f in pr["target"])
            matched = key in gold_norm
            if matched:
                gold_link = "exact"
            elif _pair(src_name, tgt_name) in gold_pairs:
                gold_link = "same pair, other type"
            elif _pair(tgt_name, src_name) in gold_pairs:
                gold_link = "reversed pair in gold"
            else:
                gold_link = "no gold link between these names"
            found.append({
                "document": doc,
                "source": src_name,
                "type": raw.get("relationship_type"),
                "target": tgt_name,
                "key": list(key),
                "matched": matched,
                "relationship_type": raw.get("relationship_type"),
                "source_type": st,
                "target_type": tt,
                "pair": f"{st}->{tt}",
                "evidence_label": raw.get("x_evidence_label") or "none",
                "inference_rule": rule_s.split(":", 1)[0],
                "inference_rule_full": rule_s,
                "has_evidence_text": bool(quote),
                "confidence": confidence_bucket(raw),
                "why": why_class(raw.get("description")),
                "why_line": why_text(raw.get("description"))[:300],
                "stage3": stage3,
                "source_resolved": "gold name" if src_is_gold else "not a gold name",
                "target_resolved": "gold name" if tgt_is_gold else "not a gold name",
                "gold_link": gold_link,
                "raw_count": counts[key],
                "evidence_text": quote[:300],
            })

        # False negatives: gold relations with no found triple, listed once each.
        seen_fn: set[tuple[str, str, str]] = set()
        for r in g.get("relations", []):
            ns, nt = gold_end(names, r["source"]), gold_end(names, r["target"])
            key = metrics.norm_triple((ns, r["type"], nt))
            if key in fn_keys and key not in seen_fn:
                seen_fn.add(key)
                fn_rows.append({"document": doc, "source": ns, "type": r["type"], "target": nt,
                                "relationship_type": r["type"],
                                "pair": f"{types.get(ns, 'unknown')}->{types.get(nt, 'unknown')}"})

    # Cross-check against the score file: the same documents unscored, the same per-document
    # tp/fp/fn, and the same micro totals. Each mismatch is recorded in `problems`, and the
    # result's scorer_check reports them.
    if sorted(unscored) != sorted(score.get("documents_unscored", {})):
        problems.append(f"unscored documents {sorted(unscored)} differ from the score file's "
                        f"{sorted(score.get('documents_unscored', {}))}")
    for doc, c in per_doc.items():
        want = score["per_document"].get(doc, {}).get("relations")
        if want is None:
            problems.append(f"{doc}: no relation score in score-bundle.json")
            continue
        if (want["tp"], want["fp"], want["fn"]) != (c["tp"], c["fp"], c["fn"]):
            problems.append(f"{doc}: breakdown tp/fp/fn {(c['tp'], c['fp'], c['fn'])} != score file "
                            f"{(want['tp'], want['fp'], want['fn'])}")
    extra = sorted(set(score["per_document"]) - set(per_doc))
    if extra:
        problems.append(f"score file scores documents the breakdown did not: {extra}")
    tot = {"tp": sum(c["tp"] for c in per_doc.values()), "fp": sum(c["fp"] for c in per_doc.values()),
           "fn": sum(c["fn"] for c in per_doc.values())}
    micro = score["micro"]["relations"]
    if (micro["tp"], micro["fp"], micro["fn"]) != (tot["tp"], tot["fp"], tot["fn"]):
        problems.append(f"totals tp/fp/fn {(tot['tp'], tot['fp'], tot['fn'])} != score file micro "
                        f"{(micro['tp'], micro['fp'], micro['fn'])}")

    # The tables: each attribute's share of the false positives, the top three reasons for
    # them, and a fixed-seed sample of the false positives for manual reading.
    fp_rows = [r for r in found if not r["matched"]]
    tp_rows = [r for r in found if r["matched"]]
    fp_total = len(fp_rows)
    attrs = ("relationship_type", "pair", "evidence_label", "inference_rule", "inference_rule_full", "why",
             "stage3", "has_evidence_text", "confidence", "source_resolved", "target_resolved", "gold_link")
    by_attribute = {a: _table(found, a, fp_total) for a in attrs}
    by_document = {doc: {**c, "precision": round(c["tp"] / c["found"], 4) if c["found"] else 0.0,
                         "share_of_fp": round(c["fp"] / fp_total, 4) if fp_total else 0.0}
                   for doc, c in sorted(per_doc.items())}
    by_document_attr = {doc: {a: _table([r for r in found if r["document"] == doc], a, fp_total)
                              for a in ("why", "inference_rule", "evidence_label")}
                        for doc in sorted(per_doc)}
    fn_counts = {"relationship_type": dict(Counter(r["relationship_type"] for r in fn_rows).most_common()),
                 "pair": dict(Counter(r["pair"] for r in fn_rows).most_common())}
    top3 = list(by_attribute["why"].items())[:3]

    rng = random.Random(SAMPLE_SEED)  # noqa: S311 - a reproducible sample, not a secret
    ordered = sorted(fp_rows, key=lambda r: (r["document"], tuple(r["key"])))
    sample = rng.sample(ordered, min(SAMPLE_SIZE, len(ordered)))

    gold_total = sum(c["gold"] for c in per_doc.values())
    return {
        "run_dir": str(run_dir),
        "gold_dir": str(gold_dir),
        "scorer_check": {"ok": not problems, "problems": problems,
                         "totals": {"found": len(found), "tp": tot["tp"], "fp": tot["fp"],
                                    "gold": gold_total, "fn": tot["fn"]}},
        "unscored_documents": unscored,
        "raw_relationships": raw_total,
        "duplicates_collapsed": duplicates,
        "totals": {"found": len(found), "tp": len(tp_rows), "fp": fp_total, "gold": gold_total,
                   "fn": len(fn_rows),
                   "precision": round(len(tp_rows) / len(found), 4) if found else 0.0,
                   "recall": round(len(tp_rows) / gold_total, 4) if gold_total else 0.0},
        "by_document": by_document,
        "by_attribute": by_attribute,
        "by_document_attribute": by_document_attr,
        "top3_why": [k for k, _ in top3],
        "top3_why_share_of_fp": round(sum(v["fp"] for _, v in top3) / fp_total, 4) if fp_total else 0.0,
        "false_negatives": {"gold": gold_total, "fn": len(fn_rows), **fn_counts},
        "false_negative_rows": fn_rows,
        "false_positives": fp_rows,
        "sample_seed": SAMPLE_SEED,
        "sample": sample,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Breakdown of the relation score of an in-house bundle run.")
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--gold-dir", type=Path, default=inhouse.ROOT)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    try:
        result = analyse(args.run_dir, args.gold_dir)
    except (OSError, ValueError, KeyError) as exc:
        print(f"relation breakdown failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if not result["scorer_check"]["ok"]:
        for p in result["scorer_check"]["problems"]:
            print(f"MISMATCH with score-bundle.json: {p}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
