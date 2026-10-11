"""Measure the gazetteer's ordinary-word policy on AnnoCTR train + dev.

    python scripts/measure_gazetteer_policy.py [--root PATH] [--only CASE CONTEXT AMBIGUOUS]
                                               [--json OUT]

Stage 2b alone, on the same documents, index and corpus, with no policy (what
production emits; shadow mode emits the same) and with the policy applied —
the comparison docs/gazetteer-ordinary-words.md asks for before activation:

- document level: distinct (document, entity type, ATT&CK ID) triples, the
  gold's ID read from AnnoCTR's link to attack.mitre.org; per type, over all
  evaluable documents and over the *affected* ones (a raw, case-insensitive
  match of a form the policy judges, under the matcher's boundary rule —
  fixed before either run), with paired bootstrap intervals over documents
  (10,000 resamples, seed 13);
- mention level: each withheld occurrence against AnnoCTR's located mentions —
  annotated as that identity (a lost valid mention), as another one, or not
  annotated;
- per form: identities removed that are gold (lost) or not, and the documents;
- the spec's gates, each PASS / FAIL / INCONCLUSIVE.

`--only` applies the withholdings of the named classes only — CASE
(case_mismatch), CONTEXT (missing_context), AMBIGUOUS (ambiguous_identity).

The test split is not read (docs/eval/README.md: dev to choose, test once).
Both matcher paths are run (Aho-Corasick when pyahocorasick is installed, and
the regex fallback).  Analyst overrides are switched off: the index alone is
measured.  No database, no LLM; exit 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

os.environ["ENTITY_OVERRIDES_ENABLED"] = "0"
os.environ.pop("SKIP_HEAVY_MODELS", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation import annoctr  # noqa: E402
from evaluation.metrics import Counts, micro, paired_bootstrap, set_counts  # noqa: E402
from pipeline import gazetteer_policy  # noqa: E402
from pipeline import overrides as ov  # noqa: E402
from pipeline import stage2b_gazetteer as gaz  # noqa: E402

TYPES = {"MALWARE": "malware", "GROUP": "threat_actor", "TOOL": "tool"}
CLASSES = {"CASE": "case_mismatch", "CONTEXT": "missing_context", "AMBIGUOUS": "ambiguous_identity"}
SPLITS = ("train", "dev")
_ATTACK_ID = re.compile(r"attack\.mitre\.org/(?:software|groups)/([SG]\d{4})", re.I)
Triple = tuple[str, str]          # (entity type, ATT&CK ID) within one document


@dataclass
class Gold:
    triples: set[Triple] = field(default_factory=set)
    mentions: list[tuple[annoctr.Mention, str]] = field(default_factory=list)   # (mention, type)
    without_id: int = 0


def load_gold(root: Path, docs) -> dict[str, Gold]:
    by_id = {d.doc_id: d for d in docs}
    gold = {d.doc_id: Gold() for d in docs}
    for split in SPLITS:
        for line in (root / "linking_mitre_only" / f"{split}.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            etype = TYPES.get(r.get("entity_type", ""))
            g = gold.get(r.get("document", ""))
            if etype is None or g is None:
                continue
            m = _ATTACK_ID.search(r.get("label_link", ""))
            if not m:
                g.without_id += 1
                continue
            mention = annoctr.Mention(label=m.group(1).upper(), surface=r.get("mention", ""),
                                      kind="explicit" if r.get("entity_class") == "CE" else "implicit",
                                      context_left=r.get("_context_left", ""),
                                      context_right=r.get("_context_right", ""))
            g.triples.add((etype, mention.label))
            g.mentions.append((mention, etype))
    for doc_id, g in gold.items():
        annoctr.locate_mentions(by_id[doc_id].text, [m for m, _ in g.mentions])
    return gold


def judged_forms() -> set[str]:
    return set(gazetteer_policy.decisions()) | set(gaz._ambiguous_forms())


def affected(text: str, forms: set[str]) -> bool:
    """A raw match of one of `forms`, under the regex path's boundary rule."""
    lower = text.lower()
    return any(re.search(r"(?<![^\W_])(?<!-)" + re.escape(f) + r"(?![^\W_])(?!-)", lower) for f in forms)


@contextmanager
def only(reasons: set[str] | None):
    """Withhold only the occurrences whose reason is in `reasons`."""
    original = gazetteer_policy.judge
    if reasons is None:
        yield
        return

    def judge(name_key, surface, ambiguous):
        verdict = original(name_key, surface, ambiguous)
        if verdict.withheld and verdict.reason not in reasons:
            return gazetteer_policy.Judgement("resolved", None, verdict.decision)
        return verdict

    gazetteer_policy.judge = judge
    try:
        yield
    finally:
        gazetteer_policy.judge = original


@contextmanager
def matcher(path: str):
    saved = gaz._AHO_AVAILABLE
    gaz._AHO_AVAILABLE = saved and path == "aho"
    ov.reload()
    try:
        yield
    finally:
        gaz._AHO_AVAILABLE = saved
        ov.reload()


def run(docs, mode: str) -> tuple[list[set[Triple]], list[list[dict]], int]:
    preds, traces, without_id = [], [], 0
    for doc in docs:
        found, trace = gaz.match_gazetteer_traced(doc.text, policy_mode=mode)
        preds.append({(e.entity_type.value, e.mitre_id) for e in found if e.mitre_id})
        without_id += sum(1 for e in found if not e.mitre_id)
        traces.append(trace)
    return preds, traces, without_id


def _per_doc(docs, gold, preds, etype: str | None) -> list[Counts]:
    out = []
    for doc, p in zip(docs, preds, strict=True):
        g = gold[doc.doc_id].triples
        if etype is not None:
            p, g = {t for t in p if t[0] == etype}, {t for t in g if t[0] == etype}
        out.append(set_counts(p, g))
    return out


def _boot(a: list[Counts], b: list[Counts]) -> dict:
    return {m: paired_bootstrap(a, b, metric=m, n=10000, seed=13) for m in ("precision", "recall", "f1")}


def _mention_at(gold: Gold, start: int, end: int) -> tuple[annoctr.Mention, str] | None:
    for m, etype in gold.mentions:
        if m.start is not None and m.end is not None and m.start < end and start < m.end:
            return m, etype
    return None


def compare(docs, gold, affected_ids: set[str], base, applied, traces) -> dict:
    per_type = {}
    for etype in (*TYPES.values(), None):
        a, b = _per_doc(docs, gold, base, etype), _per_doc(docs, gold, applied, etype)
        per_type[etype or "all"] = {"off": micro(a).as_dict(), "apply": micro(b).as_dict()}
    a_all, b_all = _per_doc(docs, gold, base, None), _per_doc(docs, gold, applied, None)
    idx = [i for i, d in enumerate(docs) if d.doc_id in affected_ids]
    a_aff, b_aff = [a_all[i] for i in idx], [b_all[i] for i in idx]

    forms: dict[str, Counter] = defaultdict(Counter)
    form_docs: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    lost: list[str] = []
    added: list[str] = []
    for doc, pa, pb, trace in zip(docs, base, applied, traces, strict=True):
        g = gold[doc.doc_id]
        withheld = [i for i in trace if i["outcome"] != "resolved"]
        for identity in sorted(pa - pb):
            by = sorted({i["form"] for i in withheld if (i["entity_type"], i["mitre_id"]) == identity})
            key = ", ".join(by) or "(displaced)"
            if identity in g.triples:
                forms[key]["identities_lost_gold"] += 1
                lost.append(f"[{key}] {doc.doc_id}: {identity[1]} ({identity[0]})")
            else:
                forms[key]["identities_removed_non_gold"] += 1
        added += [f"{doc.doc_id}: {t[1]} ({t[0]})" for t in sorted(pb - pa)]
        occurrences: dict[tuple[int, int], list[dict]] = defaultdict(list)
        for i in withheld:
            occurrences[(i["start"], i["end"])].append(i)
        for (start, end), items in occurrences.items():
            form = items[0]["form"]
            ids = {(i["entity_type"], i["mitre_id"]) for i in items}
            hit = _mention_at(g, start, end)
            if hit is None:
                kind = "not_annotated"
            elif (hit[1], hit[0].label) in ids:
                kind = "annotated_as_this_identity"
            else:
                kind = "annotated_as_another_identity"
            forms[form][f"mentions_{kind}"] += 1
            form_docs[form]["positive" if kind == "annotated_as_this_identity" else "negative"].add(doc.doc_id)
    for form, sides in form_docs.items():
        forms[form]["documents_positive"] = len(sides["positive"])
        forms[form]["documents_negative"] = len(sides["negative"])

    return {
        "documents": len(docs),
        "affected_documents": len(idx),
        "identities_emitted": {"off": sum(map(len, base)), "apply": sum(map(len, applied))},
        "per_type_all_documents": per_type,
        "all_types_all_documents": {"off": micro(a_all).as_dict(), "apply": micro(b_all).as_dict(),
                                    "bootstrap": _boot(a_all, b_all)},
        "all_types_affected_documents": {"off": micro(a_aff).as_dict(), "apply": micro(b_aff).as_dict(),
                                         "bootstrap": _boot(a_aff, b_aff)},
        "per_form": {k: dict(v) for k, v in sorted(forms.items())},
        "lost_gold": lost,
        "added_by_apply": added,
    }


def gates(r: dict, paths_agree: bool | None) -> dict[str, str]:
    """The spec's gates that matcher output can decide; the others are named."""
    aff = r["all_types_affected_documents"]["bootstrap"]["precision"]
    rec = r["all_types_all_documents"]["bootstrap"]["recall"]
    worst = min(min(row["apply"][m] - row["off"][m] for m in ("precision", "recall"))
                for t, row in r["per_type_all_documents"].items() if t != "all")
    lost_mentions = sum(c.get("mentions_annotated_as_this_identity", 0) for c in r["per_form"].values())
    thin = [f for f, c in r["per_form"].items()
            if c.get("documents_positive", 0) < 5 or c.get("documents_negative", 0) < 5]
    verdict = lambda ok: "PASS" if ok else "FAIL"  # noqa: E731
    return {
        "paths agree": "n/a (one path)" if paths_agree is None else verdict(paths_agree),
        "precision on affected documents (>= +5 pts, CI low > 0)":
            verdict(aff["observed_diff"] >= 0.05 and aff["ci95"][0] > 0),
        "recall over all documents (>= -1 pt, CI low >= -2 pts)":
            verdict(rec["observed_diff"] >= -0.01 and rec["ci95"][0] >= -0.02),
        "per type (no P or R drop > 2 pts)": verdict(worst >= -0.02) + f" (worst {worst:+.4f})",
        "lost valid mentions (AnnoCTR)": verdict(lost_mentions == 0) + f" ({lost_mentions})",
        "coverage (5 documents per class, per form)":
            "INCONCLUSIVE: AnnoCTR's silence is not an adjudicated negative"
            + (f"; under 5 documents on a side: {len(thin)} of {len(r['per_form'])} forms" if thin else ""),
        "protected cases, output/provenance": "see tests/test_gazetteer_policy.py; end to end not measured here",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", type=Path, default=annoctr.DEFAULT_ROOT)
    ap.add_argument("--only", nargs="+", choices=sorted(CLASSES), default=None)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    docs = [d for d in annoctr.load(args.root, splits=SPLITS) if "cyber" in d.layers]
    gold = load_gold(args.root, docs)
    forms = judged_forms()
    affected_ids = {d.doc_id for d in docs if affected(d.text, forms)}
    reasons = {CLASSES[c] for c in args.only} if args.only else None
    paths = ["aho", "regex"] if gaz._AHO_AVAILABLE else ["regex"]
    results: dict = {"policy_version": gazetteer_policy.version(), "splits": list(SPLITS),
                     "only": args.only or sorted(CLASSES), "judged_forms": len(forms),
                     "gold_linked_outside_attack": sum(g.without_id for g in gold.values()),
                     "gold_mentions_not_located": sum(1 for g in gold.values() for m, _ in g.mentions
                                                      if m.start is None),
                     "paths": {}}
    outputs = {}
    with only(reasons):
        for path in paths:
            with matcher(path):
                base, _, base_no_id = run(docs, "off")
                applied, traces, applied_no_id = run(docs, "apply")
            outputs[path] = (base, applied, traces)
            results["paths"][path] = compare(docs, gold, affected_ids, base, applied, traces)
            results["paths"][path]["predictions_without_attack_id"] = {"off": base_no_id, "apply": applied_no_id}
    agree = None
    if len(outputs) == 2:
        (ba, aa, ta), (br, ar, tr) = outputs["aho"], outputs["regex"]
        key = lambda t: sorted((i["start"], i["end"], i["mitre_id"], i["outcome"]) for i in t)  # noqa: E731
        diff = {"off": sum(x != y for x, y in zip(ba, br, strict=True)),
                "apply": sum(x != y for x, y in zip(aa, ar, strict=True)),
                "withheld occurrences": sum(key(x) != key(y) for x, y in zip(ta, tr, strict=True))}
        results["documents_where_paths_differ"] = diff
        agree = not any(diff.values())
    first = results["paths"][paths[0]]
    results["gates"] = gates(first, agree)

    print(f"policy {results['policy_version']}  classes {results['only']}  "
          f"{first['documents']} documents (AnnoCTR train+dev, cyber layer), "
          f"{first['affected_documents']} affected ({len(forms)} judged forms)")
    print(f"gold rows linked outside ATT&CK (not scored): {results['gold_linked_outside_attack']}; "
          f"gold mentions not located: {results['gold_mentions_not_located']}")
    if "documents_where_paths_differ" in results:
        print(f"documents where aho and regex differ: {results['documents_where_paths_differ']}")
    r = first
    print(f"\n[{paths[0]}] (document, type, ATT&CK ID) identities emitted "
          f"off={r['identities_emitted']['off']} apply={r['identities_emitted']['apply']}")
    for t, row in r["per_type_all_documents"].items():
        o, a = row["off"], row["apply"]
        print(f"  {t:13} off P={o['precision']:.3f} R={o['recall']:.3f} F1={o['f1']:.3f} "
              f"(tp {o['tp']} fp {o['fp']} fn {o['fn']})   apply P={a['precision']:.3f} "
              f"R={a['recall']:.3f} F1={a['f1']:.3f} (tp {a['tp']} fp {a['fp']} fn {a['fn']})")
    for scope in ("all_types_all_documents", "all_types_affected_documents"):
        print(f"  {scope}:")
        for m, b in r[scope]["bootstrap"].items():
            print(f"    delta {m:9} {b['observed_diff']:+.4f}  95% CI {b['ci95']}")
    print("  per form:")
    for form, c in r["per_form"].items():
        print(f"    {form:24} " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
    for item in r["lost_gold"]:
        print(f"    LOST {item}")
    for item in r["added_by_apply"]:
        print(f"    ADDED {item}")
    print("\ngates:")
    for g, v in results["gates"].items():
        print(f"  {g}: {v}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
        print(f"\nwritten {args.json}")


if __name__ == "__main__":
    main()
