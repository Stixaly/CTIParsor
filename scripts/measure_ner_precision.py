"""Measure the entity precision filters (ADR-0088, ADR-0089) on AnnoCTR.

    python scripts/measure_ner_precision.py run --split SPLIT --name NAME [--disable IDS]
                                                [--allow-degraded] [--limit N] [--allow-dirty]
    python scripts/measure_ner_precision.py status NAME [--move-aside]
    python scripts/measure_ner_precision.py replay NAME --expect VARIANT [--base VARIANT]
                                                [--variants V,...] [--json OUT]
    python scripts/measure_ner_precision.py compare BASE CANDIDATE [--json OUT]
    python scripts/measure_ner_precision.py gates COMPARE_JSON [--train REPLAY_JSON]

run      `python -m evaluation run`, unchanged, plus what Stage 2's models
         said.  Each document record gains "sources" (each extractor's rows
         before the merge) and "raw" (the chunks, the text, CyNER's
         predictions as the HuggingFace pipeline returned them and spaCy's
         entities per call, every label with its sentence).  `evaluation
         score` and `evaluation compare` read the record as usual.  The run
         also gets ner-meta.json beside run.json: the commit, whether the
         tracked files are clean, the options and the variables the
         measurement depends on, read after `.env` is loaded, and the spaCy
         and CyNER models loaded.  It refuses to start without the checkout's
         .env, without spaCy and CyNER loaded, without NER_PRECISION_FILTERS
         and NER_PRECISION_MALWARE set to true or false, with analyst
         overrides or calibrated cutoffs on, with Stage 3 and a temperature
         other than 0 or no seed, from a tree whose tracked files differ from
         the commit (unless --allow-dirty), or to resume with another commit,
         options, settings or models.
status   what a run has written: documents missing, and the ones to run again
         (see `rerun_reason`: an error or unreadable record, a Stage 3
         request that got no answer, a CyNER or spaCy pass that did not
         run).  --move-aside moves those records to
         rerun-<time>/ so that resuming the run does them again, at most twice
         per document.  Prints nothing about entities.
replay   re-runs Stage 2 of a recorded run on its recorded model outputs with
         the code of this checkout, once per variant.  spaCy and CyNER are
         replaced by stubs that return what the models returned; the regex
         extractors, the filters, the merge and the type conflicts run.  The
         gazetteer, GLiNER and alias-list rows are the recorded ones (no
         filter touches them), and the LLM's rows are added as the run
         recorded them.  The --expect variant must give back the run's Stage 2
         entities (type, value, source, confidence, ATT&CK id) exactly,
         document by document, or the command stops.  Each --variants entry is
         scored against --base (default: --expect).
compare  two real runs of the same split, per type: counts, the paired
         bootstrap, the gold entities lost and gained, the predictions removed
         and added with the extractors that proposed them.  A document is left
         out of both runs when it is missing from either, or when either
         record still has to be run again (see status).  It lists every way
         the two runs' configurations differ beyond NER_PRECISION_MALWARE
         (ner-meta.json, and run.json's options and manifest).
gates    ADR-0089's criteria (docs/eval/ner-malware-2026-10.md, fixed before
         the test runs), PASS or FAIL each, from a `compare` JSON of the two
         test runs and, for M5, the `replay` JSON of the train recording.
         Exit 0 adopt, 1 do not adopt, 2 void (M0), 3 an input is missing.

Variants: off (NER_PRECISION_FILTERS=false), adr0088 (the filters on,
NER_PRECISION_MALWARE=false), malware (both on).  ADR-0089's lead was not
adopted and its switch was removed from the pipeline after the measurement:
the `malware` variant, and `run` with NER_PRECISION_MALWARE, refuse to run
without it.  Replay or run them at commit ccb9edf, where the lead and this
harness were frozen.  `gates` is ADR-0089's rule as registered; a new lead
registers its own.

Scoring is `evaluation.metrics.score_entities`, strict, on the types AnnoCTR
annotates in each document, micro-averaged over the documents; the bootstrap
is `evaluation.metrics.paired_bootstrap`, documents resampled, 10,000
resamples, seed 13.  `replay` needs no model, no LLM and no database: it sets
SKIP_HEAVY_MODELS=1, ENTITY_OVERRIDES_ENABLED=0 and
THRESHOLD_CALIBRATION_ENABLED=false itself, as the runs it replays were made.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# `replay`, `compare` and `status` read another checkout's data with --data (a
# worktree without its own data/); `run` writes where `python -m evaluation`
# does, and refuses --data.
DATA = _ROOT / "data"
SCORED = ("threat_actor", "malware", "location", "tool", "identity")
RESAMPLES = 10_000
SEED = 13
MAX_RERUNS = 2

VARIANTS: dict[str, dict[str, str]] = {
    "off": {"NER_PRECISION_FILTERS": "false", "NER_PRECISION_MALWARE": "false"},
    "adr0088": {"NER_PRECISION_FILTERS": "true", "NER_PRECISION_MALWARE": "false"},
    "malware": {"NER_PRECISION_FILTERS": "true", "NER_PRECISION_MALWARE": "true"},
}

# What the measurement depends on, recorded with each run (never a secret:
# names with KEY, TOKEN, SECRET or PASSWORD are skipped).
_META_ENV = (
    "NER_PRECISION_FILTERS", "NER_PRECISION_MALWARE", "ENTITY_OVERRIDES_ENABLED",
    "THRESHOLD_CALIBRATION_ENABLED", "SKIP_HEAVY_MODELS", "CYNER_ENABLED", "GLINER_ENABLED",
    "GAZETTEER_POLICY", "LLM_PROVIDER", "VLLM_MODEL", "LLM_TEMPERATURE", "LLM_SEED",
    "LLM_PARALLELISM", "TTP_MODE", "ENABLE_STIX_VERIFICATION", "ENABLE_TTP_VERIFICATION",
)
# The options of `run` a resumed run must share with its start.
_META_SAME = ("commit", "clean", "env", "filters", "malware_lead", "split", "disable", "allow_degraded", "limit",
              "models")


# ── run ──────────────────────────────────────────────────────────────────────

def _git(*args: str) -> str:
    """Git in this checkout: WSL's git, or Windows git through WSL's interop
    when the worktree was made by Windows git (its .git file names a Windows
    path that WSL's git cannot open)."""
    last: Exception | None = None
    for binary in ("git", "git.exe"):
        try:
            return subprocess.run([binary, *args], cwd=_ROOT, capture_output=True, text=True,
                                  check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            last = exc
    raise RuntimeError(f"git {' '.join(args)}: {last}")


def _head() -> tuple[str | None, bool | None]:
    """The commit checked out, and whether the tracked files are clean (None:
    unknown).  Without a working git, the HEAD is read from the worktree's git
    directory and cleanliness is unknown."""
    try:
        return _git("rev-parse", "HEAD"), _git("status", "--porcelain", "--untracked-files=no") == ""
    except RuntimeError:
        pass
    try:
        gitdir = (_ROOT / ".git").read_text(encoding="utf-8").split("gitdir:", 1)[1].strip()
        if len(gitdir) > 2 and gitdir[1] == ":":            # C:/Users/... -> /mnt/c/Users/...
            gitdir = f"/mnt/{gitdir[0].lower()}{gitdir[2:]}"
        wt = Path(gitdir)
        head = (wt / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):                        # on a branch: the ref, loose or packed
            ref = head[5:]
            common = (wt / (wt / "commondir").read_text(encoding="utf-8").strip()).resolve()
            loose = common / ref
            if loose.exists():
                head = loose.read_text(encoding="utf-8").strip()
            else:
                packed = (common / "packed-refs").read_text(encoding="utf-8").splitlines()
                head = next((ln.split()[0] for ln in packed if ln.endswith(" " + ref)), "")
    except (OSError, IndexError):
        return None, None
    return (head if len(head) == 40 and all(c in "0123456789abcdef" for c in head) else None), None


def _meta(args, models: dict) -> dict:
    from pipeline import ner_precision
    code = Path(ner_precision.__file__).resolve()
    if _ROOT.resolve() not in code.parents:
        sys.exit(f"pipeline is imported from {code}, not from this checkout ({_ROOT})")
    commit, clean = _head()
    if commit is None:
        sys.exit("cannot tell which commit is checked out: a measurement run must name its commit")
    if clean is not True and not args.allow_dirty:
        sys.exit(f"tracked files differ from {commit[:7]} (or git cannot tell): commit, or pass --allow-dirty")
    env = {k: os.environ[k] for k in _META_ENV
           if k in os.environ and not any(s in k for s in ("KEY", "TOKEN", "SECRET", "PASSWORD"))}
    return {"commit": commit, "clean": clean, "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "split": args.split, "disable": args.disable, "allow_degraded": args.allow_degraded,
            "limit": args.limit, "env": env, "models": models,
            "filters": ner_precision.enabled(), "malware_lead": _malware_lead()}


def _malware_lead() -> bool:
    """Whether ADR-0089's lead is on; False where the switch no longer exists."""
    from pipeline import ner_precision
    enabled = getattr(ner_precision, "malware_enabled", None)
    return bool(enabled()) if enabled else False


def _write_meta(args, models: dict) -> None:
    run_dir = _ROOT / "data" / "eval" / "runs" / args.name
    path = run_dir / "ner-meta.json"
    meta = _meta(args, models)
    if path.exists():
        first = json.loads(path.read_text(encoding="utf-8"))
        for k in _META_SAME:
            if first.get(k) != meta[k]:
                sys.exit(f"refusing to resume {args.name}: {k} was {first.get(k)!r}, is now {meta[k]!r}")
        first.setdefault("resumed", []).append(meta["started"])
        meta = first
    run_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")


def cmd_run(args) -> None:
    if DATA.resolve() != (_ROOT / "data").resolve():
        sys.exit("--data is for status, replay and compare: `run` writes into this checkout's data/")
    # As main.py does, before any pipeline module reads its settings at import.
    # Without it, stage3_llm's own load_dotenv() would find another checkout's
    # .env after ner-meta.json is written.
    env_file = _ROOT / ".env"
    if not env_file.is_file():
        sys.exit(f"no .env in {_ROOT}: copy the main checkout's, a measurement runs with its settings")
    from dotenv import load_dotenv
    load_dotenv(env_file)
    from pipeline.env_flags import env_bool

    disabled = {s.strip() for s in (args.disable or "").split(",") if s.strip()}
    if "3" not in disabled:
        missing = [k for k in ("LLM_TEMPERATURE", "LLM_SEED") if not os.environ.get(k)]
        if missing:
            sys.exit(f"Stage 3 runs: set {', '.join(missing)} (docs/eval/README.md, run-to-run spread)")
        try:
            temperature = float(os.environ["LLM_TEMPERATURE"])
        except ValueError:
            temperature = -1.0
        if temperature != 0:
            sys.exit("Stage 3 runs: set LLM_TEMPERATURE=0 (docs/eval/README.md, run-to-run spread)")
    from pipeline import ner_precision
    has_lead = hasattr(ner_precision, "malware_enabled")
    for k in ("NER_PRECISION_FILTERS", "NER_PRECISION_MALWARE") if has_lead else ("NER_PRECISION_FILTERS",):
        if os.environ.get(k, "").strip().lower() not in ("true", "false"):
            sys.exit(f"set {k}=true or {k}=false: a measurement run names the filters it runs with")
    if not has_lead and os.environ.get("NER_PRECISION_MALWARE", "").strip().lower() in ("1", "true", "yes", "on"):
        sys.exit("NER_PRECISION_MALWARE=true: this checkout has no malware lead (ADR-0089, removed); run at ccb9edf")
    # The rows analysts saved in the database (deny rows, calibrated cutoffs)
    # change what the models' names become, and can change between two runs.
    for k in ("ENTITY_OVERRIDES_ENABLED", "THRESHOLD_CALIBRATION_ENABLED"):
        if env_bool(k, default=True):
            sys.exit(f"set {k}=false: a measurement measures the models, not the database's rows")

    from evaluation import __main__ as em
    from pipeline import orchestrator
    from pipeline import stage2_extraction as s2
    from pipeline import stage2d_cyner as s2d

    # The filters act on what these two models return: a run without them
    # measures nothing (SKIP_HEAVY_MODELS, CYNER_ENABLED=false, no model).
    if s2._nlp is None or not s2d.cyner_available():
        sys.exit(f"spaCy loaded: {s2._nlp is not None}, CyNER loaded: {s2d.cyner_available()}: both are needed")
    # spaCy falls back from en_core_web_lg to en_core_web_sm without a word.
    nlp_meta = getattr(s2._nlp, "meta", None) or {}
    models = {"spacy": f"{nlp_meta.get('lang')}_{nlp_meta.get('name')}-{nlp_meta.get('version')}",
              "cyner": s2d._MODEL_ID}

    rec: dict[str, list] = {"spacy": [], "cyner": []}

    class SpacyRecorder:
        def __init__(self, nlp):
            self._nlp = nlp

        def __call__(self, text):
            doc = self._nlp(text)
            rec["spacy"].append([{"text": e.text, "label": e.label_, "start": e.start_char,
                                  "end": e.end_char, "sent": e.sent.text[:200]} for e in doc.ents])
            return doc

    s2._nlp = SpacyRecorder(s2._nlp)
    real_load = s2d._load_pipeline

    def load_recording():
        ner = real_load()
        if ner is None:
            return None

        def call(chunks, **kw):
            out = ner(chunks, **kw)
            flat = [out] if out and isinstance(out[0], dict) else out
            rec["cyner"].append([[{"entity_group": p.get("entity_group"), "score": float(p.get("score", 0.0)),
                                   "word": p.get("word"), "start": p.get("start"), "end": p.get("end")}
                                  for p in (preds or [])] for preds in flat])
            return out
        return call

    s2d._load_pipeline = load_recording  # type: ignore[assignment]

    def rows(entities, with_context=False):
        out = []
        for e in entities:
            row = {"type": e.entity_type.value, "value": e.value, "source": e.source,
                   "confidence": e.confidence, "mitre_id": e.mitre_id}
            if with_context and e.source == "spacy":
                row["context"] = e.context
            out.append(row)
        return out

    real_predictions = em._predictions

    def predictions(result):
        p = real_predictions(result)
        p["sources"] = {
            "chunks": [rows(c, with_context=True) for c in result.entities_per_chunk],
            "gazetteer": rows(result.gazetteer),
            "cyner": rows(result.cyner),
            "gliner": rows(result.gliner),
            "alias_list": rows(result.alias_list),
            "stage2_entities": rows(result.entities),
        }
        p["raw"] = {"text": result.text, "chunks": list(result.chunks),
                    "spacy_calls": list(rec["spacy"]), "cyner_calls": list(rec["cyner"])}
        rec["spacy"].clear()
        rec["cyner"].clear()
        return p

    em._predictions = predictions

    # A document that raises leaves its recordings behind: start each one clean.
    real_run_document = orchestrator.run_document

    def run_document(*a, **kw):
        rec["spacy"].clear()
        rec["cyner"].clear()
        return real_run_document(*a, **kw)

    orchestrator.run_document = run_document
    _write_meta(args, models)
    em.cmd_run(args)


# ── status ───────────────────────────────────────────────────────────────────

def read_record(p: Path) -> dict:
    """A document record, or an error record when the file cannot be read (a
    run cut off while writing it): it is then run again."""
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"doc_id": p.stem, "error": f"unreadable record: {exc}"}


def rerun_reason(rec: dict) -> str | None:
    """Why a document's record must be run again, or None.  An error record;
    a Stage 3 request that got no answer (HTTP error, timeout: the server's
    doing, not the model's); a CyNER pass that recorded nothing (Stage 2d
    logs an inference error and goes on with no names) or a spaCy pass that
    did not read every chunk.  An answer that does not parse, or an empty
    one, is the model's answer and stays."""
    if "error" in rec:
        return "error: " + str(rec["error"])[:160]
    for s in rec.get("stages") or []:
        n = (s.get("counts") or {}).get("provider_failures", 0) if s.get("stage") == "3" else 0
        if n:
            return f"Stage 3: {n} request(s) got no answer"
    raw = rec.get("raw")
    if raw is not None:
        if not raw.get("cyner_calls"):
            return "Stage 2d: CyNER recorded no prediction call"
        if len(raw.get("spacy_calls") or []) != len(raw.get("chunks") or []):
            return f"Stage 2: spaCy read {len(raw.get('spacy_calls') or [])} of {len(raw.get('chunks') or [])} chunks"
    return None


def _expected_docs(split: str) -> list[str]:
    from evaluation import annoctr
    return [d.doc_id for d in annoctr.load(root=DATA / "annoctr-repo" / "AnnoCTR", splits=(split,))
            if "cyber" in d.layers]


def cmd_status(args) -> None:
    run_dir = DATA / "eval" / "runs" / args.name
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    expected = _expected_docs(meta["split"])
    records = {p.stem: read_record(p) for p in (run_dir / "docs").glob("*.json")}
    missing = [d for d in expected if d not in records]
    rerun = {d: r for d in expected if d in records and (r := rerun_reason(records[d]))}
    moved_before = {d: len(list(run_dir.glob(f"rerun-*/{d}.json"))) for d in rerun}
    print(f"{args.name} ({meta['split']}): {len(expected)} documents, {len(records)} written, "
          f"{len(missing)} missing, {len(rerun)} to run again")
    for d in missing:
        print(f"  missing  {d}")
    for d, why in rerun.items():
        print(f"  again    {d}  ({why}; set aside {moved_before[d]} time(s) before)")
    if args.move_aside and rerun:
        dest = run_dir / f"rerun-{time.strftime('%Y%m%d-%H%M%S')}"
        for d in rerun:
            if moved_before[d] >= MAX_RERUNS:
                print(f"  kept     {d}: already run again {MAX_RERUNS} times, left out of the comparison")
                continue
            dest.mkdir(exist_ok=True)
            shutil.move(str(run_dir / "docs" / f"{d}.json"), str(dest / f"{d}.json"))
            print(f"  moved    {d} -> {dest.name}/")


# ── replay ───────────────────────────────────────────────────────────────────

def _replay_env() -> None:
    os.environ["SKIP_HEAVY_MODELS"] = "1"
    os.environ["ENTITY_OVERRIDES_ENABLED"] = "0"
    os.environ["THRESHOLD_CALIBRATION_ENABLED"] = "false"


class _Sent:
    def __init__(self, text):
        self.text = text


class _Ent:
    def __init__(self, r):
        self.text, self.label_, self.sent = r["text"], r["label"], _Sent(r["sent"])
        self.start_char, self.end_char = r["start"], r["end"]


class _Doc:
    def __init__(self, ents, text=""):
        self.ents = [_Ent(r) for r in ents]
        self.text = text


class _FakeNLP:
    def __init__(self, calls):
        self.calls, self.i = calls, 0

    def __call__(self, text):
        d = _Doc(self.calls[self.i], text)
        self.i += 1
        return d


def _to_raw(r: dict):
    from models.schemas import EntityType, RawEntity
    return RawEntity(value=r["value"], entity_type=EntityType(r["type"]),
                     context=r.get("context") or "",
                     confidence=r["confidence"] if r.get("confidence") is not None else 1.0,
                     source=r["source"], mitre_id=r.get("mitre_id"))


def _stage2(rec: dict) -> list:
    """Stage 2 as pipeline/orchestrator.py runs it (Stages 2, 2b, 2d, 2e, 2g,
    then the type conflicts), on the recorded model outputs."""
    from pipeline import stage2_extraction as s2
    from pipeline import stage2d_cyner as s2d
    from pipeline.base import BaseExtractionStage, resolve_type_conflicts
    from pipeline.stage2e_gliner import _merge_gliner_into

    raw, src = rec["raw"], rec["sources"]
    fake = _FakeNLP(raw["spacy_calls"])
    s2._nlp = fake
    per_chunk = [s2.extract_entities(c) for c in raw["chunks"]]
    if fake.i != len(raw["spacy_calls"]):
        sys.exit(f"{rec['doc_id']}: {fake.i} spaCy calls replayed, {len(raw['spacy_calls'])} recorded")
    best: dict[tuple, Any] = {}
    for chunk_ents in per_chunk:
        for e in chunk_ents:
            key = (e.value.lower(), e.entity_type)
            if key not in best or e.confidence > best[key].confidence:
                best[key] = e
    for g in src["gazetteer"]:
        ge = _to_raw(g)
        best.setdefault((ge.value.lower(), ge.entity_type), ge)
    ents = list(best.values())
    calls = raw["cyner_calls"]
    s2d._load_pipeline = (
        (lambda: (lambda chunks, **kw: calls[0])) if calls else (lambda: None))  # type: ignore[assignment]
    ents = BaseExtractionStage.merge_into(ents, s2d.extract_cyner_entities(raw["text"]))
    ents = _merge_gliner_into(ents, [_to_raw(r) for r in src["gliner"]])
    ents = BaseExtractionStage.merge_into(ents, [_to_raw(r) for r in src["alias_list"]])
    return resolve_type_conflicts(ents)


def load(name: str):
    """A run's meta and its (AnnoCTR document, record) pairs, errors left out."""
    from evaluation import annoctr
    run_dir = DATA / "eval" / "runs" / name
    meta = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    docs = {d.doc_id: d for d in annoctr.load(root=DATA / "annoctr-repo" / "AnnoCTR", splits=(meta["split"],))
            if "cyber" in d.layers}
    rows = []
    for p in sorted((run_dir / "docs").glob("*.json")):
        rec = read_record(p)
        d = docs.get(rec["doc_id"])
        if d is not None and "error" not in rec:
            rows.append((d, rec))
    return meta, rows


def _norm(v: str) -> str:
    from evaluation.metrics import _norm as norm
    return norm(v)


def _srcs_of_replay(d, rec, ents) -> dict[tuple[str, str], set[str]]:
    types = set(d.evaluable()["entity_types"])
    srcs: dict[tuple[str, str], set[str]] = {}
    for e in ents:
        if e.entity_type.value in types:
            srcs.setdefault((e.entity_type.value, _norm(e.value)), set()).add(e.source)
    for r in rec["entities"]:
        if r.get("source") == "llm" and r["type"] in types:
            srcs.setdefault((r["type"], _norm(r["value"])), set()).add("llm")
    return srcs


def _srcs_of_record(d, rec) -> dict[tuple[str, str], set[str]]:
    types = set(d.evaluable()["entity_types"])
    srcs: dict[tuple[str, str], set[str]] = {}
    for r in rec["entities"]:
        if r["type"] in types:
            srcs.setdefault((r["type"], _norm(r["value"])), set()).add(r.get("source") or "?")
    return srcs


def _tp_set(srcs, d):
    """The gold entities matched exactly, and each prediction's outcome, with
    score_entities' one-to-one matching (exact pairs first)."""
    pred = list(srcs)
    gold = list(d.entities.values())
    gold_sets = [(g.etype, {_norm(g.label)} | {_norm(s) for s in g.surfaces}) for g in gold]
    cands = []
    for pi, (pt, pv) in enumerate(pred):
        for gi, (gt, forms) in enumerate(gold_sets):
            if pt != gt:
                continue
            if pv in forms:
                cands.append((0, pi, gi, True))
            elif any(pv in f or f in pv for f in forms if f and pv):
                cands.append((1, pi, gi, False))
    cands.sort()
    used_p: dict[int, bool] = {}
    used_g: set[int] = set()
    tps = set()
    for _, pi, gi, exact in cands:
        if pi in used_p or gi in used_g:
            continue
        used_p[pi] = exact
        used_g.add(gi)
        if exact:
            tps.add((gold[gi].etype, gold[gi].label))
    outcome = {pred[i]: ("tp" if used_p.get(i) is True else "partial" if i in used_p else "fp")
               for i in range(len(pred))}
    return tps, outcome


def _scored(d, srcs) -> dict:
    from evaluation import metrics
    counts = metrics.score_entities(list(srcs), [(g.etype, g.label, g.surfaces) for g in d.entities.values()])
    tps, outcome = _tp_set(srcs, d)
    return {"counts": counts, "tps": tps, "outcome": outcome, "srcs": srcs}


def replay_variant(rows, name: str, check: bool = False) -> dict:
    from pipeline import ner_precision
    if name == "malware" and not hasattr(ner_precision, "malware_enabled"):
        sys.exit("this checkout has no malware lead (ADR-0089, removed after the measurement): replay it at ccb9edf")
    os.environ.update(VARIANTS[name])
    out = {}
    for d, rec in rows:
        ents = _stage2(rec)
        if check:
            got = [(e.entity_type.value, e.value, e.source, e.confidence, e.mitre_id) for e in ents]
            want = [(r["type"], r["value"], r["source"], r["confidence"], r["mitre_id"])
                    for r in rec["sources"]["stage2_entities"]]
            if got != want:
                sys.exit(f"replay of {name} differs from the record on {d.doc_id}: {sorted(set(got) ^ set(want))}")
        out[d.doc_id] = _scored(d, _srcs_of_replay(d, rec, ents))
    return out


def summarize(base: dict, var: dict) -> dict:
    """Per scored type: totals, lost and gained gold entities, removed and
    added predictions, and the paired bootstrap when anything moved."""
    from evaluation import metrics
    docs = sorted(base)
    res = {}
    for t in SCORED:
        a = [base[k]["counts"].get(t, metrics.Counts()) for k in docs]
        b = [var[k]["counts"].get(t, metrics.Counts()) for k in docs]
        ta, tb = sum(a, metrics.Counts()), sum(b, metrics.Counts())
        lost = sorted((k, lab) for k in docs for (tt, lab) in base[k]["tps"] - var[k]["tps"] if tt == t)
        gained = sorted((k, lab) for k in docs for (tt, lab) in var[k]["tps"] - base[k]["tps"] if tt == t)
        removed = sorted((k, v, o, "+".join(sorted(base[k]["srcs"][(tt, v)])))
                         for k in docs for (tt, v), o in base[k]["outcome"].items()
                         if tt == t and (tt, v) not in var[k]["outcome"])
        added = sorted((k, v, o, "+".join(sorted(var[k]["srcs"][(tt, v)])))
                       for k in docs for (tt, v), o in var[k]["outcome"].items()
                       if tt == t and (tt, v) not in base[k]["outcome"])
        row = {"base": ta.as_dict(), "variant": tb.as_dict(), "lost_tp": lost, "gained_tp": gained,
               "removed": removed, "added": added}
        if ta.as_dict() != tb.as_dict():
            row["bootstrap"] = {m: metrics.paired_bootstrap(a, b, metric=m, n=RESAMPLES, seed=SEED)
                                for m in ("precision", "recall", "f1")}
        res[t] = row
    return res


def _line(t: str, r: dict) -> str:
    x, y = r["base"], r["variant"]
    line = (f"  {t:<13} P {x['precision']:.3f}->{y['precision']:.3f} R {x['recall']:.3f}->{y['recall']:.3f} "
            f"F1 {x['f1']:.3f}->{y['f1']:.3f} tp {x['tp']}->{y['tp']} fp {x['fp']}->{y['fp']} "
            f"lost {len(r['lost_tp'])} gained {len(r['gained_tp'])}")
    if "bootstrap" in r:
        bs = r["bootstrap"]
        line += "  dP {:+.1f} [{:+.1f}, {:+.1f}]".format(
            bs["precision"]["observed_diff"] * 100, *(c * 100 for c in bs["precision"]["ci95"]))
    return line


def _dump(path: str | None, data: dict) -> None:
    if path:
        Path(path).write_text(json.dumps(data, indent=1, ensure_ascii=False, default=sorted), encoding="utf-8")


def cmd_replay(args) -> None:
    _replay_env()
    meta, rows = load(args.name)
    base_name = args.base or args.expect
    expected = replay_variant(rows, args.expect, check=True)
    print(f"{args.name} ({meta['split']}, {len(rows)} documents): {args.expect} gives back the recorded "
          f"Stage 2 entities on {len(rows)}/{len(rows)}")
    base = expected if base_name == args.expect else replay_variant(rows, base_name)
    report = {"run": args.name, "split": meta["split"], "documents": len(rows), "expect": args.expect,
              "base": base_name, "variants": {}}
    for v in [v for v in (args.variants or "").split(",") if v and v != base_name]:
        report["variants"][v] = summarize(base, replay_variant(rows, v))
        print(f"{v} against {base_name}:")
        for t, r in report["variants"][v].items():
            if r["base"] != r["variant"] or r["lost_tp"] or r["gained_tp"]:
                print(_line(t, r))
    _dump(args.json, report)


# ── compare ──────────────────────────────────────────────────────────────────

def _load_meta(name: str) -> dict | None:
    path = DATA / "eval" / "runs" / name / "ner-meta.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def per_doc(name: str) -> tuple[dict, dict, dict[str, str]]:
    """A run's meta, its scored documents, and the documents to leave out
    with the reason (a record still to run again)."""
    meta, rows = load(name)
    run_dir = DATA / "eval" / "runs" / name
    left_out = {}
    for p in sorted((run_dir / "docs").glob("*.json")):
        why = rerun_reason(read_record(p))
        if why:
            left_out[p.stem] = why
    return meta, {d.doc_id: _scored(d, _srcs_of_record(d, rec)) for d, rec in rows if d.doc_id not in left_out}, \
        left_out


def config_problems(ma: dict | None, mb: dict | None, a: str, b: str) -> list[str]:
    """Every way two runs' configurations differ beyond the one switch the
    measurement compares (base: lead off, candidate: lead on)."""
    if ma is None or mb is None:
        return [f"no ner-meta.json for {n}" for n, m in ((a, ma), (b, mb)) if m is None]
    out = []
    for k in ("commit", "split", "disable", "allow_degraded", "limit", "models"):
        if ma.get(k) != mb.get(k):
            out.append(f"{k}: {ma.get(k)!r} against {mb.get(k)!r}")
    for n, m in ((a, ma), (b, mb)):
        if m.get("clean") is not True:
            out.append(f"{n}: tracked files not known to be clean")
        if m.get("filters") is not True:
            out.append(f"{n}: NER_PRECISION_FILTERS off")
    if ma.get("malware_lead") is not False or mb.get("malware_lead") is not True:
        out.append(f"malware lead {ma.get('malware_lead')!r} -> {mb.get('malware_lead')!r}, expected False -> True")
    ea = {k: v for k, v in (ma.get("env") or {}).items() if k != "NER_PRECISION_MALWARE"}
    eb = {k: v for k, v in (mb.get("env") or {}).items() if k != "NER_PRECISION_MALWARE"}
    for k in sorted(set(ea) | set(eb)):
        if ea.get(k) != eb.get(k):
            out.append(f"{k}: {ea.get(k)!r} against {eb.get(k)!r}")
    return out


# run.json: what `python -m evaluation run` decided and recorded (models, data
# files, packages, prompt fingerprints, sampling).  Two runs hours apart can
# drift (a package upgraded, a data file rebuilt) with the same commit.
_RUN_SAME = ("split", "disabled", "required", "consensus", "document_relations", "ttp_mode")


def run_problems(ra: dict, rb: dict) -> list[str]:
    """Every way two runs' run.json differ, beyond their name and start time."""
    out = [f"run.json {k}: {ra.get(k)!r} against {rb.get(k)!r}" for k in _RUN_SAME if ra.get(k) != rb.get(k)]
    ma, mb = ra.get("manifest") or {}, rb.get("manifest") or {}
    out += [f"run.json manifest.{k} differs" for k in sorted(set(ma) | set(mb)) if ma.get(k) != mb.get(k)]
    return out


def left_out_docs(expected: list[str], scored: dict[str, set[str]], out: dict[str, dict[str, str]]) -> dict[str, str]:
    """The documents of the split not scored in both runs, with why: a record
    still to run again (`out`), or none at all.  `scored` and `out` are keyed
    by run name, the base first."""
    names = list(scored)
    left = {}
    for d in expected:
        if all(d in scored[n] for n in names):
            continue
        left[d] = "; ".join(f"{n}: {out[n][d]}" if d in out[n] else f"{n}: not scored"
                            for n in names if d not in scored[n])
    return left


def cmd_compare(args) -> None:
    meta_a, a, out_a = per_doc(args.base)
    meta_b, b, out_b = per_doc(args.candidate)
    if meta_a["split"] != meta_b["split"]:
        sys.exit(f"{args.base} is {meta_a['split']}, {args.candidate} is {meta_b['split']}")
    expected = _expected_docs(meta_a["split"])
    common = sorted(set(a) & set(b))
    if not common:
        sys.exit("no document scored in both runs")
    left_out = left_out_docs(expected, {args.base: set(a), args.candidate: set(b)},
                             {args.base: out_a, args.candidate: out_b})
    problems = config_problems(_load_meta(args.base), _load_meta(args.candidate), args.base, args.candidate)
    problems += run_problems(meta_a, meta_b)
    res = summarize({k: a[k] for k in common}, {k: b[k] for k in common})
    report = {"a": args.base, "b": args.candidate, "split": meta_a["split"], "expected": len(expected),
              "documents": len(common), "left_out": left_out, "config_problems": problems, "types": res}
    print(f"{args.candidate} against {args.base} ({meta_a['split']}): {len(common)} of {len(expected)} documents")
    for d, reason in left_out.items():
        print(f"  left out {d}: {reason}")
    for p in problems:
        print(f"  configuration: {p}")
    for t, r in res.items():
        print(_line(t, r))
    _dump(args.json, report)


# ── gates (ADR-0089, fixed before the test runs) ─────────────────────────────

PRIMARY = "malware"
ALSO_ACTED_ON = "threat_actor"       # lead B shortens actor names too
MIN_GAIN = 0.05                      # M1: +5 points of strict precision
MAX_NET_LOSS = 1                     # M2, M4a: gold entities lost, net
MAX_DROP = 0.01                      # M4a precision, M4b precision and recall
MAX_TRAIN_LOSS = 0.02                # M5: share of the train true positives
MAX_LEFT_OUT = 2                     # M0: more documents left out: no decision


def _diff(r: dict, m: str) -> float:
    # Rounded as `Counts.as_dict` rounds: +5.0 points must not read 0.04999.
    return round(r["variant"][m] - r["base"][m], 4)


def gates(cmp: dict, train: dict | None) -> list[tuple[str, str, bool | None, str]]:
    """(gate, type, passed, detail); passed is None when an input is missing
    or is not the one the criteria name."""
    out: list[tuple[str, str, bool | None, str]] = []
    problems = list(cmp["config_problems"]) + ([] if cmp["split"] == "test" else [f"split {cmp['split']}"])
    out.append(("M0", "configuration", not problems, "; ".join(problems) or
                "same commit and settings, the lead off then on, test split"))
    missing = cmp["expected"] - cmp["documents"]
    out.append(("M0", "documents", missing <= MAX_LEFT_OUT,
                f"{cmp['documents']} of {cmp['expected']} scored in both runs"
                + (f"; left out: {', '.join(cmp['left_out'])}" if cmp["left_out"] else "")))
    types = cmp["types"]
    m = types[PRIMARY]
    bs = m.get("bootstrap", {}).get("precision")
    gain = _diff(m, "precision")
    low = bs["ci95"][0] if bs else 0.0
    out.append(("M1", PRIMARY, gain >= MIN_GAIN and low > 0,
                f"precision {m['base']['precision']:.3f} -> {m['variant']['precision']:.3f}, "
                f"{gain * 100:+.1f} points, interval low {low * 100:+.1f}"))
    net = len(m["lost_tp"]) - len(m["gained_tp"])
    out.append(("M2", PRIMARY, net <= MAX_NET_LOSS,
                f"lost {len(m['lost_tp'])}, gained {len(m['gained_tp'])}: {m['lost_tp']}"))
    out.append(("M3", PRIMARY, m["variant"]["f1"] >= m["base"]["f1"],
                f"F1 {m['base']['f1']:.3f} -> {m['variant']['f1']:.3f}"))
    a = types[ALSO_ACTED_ON]
    net_a = len(a["lost_tp"]) - len(a["gained_tp"])
    ok = net_a <= MAX_NET_LOSS and a["variant"]["f1"] >= a["base"]["f1"] and _diff(a, "precision") >= -MAX_DROP
    out.append(("M4a", ALSO_ACTED_ON, ok,
                f"lost {len(a['lost_tp'])}, gained {len(a['gained_tp'])}; F1 {a['base']['f1']:.3f} -> "
                f"{a['variant']['f1']:.3f}; precision {_diff(a, 'precision') * 100:+.1f} points"))
    for t in SCORED:
        if t in (PRIMARY, ALSO_ACTED_ON):
            continue
        r = types[t]
        dp, dr = _diff(r, "precision"), _diff(r, "recall")
        out.append(("M4b", t, dp >= -MAX_DROP and dr >= -MAX_DROP,
                    f"precision {dp * 100:+.1f}, recall {dr * 100:+.1f} points"))
    named = train is not None and (train.get("split"), train.get("expect"), train.get("base")) == \
        ("train", "off", "adr0088") and "malware" in train.get("variants", {})
    if train is None or not named:
        out.append(("M5", "train", None, "no train replay given" if train is None else
                    "not the train replay the criteria name (split train, --expect off --base adr0088 "
                    "--variants malware)"))
    else:
        v = train["variants"]["malware"]
        for t in (PRIMARY, ALSO_ACTED_ON):
            r = v[t]
            share = len(r["lost_tp"]) / r["base"]["tp"] if r["base"]["tp"] else 0.0
            out.append(("M5", f"{t} (train)", share <= MAX_TRAIN_LOSS,
                        f"lost {len(r['lost_tp'])} of {r['base']['tp']} true positives ({share:.1%})"))
    return out


def decision(rows: list[tuple[str, str, bool | None, str]]) -> str:
    """void when M0 fails (no decision on these runs); do not adopt as soon as
    a criterion fails; incomplete when an input is missing; adopt when every
    criterion passes."""
    if any(g == "M0" and p is not True for g, _, p, _ in rows):
        return "void"
    if any(p is False for _, _, p, _ in rows):
        return "do not adopt"
    if any(p is None for _, _, p, _ in rows):
        return "incomplete"
    return "adopt"


def cmd_gates(args) -> None:
    cmp = json.loads(Path(args.compare).read_text(encoding="utf-8"))
    train = json.loads(Path(args.train).read_text(encoding="utf-8")) if args.train else None
    rows = gates(cmp, train)
    for gate, t, passed, detail in rows:
        mark = "PASS" if passed else "n/a " if passed is None else "FAIL"
        print(f"{gate:<4} {mark} {t:<22} {detail}")
    verdict = decision(rows)
    print("decision:", verdict)
    sys.exit({"adopt": 0, "do not adopt": 1, "void": 2, "incomplete": 3}[verdict])


def main() -> None:
    global DATA
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", type=Path, default=DATA, help="the data/ folder holding the runs and AnnoCTR")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run")
    p.add_argument("--split", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--disable")
    p.add_argument("--allow-degraded", action="store_true")
    p.add_argument("--limit", type=int)
    p.add_argument("--allow-dirty", action="store_true", help="run from tracked files that differ from the commit")
    p.set_defaults(fn=cmd_run)
    p = sub.add_parser("status")
    p.add_argument("name")
    p.add_argument("--move-aside", action="store_true")
    p.set_defaults(fn=cmd_status)
    p = sub.add_parser("replay")
    p.add_argument("name")
    p.add_argument("--expect", required=True, choices=sorted(VARIANTS))
    p.add_argument("--base", choices=sorted(VARIANTS))
    p.add_argument("--variants", help="comma list of variants to score against --base")
    p.add_argument("--json")
    p.set_defaults(fn=cmd_replay)
    p = sub.add_parser("compare")
    p.add_argument("base")
    p.add_argument("candidate")
    p.add_argument("--json")
    p.set_defaults(fn=cmd_compare)
    p = sub.add_parser("gates")
    p.add_argument("compare")
    p.add_argument("--train")
    p.set_defaults(fn=cmd_gates)
    args = ap.parse_args()
    DATA = args.data
    args.fn(args)


if __name__ == "__main__":
    main()
