"""
TTP candidate retrieval (ADR-0072) — ranked ATT&CK candidates per passage.

Stage 2c's detector embeds a sentence, keeps its single best technique above a
cosine threshold and emits it as a technique.  On AnnoCTR dev that path is a
net loss (docs/eval/baseline-2026-09.md: switching it off lifts technique F1
from 0.339 to 0.488).  This module is the other half of retrieve-then-select
(ADR-0023 Phases 4-5): for every passage it returns a *ranked list* of
candidate techniques, and decides nothing.  A `TtpCandidate` is not a
technique — only the selector (Stage 3f in select mode,
`pipeline.stage3f_ttp_select`) can turn one into a TTP that ships.

Corpora (`kind` of an entry; built by `scripts/build_indexes.py --only retrieval`)
  description  a technique's name and full description ("Adversaries may…")
  procedure    the description of an ATT&CK `uses` relationship whose target is
               the technique ("APT28 has exploited CVE-2017-0262…"), written in
               the register of a report; one technique, many examples
  short        the legacy Stage 2c cache (name + first 300 characters), loaded
               from mitre_embeddings*.  What ships today; kept for comparison.

Retrievers
  dense        cosine between the passage and entry embeddings
  bm25         Okapi BM25 (k1 = 1.6, b = 0.75, the RCPO / TTP-R1 values)
  minrank      a technique's rank is min(dense rank, BM25 rank) (TTP-R1)
  rrf          reciprocal rank fusion, 1/(60 + rank) summed over both

Entries are grouped by technique before ranking: a technique scores its best
entry, so `k` counts distinct technique ids, never retrieved examples.  A
technique with 520 procedures (T1105) and one with 7 compete on one example
each.
"""
from __future__ import annotations

import functools
import hashlib
import json
import math
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from api.logging_config import get_logger
from pipeline.env_flags import env_bool, env_int
from pipeline.regex_safety import compile_pattern

logger = get_logger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
CORPUS_PATH = _DATA_DIR / "attack_retrieval_corpus.json"
EMBEDDINGS_PATH = _DATA_DIR / "attack_retrieval_embeddings.npy"

CORPORA = ("short", "description", "procedure", "both")
METHODS = ("dense", "bm25", "minrank", "rrf")

_BM25_K1 = 1.6
_BM25_B = 0.75
_RRF_K = 60


# ── Candidate contract ────────────────────────────────────────────────────────

class TtpCandidate(BaseModel):
    """A technique that MAY describe a passage — never exported as is.

    Built by retrieval, by the Stage 3 LLM's own proposals, or both; turned
    into a technique only by the selector, which must quote the passage.
    """
    attack_id: str
    name: str = ""
    passage: str = ""                  # the passage it was retrieved for / proposed in
    start: int | None = None           # offsets of `passage` in the text it was cut from
    end: int | None = None
    sources: list[str] = Field(default_factory=list)   # "dense", "bm25", "llm"
    dense_rank: int | None = None      # rank among techniques, 1 = best
    bm25_rank: int | None = None
    fused_rank: int | None = None
    dense_score: float | None = None
    bm25_score: float | None = None
    example: str = ""                  # the best corpus entry for this technique
    example_kind: str = ""             # "description" | "procedure" | "short"


# ── Passages with offsets ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class Passage:
    start: int
    end: int
    text: str


_NEWLINE_RUN = compile_pattern(r"[\r\n]+")
_BOUNDARY = compile_pattern(r"(?<=[.!?])\s+|\n+|;\s+")
_LIST_NUMBER = compile_pattern(r"^\d+[.)]\s")
_BULLETS = ("-", "*", "•", "–", "—")
_WS = compile_pattern(r"\s+")


def split_passages(text: str, *, unwrap: bool | None = None, min_chars: int = 21) -> list[Passage]:
    """Stage 2c's sentence split, keeping each sentence's offsets in `text`.

    Same decisions as `stage2c_ttp_semantic._split_candidate_sentences` (join a
    hard wrap unless the previous line ended a sentence or the next opens a list
    item; split on sentence punctuation, newlines and "; "), but a joined
    newline run is replaced by spaces of the same length instead of one space,
    so every passage keeps its position: an annotated mention or a quote can be
    placed in it.  Whitespace inside a passage's text is collapsed.
    """
    if not isinstance(text, str) or not text:
        return []
    if unwrap is None:
        unwrap = env_bool("TTP_UNWRAP_LINES", default=True)
    chars = list(text)
    for m in _NEWLINE_RUN.finditer(text):
        s, e = m.start(), m.end()
        if unwrap:
            prev = text[:s].rstrip(" \t")
            nxt = text[e:].lstrip(" \t")
            line_end = prev[-1] if prev else ""
            ends_sentence = line_end in ".!?:;" or line_end in "\r\n" or not line_end
            starts_list = nxt.startswith(_BULLETS) or bool(_LIST_NUMBER.match(nxt))
            if nxt and not nxt.startswith(("\r", "\n")) and not ends_sentence and not starts_list:
                chars[s:e] = " " * (e - s)
                continue
        chars[s:e] = "\n" * (e - s)
    norm = "".join(chars)
    out: list[Passage] = []
    pos = 0
    for m in [*_BOUNDARY.finditer(norm), None]:
        seg_end = m.start() if m is not None else len(norm)
        seg = norm[pos:seg_end]
        lead = len(seg) - len(seg.lstrip())
        body = seg.strip()
        if len(body) >= min_chars:
            start = pos + lead
            out.append(Passage(start, start + len(body), _WS.sub(" ", body)))
        if m is not None:
            pos = m.end()
    return out


def gate_passages(passages: Sequence[Passage], *, keyword_gate: bool | None = None) -> list[Passage]:
    """Stage 2c's sentence gates (keyword allow-list, advisory sentences).

    `keyword_gate` overrides TTP_KEYWORD_GATE for a measurement; None follows it.
    """
    from pipeline import stage2c_ttp_semantic as s2c

    if keyword_gate is None:
        keyword_gate = s2c._keyword_gate_enabled()
    out = []
    for p in passages:
        if keyword_gate and not any(kw in p.text.lower() for kw in s2c._TTP_KEYWORDS):
            continue
        if s2c._is_advisory_noise(p.text):
            continue
        out.append(p)
    return out


# ── ATT&CK text cleaning (used by the corpus build) ───────────────────────────

_MD_LINK = compile_pattern(r"\[([^\]]{1,200})\]\((https?://attack\.mitre\.org/([a-z]+)/[^)\s]{0,200})\)")
_CITATION = compile_pattern(r"\(Citation:[^)]{0,300}\)")
_CODE_TAG = compile_pattern(r"</?code>")
_HTML_TAG = compile_pattern(r"<[^>]{1,100}>")

# The placeholder a neutralised ATT&CK link becomes, by the link's section.
_PLACEHOLDER = {"groups": "the threat actor", "software": "the software",
                "campaigns": "the campaign"}


def clean_attack_text(text: str, *, neutral_names: Iterable[str] = (), neutralise: bool = False) -> str:
    """ATT&CK prose as plain text: links to their label, citations and tags removed.

    With `neutralise`, a link to a group, software or campaign page becomes a
    generic placeholder and every name in `neutral_names` (the procedure's
    source object and its aliases) is replaced the same way.  Procedure
    examples name the actor or the malware in nearly every sentence; a report
    naming the same actor would match on the name, not on the behaviour.
    """
    if not isinstance(text, str):
        return ""

    def link(m: re.Match) -> str:
        if neutralise and m.group(3) in _PLACEHOLDER:
            return _PLACEHOLDER[m.group(3)]
        return m.group(1)

    out = _MD_LINK.sub(link, text)
    out = _CITATION.sub("", out)
    out = _CODE_TAG.sub("", out)
    out = _HTML_TAG.sub(" ", out)
    if neutralise:
        for name in sorted({n for n in neutral_names if n and len(n) >= 3}, key=len, reverse=True):
            out = re.sub(rf"(?<![\w-]){re.escape(name)}(?![\w-])", "the software", out)
    out = _WS.sub(" ", out).strip()
    if neutralise and out[:1].islower():
        out = out[0].upper() + out[1:]
    return out


def _dedup_key(attack_id: str, text: str) -> str:
    return attack_id + "|" + re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id")
    return None


def build_corpus_entries(objects: list[dict], domain: str, *, neutralise: bool = False) -> list[dict]:
    """Retrieval entries of one ATT&CK bundle: one per active technique
    (`description`) and one per distinct `uses` example (`procedure`).

    A procedure is kept when the relationship and both ends are active and the
    target is a technique.  Two examples of the same technique that read the
    same once cleaned (and, with `neutralise`, stripped of names) are one
    entry.  Every procedure keeps the URLs it cites, so an evaluation can drop
    the examples MITRE wrote from a report it scores (`exclude_cited`).
    """
    by_id = {o["id"]: o for o in objects if "id" in o}

    def active(o: dict) -> bool:
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    entries: list[dict] = []
    seen: set[str] = set()
    for o in objects:
        if o.get("type") != "attack-pattern" or not active(o):
            continue
        tid = _external_id(o)
        if not tid or not tid.startswith("T"):
            continue
        desc = clean_attack_text(o.get("description", ""))
        text = f"{o.get('name', '')}. {desc}" if desc else o.get("name", "")
        entries.append({"id": tid, "name": o.get("name", ""), "kind": "description",
                        "domain": domain, "text": text, "source": "", "ref": o["id"], "urls": []})
        seen.add(_dedup_key(tid, text))

    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        if not active(rel) or not rel.get("description"):
            continue
        src, tgt = by_id.get(rel.get("source_ref", "")), by_id.get(rel.get("target_ref", ""))
        if src is None or tgt is None or not (active(src) and active(tgt)):
            continue
        if tgt.get("type") != "attack-pattern":
            continue
        tid = _external_id(tgt)
        if not tid or not tid.startswith("T"):
            continue
        names = [src.get("name", "")] + list(src.get("aliases") or src.get("x_mitre_aliases") or [])
        text = clean_attack_text(rel["description"], neutral_names=names, neutralise=neutralise)
        if len(text) < 20:
            continue
        key = _dedup_key(tid, text)
        if key in seen:
            continue
        seen.add(key)
        urls = sorted({r["url"] for r in rel.get("external_references", []) or [] if r.get("url")})
        entries.append({"id": tid, "name": tgt.get("name", ""), "kind": "procedure",
                        "domain": domain, "text": text, "source": _external_id(src) or "",
                        "ref": rel["id"], "urls": urls})
    return entries


# ── BM25 ──────────────────────────────────────────────────────────────────────

_TOKEN = compile_pattern(r"[a-z0-9]+")
_STOPWORDS = frozenset("""
a about after all also an and any are as at be been before being but by can could did do does
during each for from had has have he her his how if in into is it its may more most no not of on
once one only or other our out over own same she should so some such than that the their them then
there these they this those through to too under until up very was we were what when where which
while who why will with would you your
""".split())


def _stem(tok: str) -> str:
    """A crude suffix strip: "downloads", "downloaded", "downloading" -> "download"."""
    for suf in ("ing", "ed", "es", "s"):
        if tok.endswith(suf) and len(tok) - len(suf) >= 4:
            return tok[: -len(suf)]
    return tok


def tokenize(text: str) -> list[str]:
    return [_stem(t) for t in _TOKEN.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]


class BM25:
    """Okapi BM25 over a fixed corpus, scored for many queries at once.

    Postings carry their precomputed term weight, so a query is one vectorised
    add per distinct query token.
    """

    def __init__(self, docs: Sequence[str], k1: float = _BM25_K1, b: float = _BM25_B) -> None:
        import numpy as np

        toks = [tokenize(d) for d in docs]
        self.n = len(toks)
        lens = np.array([len(t) for t in toks], dtype=np.float64)
        avgdl = float(lens.mean()) if self.n else 0.0
        df: dict[str, int] = {}
        tfs: list[dict[str, int]] = []
        for t in toks:
            tf: dict[str, int] = {}
            for w in t:
                tf[w] = tf.get(w, 0) + 1
            tfs.append(tf)
            for w in tf:
                df[w] = df.get(w, 0) + 1
        rows: dict[str, tuple[list[int], list[float]]] = {}
        for i, tf in enumerate(tfs):
            norm = k1 * (1 - b + b * (lens[i] / avgdl if avgdl else 0.0))
            for w, f in tf.items():
                idf = math.log(1 + (self.n - df[w] + 0.5) / (df[w] + 0.5))
                r = rows.setdefault(w, ([], []))
                r[0].append(i)
                r[1].append(idf * f * (k1 + 1) / (f + norm))
        self.postings = {w: (np.array(ix, dtype=np.int64), np.array(ws, dtype=np.float32))
                         for w, (ix, ws) in rows.items()}

    def scores(self, queries: Sequence[str]):
        """(len(queries), n) score matrix."""
        import numpy as np

        out = np.zeros((len(queries), self.n), dtype=np.float32)
        for qi, q in enumerate(queries):
            for w in set(tokenize(q)):
                post = self.postings.get(w)
                if post is not None:
                    out[qi, post[0]] += post[1]
        return out


# ── Corpus ────────────────────────────────────────────────────────────────────

@dataclass
class Corpus:
    """Entries sorted by technique id, with their embeddings (or None)."""
    ids: list[str]
    names: list[str]
    kinds: list[str]
    domains: list[str]
    texts: list[str]
    urls: list[list[str]]
    embeddings: Any                   # numpy (N, D) or None
    model: str
    version: str                      # ties a cache or a result to its corpus

    def select(self, keep: list[int]) -> Corpus:
        emb = self.embeddings[keep] if self.embeddings is not None else None
        return Corpus([self.ids[i] for i in keep], [self.names[i] for i in keep],
                      [self.kinds[i] for i in keep], [self.domains[i] for i in keep],
                      [self.texts[i] for i in keep], [self.urls[i] for i in keep],
                      emb, self.model, self.version)


def _short_corpus() -> Corpus | None:
    """The legacy Stage 2c cache: what ships today."""
    from pipeline import mitre_db
    from pipeline import stage2c_ttp_semantic as s2c

    loaded = s2c._load_corpus()
    if loaded is None:
        return None
    emb, meta = loaded
    by_id = {t["id"]: t for t in mitre_db.get_techniques()}
    texts = []
    for m in meta:
        t = by_id.get(m["id"], {})
        desc = (t.get("description") or "").strip()
        texts.append(f"{m['name']}. {desc}" if desc else m["name"])
    return Corpus([m["id"] for m in meta], [m["name"] for m in meta], ["short"] * len(meta),
                  [m.get("domain", "") for m in meta], texts, [[] for _ in meta], emb,
                  s2c._TTP_EMBEDDING_MODEL, "short")


@functools.lru_cache(maxsize=4)
def _built_corpus(path: str, emb_path: str) -> Corpus | None:
    p, ep = Path(path), Path(emb_path)
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    manifest = data.get("manifest", {})
    embeddings = None
    if ep.exists():
        import numpy as np
        embeddings = np.load(str(ep))
        if embeddings.shape[0] != len(entries):
            logger.warning("Retrieval embeddings do not match the corpus (%d vs %d) — "
                           "rebuild: python scripts/build_indexes.py --only retrieval",
                           embeddings.shape[0], len(entries))
            embeddings = None
    return Corpus([e["id"] for e in entries], [e.get("name", "") for e in entries],
                  [e["kind"] for e in entries], [e.get("domain", "") for e in entries],
                  [e["text"] for e in entries], [e.get("urls", []) for e in entries],
                  embeddings, manifest.get("model", ""), manifest.get("version", ""))


def load_corpus(kind: str = "both", *, path: Path | None = None, emb_path: Path | None = None,
                exclude_cited: Iterable[str] = ()) -> Corpus | None:
    """The retrieval corpus of `kind` (one of CORPORA), restricted to the
    enabled domains, sorted by technique, without the entries citing a URL
    that contains one of `exclude_cited`."""
    if kind not in CORPORA:
        raise ValueError(f"corpus must be one of {CORPORA}, not {kind!r}")
    if kind == "short":
        corpus = _short_corpus()
    else:
        corpus = _built_corpus(str(path or CORPUS_PATH), str(emb_path or EMBEDDINGS_PATH))
    if corpus is None:
        return None
    from pipeline.stage2c_ttp_semantic import _enabled_domains

    domains = _enabled_domains()
    excl = [s.lower() for s in exclude_cited if s]
    keep = []
    for i, k in enumerate(corpus.kinds):
        if kind in ("description", "procedure") and k != kind:
            continue
        if domains is not None and corpus.domains[i] not in domains:
            continue
        if excl and any(s in u.lower() for u in corpus.urls[i] for s in excl):
            continue
        keep.append(i)
    keep.sort(key=lambda i: corpus.ids[i])
    out = corpus.select(keep)
    if kind != "short":
        out.version = f"{corpus.version}:{kind}" + (
            f":excl-{hashlib.sha256(chr(10).join(sorted(excl)).encode()).hexdigest()[:8]}" if excl else "")
    return out


# ── Retriever ─────────────────────────────────────────────────────────────────

def _ranks_desc(scores):
    """1-based rank of every column by descending score, row by row (ties by column)."""
    import numpy as np

    order = np.argsort(-scores, axis=1, kind="stable")
    ranks = np.empty_like(order)
    rows = np.arange(scores.shape[0])[:, None]
    ranks[rows, order] = np.arange(1, scores.shape[1] + 1)
    return ranks


class Retriever:
    """Ranks ATT&CK techniques for passages: dense, BM25 or both fused."""

    def __init__(self, corpus: Corpus, method: str = "minrank", model=None) -> None:
        import numpy as np

        if method not in METHODS:
            raise ValueError(f"method must be one of {METHODS}, not {method!r}")
        if method != "bm25" and (corpus.embeddings is None or model is None):
            raise ValueError(f"method {method!r} needs embeddings and an encoder")
        self.corpus, self.method, self.model = corpus, method, model
        # Entries are sorted by id: one contiguous block per technique.
        self.tech_ids: list[str] = []
        starts: list[int] = []
        for i, tid in enumerate(corpus.ids):
            if not self.tech_ids or self.tech_ids[-1] != tid:
                self.tech_ids.append(tid)
                starts.append(i)
        self._starts = np.array(starts, dtype=np.int64)
        self._bm25 = BM25(corpus.texts) if method != "dense" else None
        self._names = {tid: name for tid, name in zip(corpus.ids, corpus.names) if name}

    def _group(self, entry_scores):
        """(per-technique best score, index of the best entry) over each block."""
        import numpy as np

        best = np.maximum.reduceat(entry_scores, self._starts, axis=1)
        # argmax within each block: offset of the first entry equal to the max
        n_tech = len(self._starts)
        ends = np.append(self._starts[1:], entry_scores.shape[1])
        arg = np.empty((entry_scores.shape[0], n_tech), dtype=np.int64)
        for j in range(n_tech):
            s, e = self._starts[j], ends[j]
            arg[:, j] = s + np.argmax(entry_scores[:, s:e], axis=1)
        return best, arg

    def rank(self, passages: Sequence[Passage | str], k: int = 10) -> list[list[TtpCandidate]]:
        """Top-`k` candidate techniques for each passage, best first."""
        import numpy as np

        texts = [p.text if isinstance(p, Passage) else p for p in passages]
        if not texts or not self.tech_ids:
            return [[] for _ in texts]
        k = max(1, min(k, len(self.tech_ids)))
        dense_best: Any = None
        dense_arg: Any = None
        dense_rank: Any = None
        bm_best: Any = None
        bm_arg: Any = None
        bm_rank: Any = None
        if self.method != "bm25":
            from sentence_transformers import util

            q = self.model.encode(texts, batch_size=32, convert_to_numpy=True, show_progress_bar=False)
            entry = util.cos_sim(q, self.corpus.embeddings).numpy()
            dense_best, dense_arg = self._group(entry)
            dense_rank = _ranks_desc(dense_best)
        if self._bm25 is not None:
            entry = self._bm25.scores(texts)
            bm_best, bm_arg = self._group(entry)
            bm_rank = _ranks_desc(bm_best)
            # A technique sharing no token with the passage has no BM25 rank.
            bm_rank = np.where(bm_best > 0, bm_rank, np.iinfo(np.int64).max // 4)

        if self.method == "dense":
            key = dense_rank.astype(np.float64)
        elif self.method == "bm25":
            key = bm_rank.astype(np.float64)
        elif self.method == "minrank":
            n = len(self.tech_ids)
            lo = np.minimum(dense_rank, bm_rank).astype(np.float64)
            hi = np.minimum(np.maximum(dense_rank, bm_rank), n + 1).astype(np.float64)
            key = lo + hi / (n + 2.0)          # a tie on the best rank goes to the other rank
        else:  # rrf
            key = -(1.0 / (_RRF_K + dense_rank) + 1.0 / (_RRF_K + np.minimum(bm_rank, 10**9)))
        order = np.argsort(key, axis=1, kind="stable")[:, :k]

        out: list[list[TtpCandidate]] = []
        for pi, p in enumerate(passages):
            row = []
            for fused, j in enumerate(order[pi], start=1):
                tid = self.tech_ids[j]
                d_r = int(dense_rank[pi, j]) if dense_rank is not None else None
                b_ok = bm_best is not None and bm_best[pi, j] > 0
                b_r = int(bm_rank[pi, j]) if b_ok else None
                # The example shown is the one that ranked it: the better of the two.
                use_bm = dense_arg is None or (b_ok and (b_r is not None and d_r is not None and b_r < d_r))
                ex = int(bm_arg[pi, j]) if use_bm else int(dense_arg[pi, j])
                sources = [s for s, r in (("dense", d_r), ("bm25", b_r)) if r is not None and r <= k]
                row.append(TtpCandidate(
                    attack_id=tid, name=self._names.get(tid, ""),
                    passage=texts[pi],
                    start=p.start if isinstance(p, Passage) else None,
                    end=p.end if isinstance(p, Passage) else None,
                    sources=sources or [self.method],
                    dense_rank=d_r, bm25_rank=b_r, fused_rank=fused,
                    dense_score=round(float(dense_best[pi, j]), 4) if dense_best is not None else None,
                    bm25_score=round(float(bm_best[pi, j]), 3) if b_ok else None,
                    example=self.corpus.texts[ex][:400], example_kind=self.corpus.kinds[ex],
                ))
            out.append(row)
        return out


# ── Production configuration ─────────────────────────────────────────────────

def retrieval_settings() -> dict:
    """What the select path retrieves with — part of the run's fingerprint."""
    return {
        "corpus": os.getenv("TTP_RETRIEVAL_CORPUS", "both").strip().lower(),
        "method": os.getenv("TTP_RETRIEVAL_METHOD", "rrf").strip().lower(),
        # Measured on AnnoCTR dev (ADR-0072): 10 per passage, 40 per chunk
        # finds 86% of the gold techniques in the list of a chunk carrying
        # their mention, with 21 candidates per chunk on average.
        "k_per_passage": env_int("TTP_CANDIDATES_PER_PASSAGE", default=10),
        "max_per_chunk": env_int("TTP_CANDIDATES_PER_CHUNK", default=40),
        # The keyword allow-list drops the passage of 36% of the annotated
        # mentions, yet under the per-chunk cap it is as good or better: the
        # cap's budget goes to behaviour sentences (ADR-0072).  Its own switch,
        # so the select path can be measured apart from Stage 2c's.
        "keyword_gate": env_bool("TTP_RETRIEVAL_KEYWORD_GATE", default=True),
        "exclude_cited": os.getenv("TTP_RETRIEVAL_EXCLUDE_CITED", "").strip(),
    }


def _exclusions(path: str) -> list[str]:
    if not path:
        return []
    try:
        return [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError:
        logger.warning("TTP_RETRIEVAL_EXCLUDE_CITED=%s cannot be read — nothing excluded", path)
        return []


@functools.lru_cache(maxsize=2)
def _production_retriever(corpus: str, method: str, exclude_cited: str) -> Retriever | None:
    from pipeline import stage2c_ttp_semantic as s2c

    c = load_corpus(corpus, exclude_cited=_exclusions(exclude_cited))
    if c is None:
        logger.warning("Retrieval corpus %r unavailable — build it: "
                       "python scripts/build_indexes.py --only retrieval", corpus)
        return None
    model = None
    if method != "bm25":
        model = s2c._load_model()
        if model is None or c.embeddings is None:
            logger.warning("Dense retrieval unavailable (encoder or embeddings missing)")
            return None
        if corpus != "short" and c.model and c.model != s2c._TTP_EMBEDDING_MODEL:
            logger.warning("Retrieval embeddings built with %r, TTP_EMBEDDING_MODEL is %r — "
                           "rebuild: python scripts/build_indexes.py --only retrieval",
                           c.model, s2c._TTP_EMBEDDING_MODEL)
            return None
    return Retriever(c, method, model)


def retrieval_available() -> bool:
    s = retrieval_settings()
    if s["corpus"] not in CORPORA or s["method"] not in METHODS:
        return False
    if s["method"] != "bm25" and env_bool("SKIP_HEAVY_MODELS"):
        return False
    return _production_retriever(s["corpus"], s["method"], s["exclude_cited"]) is not None


def candidates_for_chunks(chunks: Sequence[str]) -> list[list[TtpCandidate]]:
    """The candidates of every chunk, for the selector, with the production
    settings (`retrieval_settings`).  Empty lists when retrieval is off."""
    s = retrieval_settings()
    retriever = _production_retriever(s["corpus"], s["method"], s["exclude_cited"])
    if retriever is None:
        return [[] for _ in chunks]
    return chunk_candidates_with(retriever, chunks, k_per_passage=s["k_per_passage"],
                                 max_per_chunk=s["max_per_chunk"], keyword_gate=s["keyword_gate"])


def chunk_candidates_with(retriever: Retriever, chunks: Sequence[str], *, k_per_passage: int,
                          max_per_chunk: int | None, keyword_gate: bool | None = None,
                          ) -> list[list[TtpCandidate]]:
    """Each gated passage's top `k_per_passage` techniques, merged per
    technique within its chunk (best fused rank wins), at most `max_per_chunk`
    per chunk.

    Passages are cut per chunk, so a sentence in the 400-character overlap of
    two chunks is retrieved for both — the merge of chunk results dedups.
    """
    per_chunk = [gate_passages(split_passages(c), keyword_gate=keyword_gate) for c in chunks]
    flat = [p for ps in per_chunk for p in ps]
    ranked = retriever.rank(flat, k=max(1, k_per_passage)) if flat else []
    out: list[list[TtpCandidate]] = []
    pos = 0
    for ps in per_chunk:
        rows = ranked[pos:pos + len(ps)]
        pos += len(ps)
        out.append(merge_by_technique([c for row in rows for c in row], max_per_chunk or None))
    return out


def merge_by_technique(cands: Iterable[TtpCandidate], limit: int | None = None) -> list[TtpCandidate]:
    """One candidate per technique id — the best-ranked one, carrying the union
    of the sources — ordered by fused rank, then dense rank; at most `limit`."""
    best: dict[str, TtpCandidate] = {}
    for c in cands:
        key = c.attack_id.upper()
        inc = best.get(key)
        if inc is None:
            best[key] = c.model_copy()
            continue
        merged = sorted(set(inc.sources) | set(c.sources))
        if (c.fused_rank or 10**9, c.dense_rank or 10**9) < (inc.fused_rank or 10**9, inc.dense_rank or 10**9):
            best[key] = c.model_copy(update={"sources": merged})
        else:
            inc.sources = merged
    ordered = sorted(best.values(), key=lambda c: (c.fused_rank or 10**9, c.dense_rank or 10**9, c.attack_id))
    return ordered[:limit] if limit else ordered
