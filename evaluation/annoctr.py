"""AnnoCTR (Lange et al., LREC-COLING 2024) as gold data.

What the corpus can and cannot measure — read before using a number from it:

* 400 reports from five vendor blogs (Intel471, Lab52, Proofpoint,
  QuoIntelligence, Zscaler).  Only **120** carry the cybersecurity layer
  (ATT&CK techniques and tactics, explicit and implicit; malware, groups,
  tools): 70 train / 16 dev / 34 test.  The other 280 (in `all/`, outside the
  three splits) carry the general layer only — they are NOT reports without
  techniques and are never scored for TTPs.  (The repository's `train_ext`
  directories hold the same 70 train documents, not those 280.)
* The official split is temporal and puts every vendor in every split (§5.1).
  It is kept as is; a vendor-held-out split would be another protocol, reported
  separately.
* No IoCs and no relationships are annotated.  Those are measured on the
  in-house set (docs/eval/annotation-guide.md).
* The texts are the blog posts converted to Markdown: this measures reading the
  text, not ingesting a PDF.
* Mentions come with their context, not offsets; `locate_mentions` finds them
  back in the text (the unlocated ones are counted, not dropped silently).

Data: CC-BY-SA 4.0 — cloned into data/ (git-ignored), never committed here.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

REPO_URL = "https://github.com/boschresearch/anno-ctr-lrec-coling-2024"
DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "data" / "annoctr-repo" / "AnnoCTR"

SPLITS = ("train", "dev", "test")
GENERAL_ONLY = "general_only"     # pseudo-split: the 280 documents outside the three splits

# AnnoCTR type -> CTIParsor EntityType value, for the types both sides mean the
# same way.  ORG and CON (cybersecurity concepts) have no counterpart and are
# not scored; SECTOR maps to `identity`, which is what the pipeline emits for a
# targeted sector.
ENTITY_TYPE_MAP: dict[str, str] = {
    "MALWARE": "malware",
    "GROUP": "threat_actor",
    "TOOL": "tool",
    "LOC": "location",
    "SECTOR": "identity",
}

_TECHNIQUE_URL = re.compile(r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?", re.I)
_TACTIC_URL = re.compile(r"attack\.mitre\.org/tactics/(TA\d{4})", re.I)


@dataclass
class Mention:
    label: str            # T-ID for a technique, canonical name for an entity
    surface: str          # the annotated text
    kind: str             # "explicit" (CE) or "implicit" (CI)
    start: int | None = None   # offset in the document text, when found
    end: int | None = None
    context_left: str = ""
    context_right: str = ""


@dataclass
class GoldEntity:
    etype: str                      # CTIParsor EntityType value
    label: str                      # canonical name (AnnoCTR's link title)
    surfaces: set[str] = field(default_factory=set)


@dataclass
class AnnoctrDoc:
    doc_id: str
    split: str
    vendor: str
    date: str
    text: str
    layers: frozenset[str]          # {"general"} or {"general", "cyber"}
    techniques: list[Mention] = field(default_factory=list)
    tactics: list[Mention] = field(default_factory=list)
    entities: dict[str, GoldEntity] = field(default_factory=dict)   # key: etype|label

    @property
    def technique_ids(self) -> set[str]:
        return {m.label for m in self.techniques}

    def technique_kinds(self) -> dict[str, set[str]]:
        """T-ID -> {"explicit", "implicit"} as annotated in this document."""
        kinds: dict[str, set[str]] = {}
        for m in self.techniques:
            kinds.setdefault(m.label, set()).add(m.kind)
        return kinds

    def evaluable(self) -> dict:
        """What this document can score (the annotated-layer registry)."""
        cyber = "cyber" in self.layers
        types = sorted({v for k, v in ENTITY_TYPE_MAP.items()
                        if cyber or k in ("LOC", "SECTOR")})
        return {"ttp": cyber, "entity_types": types, "iocs": False, "relations": False}


def technique_id_from_url(url: str) -> str | None:
    m = _TECHNIQUE_URL.search(url or "")
    if not m:
        return None
    return f"{m.group(1).upper()}.{m.group(2)}" if m.group(2) else m.group(1).upper()


def _vendor_date(doc_id: str) -> tuple[str, str]:
    parts = doc_id.split("_", 2)
    return (parts[0], parts[1]) if len(parts) >= 2 else (doc_id, "")


def locate_mentions(text: str, mentions: list[Mention]) -> int:
    """Set start/end on each mention from its left/right context.  Returns how
    many could not be found."""
    missing = 0
    cursor: dict[str, int] = {}
    for m in mentions:
        if not m.surface:
            missing += 1
            continue
        probes = [
            (m.context_left[-60:] + m.surface + m.context_right[:60], len(m.context_left[-60:])),
            (m.context_left[-25:] + m.surface, len(m.context_left[-25:])),
            (m.surface, 0),
        ]
        found = None
        for probe, shift in probes:
            if not probe.strip():
                continue
            i = text.find(probe, cursor.get(probe, 0))
            if i < 0:
                i = text.find(probe)
            if i >= 0:
                found = i + shift
                cursor[probe] = i + 1
                break
        if found is None:
            missing += 1
        else:
            m.start, m.end = found, found + len(m.surface)
    return missing


def load(root: Path = DEFAULT_ROOT, splits: tuple[str, ...] = SPLITS,
         include_general_only: bool = False) -> list[AnnoctrDoc]:
    """Load the documents of `splits` with their annotations.

    Techniques, tactics, malware, groups and tools come from
    `linking_mitre_only/<split>.jsonl`; locations and sectors from the general
    layer's BIO tags in `ner_json/<split>.json`.
    """
    if not root.is_dir():
        raise FileNotFoundError(
            f"AnnoCTR not found at {root}. Clone it first:\n"
            f"  git clone --depth 1 {REPO_URL} {root.parent}"
        )
    docs: dict[str, AnnoctrDoc] = {}
    for split in splits:
        for path in sorted((root / "text" / split).glob("*.txt")):
            doc_id = path.stem
            vendor, date = _vendor_date(doc_id)
            docs[doc_id] = AnnoctrDoc(doc_id, split, vendor, date,
                                      path.read_text(encoding="utf-8"),
                                      frozenset({"general", "cyber"}))

        link_file = root / "linking_mitre_only" / f"{split}.jsonl"
        if link_file.exists():
            for line in link_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                doc = docs.get(r.get("document", ""))
                if doc is None:
                    continue
                kind = "explicit" if r.get("entity_class") == "CE" else "implicit"
                etype = r.get("entity_type", "")
                mention = Mention(label="", surface=r.get("mention", ""), kind=kind,
                                  context_left=r.get("_context_left", ""),
                                  context_right=r.get("_context_right", ""))
                if etype == "TECHNIQUE":
                    tid = technique_id_from_url(r.get("label_link", ""))
                    if tid:
                        mention.label = tid
                        doc.techniques.append(mention)
                elif etype == "TACTIC":
                    m = _TACTIC_URL.search(r.get("label_link", ""))
                    if m:
                        mention.label = m.group(1).upper()
                        doc.tactics.append(mention)
                elif etype in ENTITY_TYPE_MAP:
                    _add_entity(doc, ENTITY_TYPE_MAP[etype], r.get("label_title") or mention.surface,
                                mention.surface)

        ner_file = root / "ner_json" / f"{split}.json"
        if ner_file.exists():
            for line in ner_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                doc = docs.get(r.get("id", "").rsplit("__", 1)[0])
                if doc is None:
                    continue
                for etype_src, surface in _bio_spans(r.get("tokens", []), r.get("ne_tags", [])):
                    if etype_src in ("LOC", "SECTOR"):
                        _add_entity(doc, ENTITY_TYPE_MAP[etype_src], surface, surface)

    if include_general_only:
        cyber_ids = set(docs)
        for path in sorted((root / "all" / "text").glob("*.txt")):
            if path.stem in cyber_ids:
                continue
            vendor, date = _vendor_date(path.stem)
            doc = docs[path.stem] = AnnoctrDoc(path.stem, GENERAL_ONLY, vendor, date,
                                               path.read_text(encoding="utf-8"),
                                               frozenset({"general"}))
            ner = root / "all" / "ner_json" / f"{path.stem}.json"
            if ner.exists():
                for line in ner.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        r = json.loads(line)
                        for etype_src, surface in _bio_spans(r.get("tokens", []), r.get("ne_tags", [])):
                            if etype_src in ("LOC", "SECTOR"):
                                _add_entity(doc, ENTITY_TYPE_MAP[etype_src], surface, surface)

    for doc in docs.values():
        locate_mentions(doc.text, doc.techniques)
    return list(docs.values())


def _add_entity(doc: AnnoctrDoc, etype: str, label: str, surface: str) -> None:
    key = f"{etype}|{label.lower()}"
    ent = doc.entities.setdefault(key, GoldEntity(etype, label))
    if surface:
        ent.surfaces.add(surface)


def _bio_spans(tokens: list[str], tags: list[str]) -> list[tuple[str, str]]:
    spans: list[tuple[str, str]] = []
    cur_type, cur_tokens = None, []
    for tok, tag in zip(tokens, tags):
        if tag.startswith("B-") or (tag.startswith("I-") and tag[2:] != cur_type):
            if cur_type:
                spans.append((cur_type, " ".join(cur_tokens)))
            cur_type, cur_tokens = tag[2:], [tok]
        elif tag.startswith("I-"):
            cur_tokens.append(tok)
        else:
            if cur_type:
                spans.append((cur_type, " ".join(cur_tokens)))
            cur_type, cur_tokens = None, []
    if cur_type:
        spans.append((cur_type, " ".join(cur_tokens)))
    return spans


def registry(docs: list[AnnoctrDoc]) -> list[dict]:
    """One row per document: split, vendor, date, annotated layers, what can
    be scored, and how many technique mentions could be located."""
    rows = []
    for d in docs:
        rows.append({
            "doc_id": d.doc_id, "split": d.split, "vendor": d.vendor, "date": d.date,
            "layers": sorted(d.layers), "evaluable": d.evaluable(),
            "chars": len(d.text), "techniques": len(d.technique_ids),
            "technique_mentions": len(d.techniques),
            "unlocated_mentions": sum(1 for m in d.techniques if m.start is None),
        })
    return rows
