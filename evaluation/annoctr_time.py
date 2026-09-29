"""AnnoCTR's TimeML layer, scored against pipeline.temporal's normaliser (ADR-0063 §11).

AnnoCTR ships `time/<split>/*.tml`: every date expression of a report wrapped
in a TIMEX3 tag with its normalised value, and the document creation time
(DCT).  It measures one thing CTIParsor does -- reading an expression into a
value at the right granularity, relative expressions resolved against a given
anchor -- and nothing about the rest (the anchor's recovery from a file, the
role of a date, the claim it belongs to, the export).

The DCT is the anchor, as a publication date: that is how TimeML annotates
it.  Some tags are shifted by one character (``i<TIMEX3>n 2019.</TIMEX3>``);
a gold span that does not read is retried one character wider or narrower,
and both scores are reported.

Tuning uses train + dev; test is read once per frozen normaliser (ADR-0060).

    python -m evaluation.annoctr_time [--splits train dev] [--errors 20]
"""
from __future__ import annotations

import argparse
import html
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pipeline.temporal import Anchor, normalize

DEFAULT_ROOT = Path(__file__).resolve().parent.parent / "data" / "annoctr-repo" / "AnnoCTR" / "time"
SPLITS = ("train", "dev", "test")

_DCT = re.compile(r'<DCT>\s*<TIMEX3[^>]*value="([^"]+)"', re.S)
_TEXT = re.compile(r"<TEXT>(.*)</TEXT>", re.S)
_TIMEX = re.compile(r"<TIMEX3([^>]*)>(.*?)</TIMEX3>", re.S)
_ATTR = re.compile(r'(\w+)="([^"]*)"')


@dataclass
class Timex:
    text: str
    value: str
    type: str
    start: int          # offset in the document's flat text
    end: int


@dataclass
class TimeDoc:
    doc_id: str
    split: str
    dct: str
    text: str
    timexes: list[Timex] = field(default_factory=list)


def parse_tml(raw: str, doc_id: str = "", split: str = "") -> TimeDoc | None:
    """One .tml file: its DCT, its flat text, its in-text TIMEX3s with offsets."""
    dct_m, text_m = _DCT.search(raw), _TEXT.search(raw)
    if not dct_m or not text_m:
        return None
    body = text_m.group(1)
    flat: list[str] = []
    length = 0
    timexes: list[Timex] = []
    pos = 0
    for m in _TIMEX.finditer(body):
        before = html.unescape(re.sub(r"<[^>]+>", "", body[pos:m.start()]))
        flat.append(before)
        length += len(before)
        inner = html.unescape(re.sub(r"<[^>]+>", "", m.group(2)))
        attrs = dict(_ATTR.findall(m.group(1)))
        timexes.append(Timex(text=inner, value=attrs.get("value", ""), type=attrs.get("type", ""),
                             start=length, end=length + len(inner)))
        flat.append(inner)
        length += len(inner)
        pos = m.end()
    flat.append(html.unescape(re.sub(r"<[^>]+>", "", body[pos:])))
    return TimeDoc(doc_id=doc_id, split=split, dct=dct_m.group(1)[:10], text="".join(flat),
                   timexes=timexes)


def load(root: Path = DEFAULT_ROOT, splits: tuple[str, ...] = ("train", "dev")) -> list[TimeDoc]:
    docs: list[TimeDoc] = []
    for split in splits:
        for path in sorted((root / split).glob("*.tml")):
            doc = parse_tml(path.read_text(encoding="utf-8", errors="replace"), path.stem, split)
            if doc is not None:
                docs.append(doc)
    return docs


def granularity(value: str) -> str:
    """TimeML value -> the precision word pipeline.temporal uses."""
    if re.fullmatch(r"\d{4}", value):
        return "year"
    if re.fullmatch(r"\d{4}-\d{2}", value):
        return "month"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return "day"
    if re.fullmatch(r"\d{4}-Q[1-4]", value):
        return "quarter"
    if re.fullmatch(r"\d{4}-H[12]", value):
        return "half"
    return "other"


def _as_timeml(value: str | None) -> str | None:
    """pipeline.temporal's EDTF codes written the TimeML way, for comparison."""
    if value is None:
        return None
    m = re.fullmatch(r"(\d{4})-(3[3-6])", value)
    if m:
        return f"{m.group(1)}-Q{int(m.group(2)) - 32}"
    m = re.fullmatch(r"(\d{4})-(4[01])", value)
    if m:
        return f"{m.group(1)}-H{int(m.group(2)) - 39}"
    return value


def _variants(doc: TimeDoc, t: Timex) -> list[str]:
    """The gold span, then one character wider or narrower on either side."""
    s, e, text = t.start, t.end, doc.text
    out = [text[s:e]]
    for a, b in ((s - 1, e), (s + 1, e), (s, e - 1), (s, e + 1), (s - 1, e - 1), (s + 1, e + 1)):
        if 0 <= a < b <= len(text):
            out.append(text[a:b])
    return out


@dataclass
class Score:
    total: int = 0
    read: int = 0            # the normaliser produced a value
    exact: int = 0           # ...equal to the gold value
    granularity: int = 0     # ...at the gold granularity
    relative: int = 0        # gold expressions resolved against the DCT
    relative_exact: int = 0
    # A day or month with no year is left unresolved, with a candidate year
    # taken from the anchor: how often would that candidate have been right?
    year_candidates: int = 0
    year_candidates_right: int = 0
    reasons: Counter = field(default_factory=Counter)
    errors: list[tuple[str, str, str, str | None]] = field(default_factory=list)

    def as_dict(self) -> dict:
        def pct(n: int, d: int) -> float:
            return round(100 * n / d, 1) if d else 0.0
        return {"expressions": self.total, "read_pct": pct(self.read, self.total),
                "exact_pct": pct(self.exact, self.total),
                "granularity_pct": pct(self.granularity, self.total),
                "precision_when_read_pct": pct(self.exact, self.read),
                "relative": self.relative, "relative_exact_pct": pct(self.relative_exact, self.relative),
                "year_candidates": self.year_candidates,
                "year_candidates_right_pct": pct(self.year_candidates_right, self.year_candidates),
                "not_read": dict(self.reasons.most_common())}


_RELATIVE_HINT = re.compile(r"\b(last|this|next|previous|ago|yesterday|today|past|earlier)\b", re.I)


def score(docs: list[TimeDoc], *, repair_spans: bool = True) -> Score:
    sc = Score()
    for doc in docs:
        anchor = Anchor(value=doc.dct, source="publication_meta", detail="TimeML DCT")
        for t in doc.timexes:
            sc.total += 1
            is_relative = bool(_RELATIVE_HINT.search(t.text))
            sc.relative += is_relative
            candidates = _variants(doc, t) if repair_spans else [doc.text[t.start:t.end]]
            # The gold span's reading, unless a one-character repair reads.
            reading = normalize(candidates[0], anchor=anchor)
            for text in candidates[1:]:
                if reading.status == "verified":
                    break
                repaired = normalize(text, anchor=anchor)
                if repaired.status == "verified":
                    reading = repaired
            got = _as_timeml(reading.value) if reading.status == "verified" else None
            if got is None:
                sc.reasons[reading.reason or reading.status] += 1
                if reading.reason == "year_from_context" and reading.alternatives:
                    sc.year_candidates += 1
                    sc.year_candidates_right += reading.alternatives[0] == t.value
                sc.errors.append((doc.doc_id, t.text, t.value, None))
                continue
            sc.read += 1
            if granularity(got.split("/")[0]) == granularity(t.value):
                sc.granularity += 1
            if got == t.value:
                sc.exact += 1
                sc.relative_exact += is_relative
            else:
                sc.errors.append((doc.doc_id, t.text, t.value, got))
    return sc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--splits", nargs="+", default=["train", "dev"], choices=SPLITS)
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    ap.add_argument("--errors", type=int, default=20, help="how many disagreements to print")
    args = ap.parse_args(argv)
    if "test" in args.splits:
        print("note: test is for the frozen normaliser only (ADR-0060)")
    docs = load(args.root, tuple(args.splits))
    for repair in (False, True):
        sc = score(docs, repair_spans=repair)
        print(f"{'repaired spans' if repair else 'gold spans    '}: {sc.as_dict()}")
    for doc_id, text, gold, got in score(docs).errors[:args.errors]:
        print(f"  {doc_id[:48]:48} {text!r:32} gold={gold:12} got={got}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
