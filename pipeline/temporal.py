"""Relationship dates as the source states them (ADR-0063).

A date is a ``TemporalAssertion``: the expression copied from the text, the
role it plays for the relationship, the value the CODE reads from that
expression (never padded: "2021" stays a year), its precision, the anchor a
relative expression was resolved against, and a status this module computes.
The model names and places a date; it never decides whether the date holds.

Pipeline order:

* ``check_assertions`` -- Stage 3, per chunk: locate each quote in the chunk
  (exact after typographic folding, on word boundaries), normalise it, resolve
  a relative expression against the document anchor when that anchor is a
  publication date, compare with the model's own reading, compute the status.
* ``merge_times`` -- Stage 3 merge and Stage 4 duplicates: the union, one
  assertion per occurrence, contradictions marked, never a min/max span.
* ``export_plan`` -- Stage 4: which assertions may fill ``start_time`` /
  ``stop_time`` under the policy's ``temporal_export`` mode, and why every
  other one does not (the ledger's ``time`` changes).
* ``analyst_assertion`` / ``legacy_assertions`` -- the API and rows written
  before the change.

Values are written in EDTF (ISO 8601-2): ``2023``, ``2023-03``, ``2023-03-12``,
a timestamp with its offset, quarters and halves as the level-2 codes
``2023-33``..``2023-36`` and ``2023-40``/``2023-41``, a window as ``a/b``.
``precision`` says the same thing in a word so no consumer parses EDTF codes.

Standard library + pydantic only: the API imports this module.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from models.schemas import EvidenceLabel
from pipeline.regex_safety import compile_pattern

Role = Literal["start", "end", "within", "throughout", "observed"]
Precision = Literal["year", "half", "quarter", "month", "day", "instant"]
Qualifier = Literal["none", "approx", "early", "mid", "late", "before", "after", "by"]
Status = Literal["verified", "ambiguous", "unresolved", "conflict"]
AnchorSource = Literal["publication_meta", "text_header", "analyst", "file_metadata"]

ROLES: tuple[str, ...] = ("start", "end", "within", "throughout", "observed")
BOUND_ROLES: tuple[str, ...] = ("start", "end")
EXPORT_MODES: tuple[str, ...] = ("faithful", "day")
DEFAULT_EXPORT_MODE = "faithful"
_PRECISION_RANK = {"year": 0, "half": 1, "quarter": 2, "month": 3, "day": 4, "instant": 5}
# Which anchor kinds may resolve "last month": a publication date, not the
# moment a file was printed (ADR-0063 §4).
_WEAK_ANCHORS = frozenset({"file_metadata"})


# ── Models ────────────────────────────────────────────────────────────────────


class Anchor(BaseModel):
    """The document's reference date and where it came from (ADR-0063 §4)."""
    value: str                          # YYYY-MM-DD
    source: AnchorSource
    detail: str | None = None           # the meta key, the header line, the file field
    candidates: list[dict] = Field(default_factory=list)   # every candidate seen

    @property
    def publication_grade(self) -> bool:
        return self.source not in _WEAK_ANCHORS

    def day(self) -> date:
        return date.fromisoformat(self.value[:10])


class TemporalAssertion(BaseModel):
    """One date the source attaches to one relationship (ADR-0063 §1)."""
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    role: Role
    time_text: str = ""                 # verbatim from the chunk; "" for analyst/legacy
    value: str | None = None            # EDTF, as far as the source fixes it
    precision: Precision | None = None
    qualifier: Qualifier = "none"
    first_last: Literal["first", "last"] | None = None     # "first observed in ..."
    model_value: str | None = None      # the model's own reading, kept for comparison
    alternatives: list[str] = Field(default_factory=list)  # readings the code could not choose between
    anchor: Literal["explicit", "document", "none"] = "explicit"
    anchor_source: str | None = None
    anchor_value: str | None = None
    evidence_label: EvidenceLabel | None = None
    status: Status = "unresolved"       # computed here or set by an analyst, never by the model
    reason: str | None = None
    doc_offset: int | None = None       # position in the folded document text
    origin: Literal["llm", "analyst", "legacy"] = "llm"


@dataclass(frozen=True)
class DocumentTime:
    """What Stage 3 needs to check dates against the whole report: the
    anchor, and the folded document text that places an occurrence."""
    anchor: Anchor | None = None
    folded_text: str = ""

    @classmethod
    def build(cls, text: str, anchor: Anchor | None) -> DocumentTime:
        return cls(anchor=anchor, folded_text=fold(text or "")[0])


# ── Typographic folding and exact location ───────────────────────────────────

_ZERO_WIDTH = frozenset("​‌‍⁠﻿­")
_DASHES = frozenset("‐‑‒–—―−﹘﹣－")
_QUOTES = {"‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
           "“": '"', "”": '"', "„": '"', "«": '"', "»": '"'}


def fold(text: str) -> tuple[str, list[int]]:
    """Fold typography for exact matching and return, for every folded
    character, its index in ``text``.

    Space-like characters (NBSP, thin space, newlines, tabs) become one space
    and runs collapse; dashes become '-'; curly quotes become straight ones;
    zero-width characters vanish; letters are lower-cased.  Nothing else
    changes: a digit is never approximated, so "2O23" does not fold to
    "2023".
    """
    out: list[str] = []
    imap: list[int] = []
    prev_space = False
    for i, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        if ch.isspace():
            if not prev_space:
                out.append(" ")
                imap.append(i)
                prev_space = True
            continue
        prev_space = False
        if ch in _DASHES:
            ch = "-"
        else:
            ch = _QUOTES.get(ch, ch)
        low = ch.lower()
        out.append(low if len(low) == 1 else ch)
        imap.append(i)
    return "".join(out), imap


def fold_text(text: str) -> str:
    return fold(text)[0]


def _word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _boundary_ok(hay: str, start: int, end: int) -> bool:
    """The match stands on word boundaries.  A digit next to '-', '/' or '.'
    that is itself next to a letter or digit is inside an identifier:
    ``2021`` in ``CVE-2021-44228`` or ``v1.2021``, never a date."""
    if start > 0:
        prev = hay[start - 1]
        if _word(prev):
            return False
        if prev in "-/." and hay[start].isdigit() and start > 1 and hay[start - 2].isalnum():
            return False
    if end < len(hay):
        nxt = hay[end]
        if _word(nxt):
            return False
        if nxt in "-/" and hay[end - 1].isdigit() and end + 1 < len(hay) and hay[end + 1].isalnum():
            return False
    return True


def locate(time_text: str, chunk: str) -> tuple[list[tuple[int, int]], str | None]:
    """Spans of ``time_text`` in ``chunk`` (original coordinates) and, when
    there is none, why: ``not_found`` or ``boundary`` (found only inside an
    identifier)."""
    needle = fold(time_text)[0].strip(" ").strip(" .,;:")
    if not needle:
        return [], "not_found"
    hay, imap = fold(chunk)
    spans: list[tuple[int, int]] = []
    boundary_miss = False
    pos = hay.find(needle)
    while pos != -1:
        end = pos + len(needle)
        if _boundary_ok(hay, pos, end):
            spans.append((imap[pos], imap[end - 1] + 1))
        else:
            boundary_miss = True
        pos = hay.find(needle, pos + 1)
    if spans:
        return spans, None
    return [], ("boundary" if boundary_miss else "not_found")


# ── Reading one expression ───────────────────────────────────────────────────

_MONTHS: dict[str, int] = {
    "january": 1, "jan": 1, "janvier": 1, "janv": 1,
    "february": 2, "feb": 2, "février": 2, "fevrier": 2, "févr": 2, "fevr": 2, "fév": 2,
    "march": 3, "mar": 3, "mars": 3,
    "april": 4, "apr": 4, "avril": 4, "avr": 4,
    "may": 5, "mai": 5,
    "june": 6, "jun": 6, "juin": 6,
    "july": 7, "jul": 7, "juillet": 7, "juil": 7,
    "august": 8, "aug": 8, "août": 8, "aout": 8,
    "september": 9, "sep": 9, "sept": 9, "septembre": 9,
    "october": 10, "oct": 10, "octobre": 10,
    "november": 11, "nov": 11, "novembre": 11,
    "december": 12, "dec": 12, "décembre": 12, "decembre": 12, "déc": 12,
}
_WEEKDAYS = frozenset({
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri", "sat", "sun",
    "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche",
})
_NUMBER_WORDS = {
    "a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "un": 1, "une": 1, "deux": 2, "trois": 3, "quatre": 4, "cinq": 5, "sept": 7,
    "huit": 8, "neuf": 9, "dix": 10, "onze": 11, "douze": 12,
}
_ORDINALS = {"first": 1, "1st": 1, "second": 2, "2nd": 2, "third": 3, "3rd": 3,
             "fourth": 4, "4th": 4, "premier": 1, "1er": 1, "deuxième": 2, "deuxieme": 2,
             "troisième": 3, "troisieme": 3, "quatrième": 4, "quatrieme": 4}

# Leading words: a preposition (no qualifier) or a modifier (a qualifier).
# Longest first, so "the end of" is tried before "the".
_LEADING: list[tuple[str, str]] = sorted([
    ("no later than", "by"), ("prior to", "before"), ("as early as", "none"),
    ("as of", "none"), ("some time in", "none"), ("sometime in", "none"),
    ("at the beginning of", "early"), ("at the start of", "early"),
    ("the beginning of", "early"), ("the start of", "early"),
    ("beginning of", "early"), ("start of", "early"),
    ("at the end of", "late"), ("the end of", "late"), ("end of", "late"),
    ("the middle of", "mid"), ("middle of", "mid"),
    ("starting in", "none"), ("starting from", "none"), ("starting", "none"),
    ("beginning in", "none"), ("up to", "none"), ("up until", "none"),
    ("since", "none"), ("from", "none"), ("between", "none"), ("during", "none"),
    ("in", "none"), ("on", "none"), ("at", "none"), ("of", "none"),
    ("until", "none"), ("till", "none"), ("til", "none"), ("through", "none"),
    ("throughout", "none"), ("to", "none"),
    ("before", "before"), ("after", "after"), ("by", "by"),
    ("around", "approx"), ("about", "approx"), ("approximately", "approx"),
    ("roughly", "approx"), ("circa", "approx"), ("ca.", "approx"), ("c.", "approx"),
    ("~", "approx"), ("early", "early"), ("mid", "mid"), ("late", "late"),
    ("the", "none"),
    ("à partir de", "none"), ("a partir de", "none"), ("depuis", "none"),
    ("jusqu'à", "none"), ("jusqu'a", "none"), ("jusqu'en", "none"), ("jusqu'au", "none"),
    ("au début de", "early"), ("au debut de", "early"), ("à la fin de", "late"),
    ("a la fin de", "late"), ("à la mi", "mid"), ("a la mi", "mid"),
    ("entre", "none"), ("pendant", "none"), ("durant", "none"), ("courant", "none"),
    ("en", "none"), ("le", "none"), ("du", "none"), ("de", "none"), ("au", "none"),
    ("avant", "before"), ("après", "after"), ("apres", "after"), ("vers", "approx"),
    ("environ", "approx"), ("début", "early"), ("debut", "early"), ("mi", "mid"),
    ("fin", "late"),
], key=lambda p: -len(p[0]))

_R_INSTANT = compile_pattern(
    r"^(\d{4})-(\d{2})-(\d{2})[t ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?"
    r"\s*(z|utc|gmt|[+-]\d{2}:?\d{2})?$")
_R_ISO_DAY = compile_pattern(r"^(\d{4})-(\d{2})-(\d{2})$")
_R_ISO_MONTH = compile_pattern(r"^(\d{4})-(\d{2})$")
_R_YEAR = compile_pattern(r"^(\d{4})$")
_R_YMD = compile_pattern(r"^(\d{4})[/.](\d{1,2})[/.](\d{1,2})$")
_R_NUMERIC = compile_pattern(r"^(\d{1,2})([/.-])(\d{1,2})([/.-])(\d{4})$")
_R_D_M_Y = compile_pattern(                                                   # 27th of February of 2020
    r"^(\d{1,2})(?:st|nd|rd|th|er)?\s+(?:of\s+)?([^\s\d]+?)\.?,?(?:\s+of)?\s*(\d{4})$")
_R_D_MON_Y = compile_pattern(r"^(\d{1,2})[-/]([^\s\d/-]+?)\.?[-/](\d{4})$")          # 24-Apr-2020
_R_Y_MON_D = compile_pattern(r"^(\d{4})[-/]([^\s\d/-]+?)\.?[-/](\d{1,2})$")          # 2008-May-31
_R_Y_D_M = compile_pattern(r"^(\d{4}),?\s+(\d{1,2})(?:st|nd|rd|th|er)?\s+([^\s\d]+?)\.?$")  # 2019, 11 March
_R_M_D_Y = compile_pattern(                                                   # December 27th of 2019
    r"^([^\s\d]+?)\.?\s+(\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)(?:of\s+)?(\d{4})$")
_R_M_Y = compile_pattern(r"^([^\s\d]+?)\.?,?\s+(?:of\s+)?(\d{4})$")
_R_D_M = compile_pattern(r"^(\d{1,2})(?:st|nd|rd|th|er)?\s+(?:of\s+)?([^\s\d]+?)\.?$")
_R_M_D = compile_pattern(r"^([^\s\d]+?)\.?\s+(\d{1,2})(?:st|nd|rd|th)?$")
_R_Q = compile_pattern(r"^q([1-4])\s*[-/]?\s*(\d{4})$")
_R_Y_Q = compile_pattern(r"^(\d{4})\s*[-/]?\s*q([1-4])$")
_R_QN = compile_pattern(r"^([1-4])q\s*(\d{4})$")
_R_Q_WORDS = compile_pattern(r"^([^\s]+)\s+(?:quarter|trimestre)\s+(?:of\s+|de\s+|d')?(\d{4})$")
_R_H = compile_pattern(r"^h([12])\s*[-/]?\s*(\d{4})$")
_R_H_WORDS = compile_pattern(r"^([^\s]+)\s+(?:half|semestre)\s+(?:of\s+|de\s+|d')?(\d{4})$")
_R_AGO = compile_pattern(r"^(\d+|[a-z]+)\s+(day|week|month|year)s?\s+ago$")
_R_IL_Y_A = compile_pattern(r"^il y a\s+(\d+|[a-z]+)\s+(jours?|semaines?|mois|ans|années?|annees?)$")
# "the past six months", "over the past year" (a window ending at the anchor —
# not the previous calendar year, which "last year" is).
_R_PAST_N = compile_pattern(
    r"^(?:the\s+|over\s+the\s+|in\s+the\s+|during\s+the\s+)?(?:last|past|previous)\s+"
    r"(?:(\d+|[a-z]+)\s+)?(day|week|month|year)s?$")
_R_FR_PAST_N = compile_pattern(
    r"^(?:au cours )?(?:des|ces|les)\s+(\d+|[a-z]+)\s+(?:derniers|dernières|dernieres)\s+"
    r"(jours|semaines|mois|ans|années|annees)$")
_R_LAST_MONTHNAME = compile_pattern(r"^(?:last|previous)\s+([^\s\d]+)$")
_R_MONTHNAME_REL_YEAR = compile_pattern(r"^([^\s\d]+)\s+(?:of\s+)?(last|this|next)\s+year$")
_R_FR_MONTH_DERNIER = compile_pattern(r"^(?:en\s+)?([^\s\d]+)\s+dernier$")

_REL_FIXED: dict[str, tuple[str, int]] = {
    # phrase -> (unit, offset from the anchor's own unit)
    "last month": ("month", -1), "previous month": ("month", -1), "the previous month": ("month", -1),
    "the last month": ("month", -1), "this month": ("month", 0), "current month": ("month", 0),
    "the current month": ("month", 0), "earlier this month": ("month", 0), "next month": ("month", 1),
    "last year": ("year", -1), "previous year": ("year", -1), "the previous year": ("year", -1),
    "the last year": ("year", -1), "this year": ("year", 0), "current year": ("year", 0),
    "the current year": ("year", 0), "earlier this year": ("year", 0), "next year": ("year", 1),
    "the coming year": ("year", 1), "coming year": ("year", 1), "the coming month": ("month", 1),
    "coming month": ("month", 1),
    "yesterday": ("day", -1), "today": ("day", 0),
    "last week": ("week", -1), "previous week": ("week", -1), "the previous week": ("week", -1),
    "this week": ("week", 0),
    "le mois dernier": ("month", -1), "mois dernier": ("month", -1), "le mois précédent": ("month", -1),
    "le mois precedent": ("month", -1), "ce mois-ci": ("month", 0), "ce mois": ("month", 0),
    "l'année dernière": ("year", -1), "l'annee derniere": ("year", -1), "l'an dernier": ("year", -1),
    "l'année précédente": ("year", -1), "l'annee precedente": ("year", -1),
    "cette année": ("year", 0), "cette annee": ("year", 0), "hier": ("day", -1),
    "aujourd'hui": ("day", 0), "la semaine dernière": ("week", -1), "la semaine derniere": ("week", -1),
}
_FR_UNITS = {"jour": "day", "jours": "day", "semaine": "week", "semaines": "week", "mois": "month",
             "an": "year", "ans": "year", "année": "year", "années": "year", "annee": "year",
             "annees": "year"}


@dataclass
class Reading:
    """What the code reads from one expression."""
    value: str | None = None
    precision: str | None = None
    qualifier: str = "none"
    status: str = "verified"
    reason: str | None = None
    alternatives: list[str] = field(default_factory=list)
    anchored: bool = False      # resolved against the document anchor


def _unresolved(reason: str, precision: str | None = None,
                alternatives: list[str] | None = None) -> Reading:
    return Reading(precision=precision, status="unresolved", reason=reason,
                   alternatives=list(alternatives or []))


def _plausible(year: int) -> bool:
    """A four-digit number that can be a calendar year.  Deliberately wide:
    reading "1946" or "by 2045" is the normaliser's job; whether such a date
    can belong to a relationship is the check's and the analyst's (AnnoCTR
    annotates both, and a 1970–2028 window refused them)."""
    return 1900 <= year <= 2100


def _month(token: str) -> int | None:
    return _MONTHS.get(token.strip(".").strip(","))


def _number(token: str) -> int | None:
    if token.isdigit():
        return int(token)
    return _NUMBER_WORDS.get(token)


def _day_value(y: int, m: int, d: int) -> Reading:
    if not _plausible(y):
        return _unresolved("implausible_year", "day")
    try:
        date(y, m, d)
    except ValueError:
        return _unresolved("invalid_date", "day")
    return Reading(value=f"{y:04d}-{m:02d}-{d:02d}", precision="day")


def _month_value(y: int, m: int) -> Reading:
    if not _plausible(y):
        return _unresolved("implausible_year", "month")
    if not 1 <= m <= 12:
        return _unresolved("invalid_date", "month")
    return Reading(value=f"{y:04d}-{m:02d}", precision="month")


def _year_value(y: int) -> Reading:
    if not _plausible(y):
        return _unresolved("implausible_year", "year")
    return Reading(value=f"{y:04d}", precision="year")


def _strip_leading(s: str) -> tuple[str, str]:
    """Remove leading prepositions and modifiers; return the rest and the
    first qualifier met ("since early 2023" -> "2023", early)."""
    qualifier = "none"
    changed = True
    while changed and s:
        changed = False
        for phrase, qual in _LEADING:
            if s == phrase:
                break
            if s.startswith(phrase) and len(s) > len(phrase) and s[len(phrase)] in " -":
                s = s[len(phrase) + 1:].lstrip(" -")
                if qualifier == "none" and qual != "none":
                    qualifier = qual
                changed = True
                break
    # "monday, 25 april 2022" -> "25 april 2022"
    first, _, rest = s.partition(" ")
    if first.rstrip(",") in _WEEKDAYS and rest:
        s = rest.lstrip(", ")
    return s, qualifier


def _read_absolute(s: str, order_hint: str | None) -> Reading | None:
    """An expression that needs no anchor; None when it is not one."""
    m = _R_INSTANT.match(s)
    if m:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        base = _day_value(y, mo, d)
        if base.status != "verified":
            return Reading(precision="instant", status=base.status, reason=base.reason)
        hh, mm = int(m.group(4)), int(m.group(5))
        ss = int(m.group(6)) if m.group(6) else 0
        frac = (m.group(7) or "").ljust(6, "0")[:6]
        tz = m.group(8)
        try:
            dt = datetime(y, mo, d, hh, mm, ss, int(frac or 0))
        except ValueError:
            return _unresolved("invalid_date", "instant")
        if tz:
            if tz in ("z", "utc", "gmt"):
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                sign = 1 if tz[0] == "+" else -1
                digits = tz[1:].replace(":", "")
                offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))
                dt = dt.replace(tzinfo=timezone(sign * offset))
        return Reading(value=dt.isoformat(), precision="instant")
    m = _R_ISO_DAY.match(s)
    if m:
        return _day_value(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = _R_ISO_MONTH.match(s)
    if m:
        return _month_value(int(m.group(1)), int(m.group(2)))
    m = _R_YEAR.match(s)
    if m:
        return _year_value(int(m.group(1)))
    m = _R_YMD.match(s)
    if m:
        return _day_value(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = _R_NUMERIC.match(s)
    if m:
        if m.group(2) != m.group(4):
            return _unresolved("unparsed", "day")
        a, b, y = int(m.group(1)), int(m.group(3)), int(m.group(5))
        dmy, mdy = _day_value(y, b, a), _day_value(y, a, b)
        if a == b or (dmy.status == "verified") != (mdy.status == "verified"):
            return dmy if dmy.status == "verified" else mdy
        if dmy.status != "verified":
            return dmy
        if order_hint == "dmy":
            return dmy
        if order_hint == "mdy":
            return mdy
        return Reading(precision="day", status="ambiguous", reason="numeric_order",
                       alternatives=[v for v in (dmy.value, mdy.value) if v])
    m = _R_D_M_Y.match(s) or _R_D_MON_Y.match(s)
    if m and _month(m.group(2)):
        return _day_value(int(m.group(3)), _month(m.group(2)) or 0, int(m.group(1)))
    m = _R_Y_D_M.match(s)
    if m and _month(m.group(3)):
        return _day_value(int(m.group(1)), _month(m.group(3)) or 0, int(m.group(2)))
    m = _R_Y_MON_D.match(s)
    if m and _month(m.group(2)):
        return _day_value(int(m.group(1)), _month(m.group(2)) or 0, int(m.group(3)))
    m = _R_M_D_Y.match(s)
    if m and _month(m.group(1)):
        return _day_value(int(m.group(3)), _month(m.group(1)) or 0, int(m.group(2)))
    m = _R_M_Y.match(s)
    if m and _month(m.group(1)):
        return _month_value(int(m.group(2)), _month(m.group(1)) or 0)
    for rx, qi, yi in ((_R_Q, 1, 2), (_R_Y_Q, 2, 1), (_R_QN, 1, 2)):
        m = rx.match(s)
        if m:
            y = int(m.group(yi))
            if not _plausible(y):
                return _unresolved("implausible_year", "quarter")
            return Reading(value=f"{y:04d}-{32 + int(m.group(qi))}", precision="quarter")
    m = _R_Q_WORDS.match(s)
    if m and _ORDINALS.get(m.group(1)) in (1, 2, 3, 4):
        y = int(m.group(2))
        if not _plausible(y):
            return _unresolved("implausible_year", "quarter")
        return Reading(value=f"{y:04d}-{32 + _ORDINALS[m.group(1)]}", precision="quarter")
    m = _R_H.match(s)
    if m:
        y = int(m.group(2))
        if not _plausible(y):
            return _unresolved("implausible_year", "half")
        return Reading(value=f"{y:04d}-{39 + int(m.group(1))}", precision="half")
    m = _R_H_WORDS.match(s)
    if m and _ORDINALS.get(m.group(1)) in (1, 2):
        y = int(m.group(2))
        if not _plausible(y):
            return _unresolved("implausible_year", "half")
        return Reading(value=f"{y:04d}-{39 + _ORDINALS[m.group(1)]}", precision="half")
    # A day or a month with no year: the year would come from elsewhere.
    m = _R_D_M.match(s)
    if m and _month(m.group(2)) and 1 <= int(m.group(1)) <= 31:
        return _unresolved("year_from_context", "day")
    m = _R_M_D.match(s)
    if m and _month(m.group(1)) and 1 <= int(m.group(2)) <= 31:
        return _unresolved("year_from_context", "day")
    if _month(s):
        return _unresolved("year_from_context", "month")
    return None


def _shift_month(y: int, m: int, delta: int) -> tuple[int, int]:
    idx = y * 12 + (m - 1) + delta
    return idx // 12, idx % 12 + 1


def _relative(s: str, anchor_day: date) -> Reading | None:
    """A relative expression resolved against ``anchor_day``; None when ``s``
    is not one this module reads."""
    y, mo = anchor_day.year, anchor_day.month
    fixed = _REL_FIXED.get(s)
    if fixed:
        unit, delta = fixed
        if unit == "month":
            yy, mm = _shift_month(y, mo, delta)
            return _month_value(yy, mm)
        if unit == "year":
            return _year_value(y + delta)
        if unit == "day":
            d = anchor_day + timedelta(days=delta)
            return _day_value(d.year, d.month, d.day)
        monday = anchor_day - timedelta(days=anchor_day.weekday()) + timedelta(weeks=delta)
        sunday = monday + timedelta(days=6)
        return Reading(value=f"{monday.isoformat()}/{sunday.isoformat()}", precision="day")
    for rx, fr in ((_R_AGO, False), (_R_IL_Y_A, True)):
        m = rx.match(s)
        if m:
            n = _number(m.group(1))
            unit = _FR_UNITS.get(m.group(2), m.group(2)) if fr else m.group(2)
            if n is None:
                return None
            if unit == "day":
                d = anchor_day - timedelta(days=n)
                return _day_value(d.year, d.month, d.day)
            if unit == "week":
                d = anchor_day - timedelta(weeks=n)
                r = _day_value(d.year, d.month, d.day)
                r.qualifier = "approx"
                return r
            if unit == "month":
                yy, mm = _shift_month(y, mo, -n)
                return _month_value(yy, mm)
            return _year_value(y - n)
    for rx, fr in ((_R_PAST_N, False), (_R_FR_PAST_N, True)):
        m = rx.match(s)
        if m:
            n = _number(m.group(1)) if m.group(1) else 1
            unit = _FR_UNITS.get(m.group(2), m.group(2)) if fr else m.group(2)
            if n is None:
                return None
            if unit in ("day", "week"):
                start = anchor_day - timedelta(days=n if unit == "day" else 7 * n)
                return Reading(value=f"{start.isoformat()}/{anchor_day.isoformat()}", precision="day")
            months = n if unit == "month" else 12 * n
            yy, mm = _shift_month(y, mo, -months)
            return Reading(value=f"{yy:04d}-{mm:02d}/{y:04d}-{mo:02d}", precision="month")
    m = _R_LAST_MONTHNAME.match(s) or _R_FR_MONTH_DERNIER.match(s)
    if m and _month(m.group(1)):
        target = _month(m.group(1)) or 0
        return _month_value(y if target < mo else y - 1, target)
    m = _R_MONTHNAME_REL_YEAR.match(s)
    if m and _month(m.group(1)):
        delta = {"last": -1, "this": 0, "next": 1}[m.group(2)]
        return _month_value(y + delta, _month(m.group(1)) or 0)
    return None


def _looks_relative(s: str) -> bool:
    if s in _REL_FIXED:
        return True
    return any(rx.match(s) for rx in (_R_AGO, _R_IL_Y_A, _R_PAST_N, _R_FR_PAST_N,
                                      _R_LAST_MONTHNAME, _R_MONTHNAME_REL_YEAR,
                                      _R_FR_MONTH_DERNIER))


def _read_one(s: str, anchor: Anchor | None, order_hint: str | None) -> Reading:
    """Read one (non-range) expression, relative or absolute."""
    s = s.strip(" .,;:()[]\"'")
    s = s.removesuffix("'s").strip()          # "last year's campaign"
    for candidate in (s, _strip_leading(s)[0]):
        if _looks_relative(candidate):
            qualifier = _strip_leading(s)[1]
            if anchor is None:
                return _unresolved("no_anchor")
            got = _relative(candidate, anchor.day())
            if got is None:
                return _unresolved("unparsed")
            if got.qualifier == "none":
                got.qualifier = qualifier
            if not anchor.publication_grade:
                return _unresolved("weak_anchor", got.precision,
                                   [got.value] if got.value else [])
            got.anchored = got.status == "verified"
            return got
    rest, qualifier = _strip_leading(s)
    got = _read_absolute(rest, order_hint)
    if got is None:
        return _unresolved("unparsed")
    if got.reason == "year_from_context" and anchor is not None and anchor.publication_grade:
        # The usual reading of "On June 14" in a report published on
        # 2016-06-17: the most recent such date not after publication.  A
        # candidate for the analyst, never a verified value -- a paragraph
        # about 2018 can say "In August" too.
        guess = _year_candidate(rest, anchor.day())
        if guess:
            got.alternatives = [guess]
    if got.qualifier == "none":
        got.qualifier = qualifier
    return got


def _year_candidate(rest: str, anchor_day: date) -> str | None:
    for year in (anchor_day.year, anchor_day.year - 1):
        reading = _read_absolute(f"{rest} {year}", None)
        if reading is None or reading.status != "verified" or not reading.value:
            return None
        w = window(reading.value)
        if w is not None and w[0].date() <= anchor_day:
            return reading.value
    return None


_RANGE_SEPARATORS = (" and ", " to ", " through ", " thru ", " until ", " till ",
                     " - ", " et ", " à ", " au ", " jusqu'à ", " jusqu'au ")
_R_YEAR_RANGE = compile_pattern(r"^(\d{4})\s*-\s*(\d{4})$")


def _split_range(s: str) -> tuple[str, str] | None:
    m = _R_YEAR_RANGE.match(s)
    if m:
        return m.group(1), m.group(2)
    for sep in _RANGE_SEPARATORS:
        if sep in s:
            left, _, right = s.partition(sep)
            if left.strip() and right.strip():
                return left.strip(), right.strip()
    return None


def _complete_left(left: str, right: str) -> str:
    """Borrow what the left end of a range leaves out from the right end:
    "January and April 2026" -> "january 2026"; "3 to 5 March 2023" ->
    "3 march 2023"."""
    tokens_r = right.split()
    if left.isdigit() and len(tokens_r) >= 2 and tokens_r[0].isdigit():
        return " ".join([left] + tokens_r[1:])
    year = next((t for t in reversed(tokens_r) if len(t) == 4 and t.isdigit()), None)
    if year and not any(len(t) == 4 and t.isdigit() for t in left.split()):
        return f"{left} {year}"
    return left


def _coarsest(a: str | None, b: str | None) -> str | None:
    if a is None or b is None:
        return a or b
    return a if _PRECISION_RANK[a] <= _PRECISION_RANK[b] else b


def normalize(time_text: str, *, role: str | None = None, anchor: Anchor | None = None,
              order_hint: str | None = None) -> Reading:
    """Read ``time_text`` into a value, a precision and a qualifier.

    A range in one quote ("between January and April 2026") gives its left end
    to a ``start``, its right end to an ``end``, and the window ``a/b`` to any
    other role.  A relative expression needs a publication-grade anchor;
    against a file timestamp the candidate is kept as an alternative and the
    status is ``unresolved`` / ``weak_anchor``.
    """
    s = fold(time_text)[0].strip(" .,;:()[]\"'")
    if not s:
        return _unresolved("not_found")
    rest, qualifier = _strip_leading(s)
    parts = _split_range(rest) if not _looks_relative(s) else None
    if parts:
        left, right = parts
        right_r = _read_one(right, anchor, order_hint)
        left_r = _read_one(_complete_left(left, right), anchor, order_hint)
        if role == "start":
            chosen = left_r
        elif role == "end":
            chosen = right_r
        else:
            if left_r.status != "verified" or right_r.status != "verified":
                bad = left_r if left_r.status != "verified" else right_r
                return Reading(precision=_coarsest(left_r.precision, right_r.precision),
                               status=bad.status, reason=bad.reason)
            chosen = Reading(value=f"{left_r.value}/{right_r.value}",
                             precision=_coarsest(left_r.precision, right_r.precision),
                             anchored=left_r.anchored or right_r.anchored)
        if chosen.qualifier == "none":
            chosen.qualifier = qualifier
        return chosen
    got = _read_one(s, anchor, order_hint)
    if got.qualifier == "none":
        got.qualifier = qualifier
    return got


# ── Windows and consistency ──────────────────────────────────────────────────

_FAR_TZ = timedelta(hours=14)


def window(value: str | None) -> tuple[datetime, datetime] | None:
    """The half-open window ``[lo, hi)`` a value covers, in naive civil time
    (an instant with an offset is converted to UTC).  None when unreadable."""
    if not value:
        return None
    if "/" in value:
        a, _, b = value.partition("/")
        wa, wb = window(a), window(b)
        if wa is None or wb is None:
            return None
        return wa[0], wb[1]
    try:
        if "t" in value.lower() and len(value) > 10:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt, dt + timedelta(microseconds=1)
            return dt - _FAR_TZ, dt + _FAR_TZ
        parts = value.split("-")
        y = int(parts[0])
        if len(parts) == 1:
            return datetime(y, 1, 1), datetime(y + 1, 1, 1)
        code = int(parts[1])
        if len(parts) == 2:
            if 1 <= code <= 12:
                ny, nm = _shift_month(y, code, 1)
                return datetime(y, code, 1), datetime(ny, nm, 1)
            if 33 <= code <= 36:
                first = 3 * (code - 33) + 1
                ny, nm = _shift_month(y, first, 3)
                return datetime(y, first, 1), datetime(ny, nm, 1)
            if code in (40, 41):
                first = 1 if code == 40 else 7
                ny, nm = _shift_month(y, first, 6)
                return datetime(y, first, 1), datetime(ny, nm, 1)
            return None
        d = datetime(y, code, int(parts[2][:2]))
        return d, d + timedelta(days=1)
    except (ValueError, IndexError):
        return None


def _overlap(a: tuple[datetime, datetime], b: tuple[datetime, datetime]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _compatible(code_value: str | None, model_value: str | None) -> bool:
    """The model's reading does not contradict the code's: their windows
    overlap.  A model that padded "March 2023" to 2023-03-01 is compatible."""
    if not code_value or not model_value:
        return True
    wm = window(model_value)
    if wm is None:
        reading = _read_absolute(fold(model_value)[0].strip(), None)
        wm = window(reading.value) if reading and reading.value else None
    wc = window(code_value)
    if wm is None or wc is None:
        return True
    return _overlap(wc, wm)


def mark_conflicts(times: list[TemporalAssertion]) -> list[TemporalAssertion]:
    """Within one relationship, a start whose earliest moment is not before an
    end's latest one, or two starts (two ends) whose windows cannot overlap,
    contradict each other: both become ``conflict`` / ``contradicts``.  Only
    ``verified`` assertions are judged, and never downgraded otherwise.  An
    analyst's assertions for a role replace the others for that role."""
    out = [a.model_copy() for a in times]
    by_role: dict[str, list[tuple[int, tuple[datetime, datetime]]]] = {"start": [], "end": []}
    for role in BOUND_ROLES:
        members = [i for i, a in enumerate(out) if a.role == role]
        analyst = [i for i in members if out[i].origin == "analyst"]
        for i in (analyst or members):
            a = out[i]
            if a.status not in ("verified", "conflict") or a.value is None:
                continue
            w = window(a.value)
            if w is not None:
                by_role[role].append((i, w))

    bad: set[int] = set()
    for i, ws in by_role["start"]:
        for j, we in by_role["end"]:
            if ws[0] >= we[1]:
                bad.update((i, j))
    for role in BOUND_ROLES:
        members_w = by_role[role]
        for x in range(len(members_w)):
            for y in range(x + 1, len(members_w)):
                if not _overlap(members_w[x][1], members_w[y][1]):
                    bad.update((members_w[x][0], members_w[y][0]))
    for i in bad:
        if out[i].status == "verified":
            out[i].status = "conflict"
            out[i].reason = "contradicts"
    return out


# ── Stage 3: check one relationship's dates against its chunk ────────────────

_R_NUMERIC_ANY = compile_pattern(r"(\d{1,2})([/.-])(\d{1,2})([/.-])(\d{4})")


def numeric_order_hint(chunk: str, span: tuple[int, int], sep: str | None = None) -> str | None:
    """Day/month order fixed by the passage around ``span`` (the block between
    blank lines): another numeric date in the same format with a component
    above 12.  None when there is none, or when the passage holds both orders
    -- a hint is local, never document-wide."""
    start = chunk.rfind("\n\n", 0, span[0])
    end = chunk.find("\n\n", span[1])
    passage = chunk[0 if start < 0 else start:len(chunk) if end < 0 else end]
    orders: set[str] = set()
    for m in _R_NUMERIC_ANY.finditer(passage):
        if m.group(2) != m.group(4) or (sep is not None and m.group(2) != sep):
            continue
        a, b = int(m.group(1)), int(m.group(3))
        if a > 12 and 1 <= b <= 12:
            orders.add("dmy")
        elif b > 12 and 1 <= a <= 12:
            orders.add("mdy")
    return next(iter(orders)) if len(orders) == 1 else None


def _separator(time_text: str) -> str | None:
    m = _R_NUMERIC_ANY.search(time_text)
    return m.group(2) if m else None


def _evidence_position(evidence_text: str | None, chunk: str) -> int | None:
    if not evidence_text:
        return None
    probe = fold(evidence_text)[0].strip(" ")[:80]
    if len(probe) < 12:
        return None
    hay, imap = fold(chunk)
    pos = hay.find(probe)
    return imap[pos] if pos >= 0 else None


def _doc_offset(chunk: str, span: tuple[int, int], folded_doc: str) -> int | None:
    """Where the occurrence at ``span`` sits in the folded document: its
    surrounding text, folded the same way, located there.  The same occurrence
    read through two overlapping chunks lands on the same offset."""
    if not folded_doc:
        return None
    s, e = span
    found: int | None = None
    for pad in (60, 120, 240):
        a, b = max(0, s - pad), min(len(chunk), e + pad)
        win = fold(chunk[a:b])[0]
        prefix = len(fold(chunk[a:s])[0])
        pos = folded_doc.find(win)
        if pos < 0:
            break
        found = pos + prefix
        if folded_doc.find(win, pos + 1) < 0:
            return found
    return found


def check_assertions(
    times: list[TemporalAssertion],
    chunk: str,
    *,
    document: DocumentTime | None = None,
    evidence_text: str | None = None,
    rel_label: EvidenceLabel | str | None = None,
) -> list[TemporalAssertion]:
    """Compute value, precision and status for the model's assertions against
    the chunk they came from (ADR-0063 §3).  Analyst and legacy assertions
    pass through."""
    anchor = document.anchor if document else None
    ev_pos = _evidence_position(evidence_text, chunk)
    out: list[TemporalAssertion] = []
    for a in times:
        if a.origin != "llm":
            out.append(a)
            continue
        b = a.model_copy()
        if b.evidence_label is None and rel_label is not None:
            try:
                b.evidence_label = EvidenceLabel(getattr(rel_label, "value", rel_label))
            except ValueError:
                pass
        b.value, b.precision, b.alternatives, b.doc_offset = None, None, [], None
        if not b.time_text.strip():
            b.status, b.reason, b.anchor = "unresolved", "no_quote", "none"
            out.append(b)
            continue
        spans, miss = locate(b.time_text, chunk)
        if not spans:
            b.status, b.reason, b.anchor = "conflict", miss, "none"
            out.append(b)
            continue
        span = spans[0] if ev_pos is None else min(spans, key=lambda sp: abs(sp[0] - ev_pos))
        reading = normalize(
            b.time_text, role=b.role, anchor=anchor,
            order_hint=numeric_order_hint(chunk, span, _separator(b.time_text)),
        )
        b.value, b.alternatives = reading.value, reading.alternatives
        b.precision = reading.precision  # type: ignore[assignment]  # one of Precision, from _read_*
        if reading.qualifier != "none":
            b.qualifier = reading.qualifier  # type: ignore[assignment]
        b.status, b.reason = reading.status, reading.reason  # type: ignore[assignment]
        if reading.anchored or reading.reason == "weak_anchor":
            b.anchor = "document"
            b.anchor_source = anchor.source if anchor else None
            b.anchor_value = anchor.value if anchor else None
        elif reading.reason == "no_anchor":
            b.anchor = "none"
        else:
            b.anchor = "explicit"
        if b.status == "verified" and not _compatible(b.value, b.model_value):
            b.status, b.reason = "conflict", "value_mismatch"
        if document is not None:
            b.doc_offset = _doc_offset(chunk, span, document.folded_text)
        out.append(b)
    return mark_conflicts(out)


# ── Merge ────────────────────────────────────────────────────────────────────


def _identity(a: TemporalAssertion) -> tuple:
    where: Any = a.doc_offset if a.doc_offset is not None else fold(a.time_text)[0].strip(" ")
    return (a.role, a.origin, where, a.value or a.model_value)


# What makes two assertions the same one: role, origin, the occurrence (or the
# quote when the occurrence is unknown) and the value.  Stage 4 uses it to hand
# each ledger row the decision for its own assertions after a merge.
temporal_identity = _identity


def merge_times(existing: list[TemporalAssertion],
                new: list[TemporalAssertion]) -> list[TemporalAssertion]:
    """The union of two assertion lists for the same relationship: one
    assertion per occurrence (the same quote read through two overlapping
    chunks is one assertion, not two), contradictions marked, and never a
    min/max span -- "in 2021" and "in 2024" stay two assertions."""
    seen: dict[tuple, int] = {}
    out: list[TemporalAssertion] = []
    for a in list(existing) + list(new):
        key = _identity(a)
        if key in seen:
            continue
        seen[key] = len(out)
        out.append(a)
    return mark_conflicts(out)


# ── Stage 4: what may fill start_time / stop_time ────────────────────────────


@dataclass
class ExportPlan:
    start_time: datetime | None = None
    stop_time: datetime | None = None
    decisions: list[dict] = field(default_factory=list)     # one per assertion (ledger)
    assertions: list[dict] = field(default_factory=list)    # x_temporal_assertions


def export_mode(policy: dict | None) -> str:
    """The policy's ``temporal_export.mode``; ``faithful`` when absent, so a
    store that never saved the key runs the documented default (ADR-0063 §7)."""
    block = (policy or {}).get("temporal_export") if isinstance(policy, dict) else None
    mode = block.get("mode") if isinstance(block, dict) else None
    return mode if mode in EXPORT_MODES else DEFAULT_EXPORT_MODE


def _label_value(label: Any) -> str | None:
    return getattr(label, "value", label) if label is not None else None


def _native(a: TemporalAssertion, mode: str) -> tuple[datetime | None, str]:
    """The native timestamp this assertion may take, and the outcome or the
    reason it may not."""
    if a.qualifier != "none":
        return None, "qualified"
    if a.precision == "instant" and a.value:
        try:
            dt = datetime.fromisoformat(a.value)
        except ValueError:
            return None, "unparsed"
        if dt.tzinfo is None:
            return None, "no_offset"
        return dt.astimezone(timezone.utc), "exported"
    if a.precision == "day" and a.value and "/" not in a.value and mode == "day":
        d = date.fromisoformat(a.value)
        if a.role == "start":
            return datetime(d.year, d.month, d.day, tzinfo=timezone.utc), "projected"
        return datetime(d.year, d.month, d.day, 23, 59, 59, 999000, tzinfo=timezone.utc), "projected"
    return None, "precision_below_policy"


def export_plan(times: list[TemporalAssertion], mode: str = DEFAULT_EXPORT_MODE) -> ExportPlan:
    """Decide the native bounds of one SRO and why every other assertion
    stays out of them (ADR-0063 §7).

    ``faithful`` (default): only a verified bound stated as an instant with an
    offset.  ``day``: also a verified day, projected on the whole civil day in
    UTC and labelled as a projection.  Month and year never fill a native
    field.  Windows never do.  Equal bounds give no native pair.
    """
    mode = mode if mode in EXPORT_MODES else DEFAULT_EXPORT_MODE
    conflicted = any(a.status == "conflict" and a.role in BOUND_ROLES for a in times)
    analyst_roles = {a.role for a in times if a.origin == "analyst"}
    outcome: dict[str, tuple[str, str | None]] = {}
    candidates: dict[str, list[tuple[TemporalAssertion, datetime, str]]] = {"start": [], "end": []}
    for a in times:
        reason: str | None
        if a.role not in BOUND_ROLES:
            reason = "window_role"
        elif a.role in analyst_roles and a.origin != "analyst":
            reason = "superseded_by_analyst"
        elif a.status != "verified":
            reason = f"status_{a.status}"
        elif conflicted:
            reason = "conflict"
        elif _label_value(a.evidence_label) in ("gap", "inferred"):
            reason = "evidence_label"
        else:
            dt, how = _native(a, mode)
            if dt is None:
                reason = how
            else:
                candidates[a.role].append((a, dt, how))
                continue
        outcome[a.id] = ("withheld", reason)

    chosen: dict[str, tuple[TemporalAssertion, datetime, str] | None] = {}
    for role in BOUND_ROLES:
        ranked = sorted(candidates[role],
                        key=lambda c: -_PRECISION_RANK.get(c[0].precision or "year", 0))
        chosen[role] = ranked[0] if ranked else None
        for c in ranked[1:]:
            outcome[c[0].id] = ("withheld", "less_precise")

    start: tuple[TemporalAssertion, datetime, str] | None = chosen["start"]
    end: tuple[TemporalAssertion, datetime, str] | None = chosen["end"]
    if start and end and end[1] <= start[1]:
        for c in (start, end):
            outcome[c[0].id] = ("withheld", "equal_bounds" if end[1] == start[1] else "order")
        start = end = None
    plan = ExportPlan()
    native_field: dict[str, str] = {}
    for pick, fname in ((start, "start_time"), (end, "stop_time")):
        if pick is None:
            continue
        outcome[pick[0].id] = (pick[2], None)
        native_field[pick[0].id] = fname
        if fname == "start_time":
            plan.start_time = pick[1]
        else:
            plan.stop_time = pick[1]

    for a in times:
        state, reason = outcome.get(a.id, ("withheld", None))
        decision = {"kind": "time", "id": a.id, "role": a.role, "value": a.value,
                    "precision": a.precision, "status": a.status, "outcome": state}
        if reason:
            decision["reason"] = reason
        if a.id in native_field:
            decision["field"] = native_field[a.id]
        plan.decisions.append({k: v for k, v in decision.items() if v is not None})
        payload = a.model_dump(mode="json", exclude_none=True,
                               exclude={"alternatives"} if not a.alternatives else set())
        payload.pop("model_value", None)
        if a.id in native_field:
            payload["native"] = native_field[a.id]
            if state == "projected":
                payload["projection"] = "day"
        plan.assertions.append(payload)
    return plan


# ── Analyst entry, old rows, storage ─────────────────────────────────────────


def analyst_assertion(role: str, raw: str) -> TemporalAssertion:
    """An analyst's date, at the precision the analyst typed: "2023",
    "2023-03", "2023-03-12", "March 2023", or a timestamp.  Raises ValueError
    when the entry is not a date this module reads, or is ambiguous."""
    if role not in BOUND_ROLES + ("within", "throughout", "observed"):
        raise ValueError(f"unknown role {role!r}")
    folded = fold(raw or "")[0].strip(" ")
    reading = _read_absolute(_strip_leading(folded)[0], None) if folded else None
    if reading is None or reading.status != "verified" or not reading.value:
        why = reading.reason if reading else "unparsed"
        raise ValueError(f"{raw!r} is not a date ({why})")
    return TemporalAssertion(role=role, time_text="", value=reading.value,  # type: ignore[arg-type]
                             precision=reading.precision,  # type: ignore[arg-type]
                             status="verified", origin="analyst", anchor="explicit")


def legacy_assertions(start: str | None, stop: str | None) -> list[TemporalAssertion]:
    """Rows written before ADR-0063 kept a padded timestamp: a 1 January may
    be a year.  They become assertions of unknown precision, never
    re-interpreted, and never exported natively (§10)."""
    out: list[TemporalAssertion] = []
    for role, raw in (("start", start), ("end", stop)):
        if raw:
            out.append(TemporalAssertion(role=role, time_text="", value=str(raw),  # type: ignore[arg-type]
                                         status="unresolved", reason="legacy",
                                         origin="legacy", anchor="none"))
    return out


def times_to_json(times: list[TemporalAssertion]) -> str | None:
    if not times:
        return None
    return json.dumps([a.model_dump(mode="json", exclude_none=True) for a in times])


def times_from_json(raw: str | None) -> list[TemporalAssertion]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    out: list[TemporalAssertion] = []
    for item in data if isinstance(data, list) else []:
        try:
            out.append(TemporalAssertion.model_validate(item))
        except Exception:
            continue
    return out


def display_bounds(times: list[TemporalAssertion]) -> tuple[str | None, str | None]:
    """The start and end an analyst view shows: an analyst's own entry first,
    then a verified one, then any value."""
    def pick(role: str) -> str | None:
        members = [a for a in times if a.role == role and (a.value or a.model_value)]
        for rank in (lambda a: a.origin == "analyst", lambda a: a.status == "verified", lambda a: True):
            for a in members:
                if rank(a):
                    return a.value or a.model_value
        return None
    return pick("start"), pick("end")


def status_counts(times: list[TemporalAssertion]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in times:
        counts[a.status] = counts.get(a.status, 0) + 1
    return counts


# ── Publication date in the text header and in page metadata ─────────────────

# No `\b`: RE2's is ASCII-only, so it never fires after "publié".  The word
# boundary is checked in Python (`_header_key`).
_R_HEADER_KEY = compile_pattern(
    r"(published|posted|publication date|date published|release date|last updated|updated|"
    r"publié|publie|mis à jour|mis a jour|date)")
_R_DATE_IN_LINE = compile_pattern(
    r"(\d{4}-\d{2}-\d{2}|\d{1,2}(?:st|nd|rd|th|er)?\s+[^\s\d,]+\.?,?\s+\d{4}|"
    r"[^\s\d,]+\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})")
_HEADER_PRIORITY = {"published": 0, "date_line": 1, "updated": 2}


def _day_in(fragment: str) -> str | None:
    for m in _R_DATE_IN_LINE.finditer(fragment):
        got = _read_absolute(_strip_leading(m.group(1))[0], None)
        if got and got.status == "verified" and got.precision == "day" and got.value:
            year = int(got.value[:4])
            if 1990 <= year <= datetime.now(timezone.utc).year + 1:
                return got.value
    return None


def _header_key(line: str):
    """The first publication keyword standing as a whole word ("date" in
    "candidate" or "dated" is not one)."""
    for m in _R_HEADER_KEY.finditer(line):
        before = line[m.start() - 1] if m.start() > 0 else " "
        after = line[m.end()] if m.end() < len(line) else " "
        if not before.isalpha() and not after.isalpha():
            return m
    return None


def header_candidates(text: str, *, max_lines: int = 60, max_chars: int = 4000) -> list[dict]:
    """Publication-date candidates near the top of the text: a keyed line
    ("Published: 12 March 2024", "Posted by … on Monday, 25 April 2022") or a
    line that is nothing but a full date."""
    out: list[dict] = []
    lines = (text or "")[:max_chars].splitlines()[:max_lines]
    for line in lines:
        folded = fold(line)[0].strip(" ")
        if not folded:
            continue
        key = _header_key(folded)
        if key:
            day = _day_in(folded[key.start():key.start() + 120])
            if day:
                word = key.group(1)
                kind = "updated" if "updated" in word or "mis" in word else "published"
                out.append({"value": day, "source": "text_header", "kind": kind,
                            "detail": line.strip()[:160]})
                continue
        whole = _read_absolute(_strip_leading(folded.strip(" .,;:"))[0], None)
        if whole and whole.status == "verified" and whole.precision == "day" and whole.value:
            out.append({"value": whole.value, "source": "text_header", "kind": "date_line",
                        "detail": line.strip()[:160]})
    return out


_PUBLISHED_KEYS = ("article:published_time", "og:published_time", "datepublished", "pubdate",
                   "publishdate", "publish-date", "publish_date", "date", "dc.date",
                   "dc.date.issued", "dcterms.created", "dcterms.issued",
                   "citation_publication_date", "sailthru.date", "parsely-pub-date")
_MODIFIED_KEYS = ("article:modified_time", "og:updated_time", "datemodified", "dcterms.modified",
                  "last-modified")


def _jsonld_dates(node: Any, found: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key in ("datePublished", "dateCreated", "dateModified"):
            v = node.get(key)
            if isinstance(v, str):
                found.append((key.lower(), v))
        for v in node.values():
            _jsonld_dates(v, found)
    elif isinstance(node, list):
        for v in node:
            _jsonld_dates(v, found)


def publication_candidates(metas: list[tuple[str, str]], jsonld: list[str] | None = None,
                           times: list[tuple[str, str]] | None = None) -> list[dict]:
    """Publication-date candidates from a page's metadata: ``metas`` are
    (name-or-property, content) pairs, ``jsonld`` the raw JSON-LD blocks,
    ``times`` (itemprop, datetime) pairs of <time> elements.  Shared by the
    HTML upload path and the URL capture (which reads the rendered DOM)."""
    pairs: list[tuple[str, str]] = [(k.strip().lower(), v) for k, v in metas if k and v]
    for block in jsonld or []:
        try:
            found: list[tuple[str, str]] = []
            _jsonld_dates(json.loads(block), found)
            pairs.extend(found)
        except (TypeError, ValueError):
            continue
    # Only <time> elements that SAY what they date (itemprop): the first bare
    # <time> of a page may date anything.
    pairs.extend((k.strip().lower(), v) for k, v in (times or []) if k and v)
    out: list[dict] = []
    for key, raw in pairs:
        kind = ("published" if key in _PUBLISHED_KEYS or key == "datecreated"
                else "updated" if key in _MODIFIED_KEYS else None)
        if kind is None:
            continue
        got = _read_absolute(fold(raw)[0].strip(" "), None)
        if got is None or got.status != "verified" or not got.value:
            continue
        day = got.value[:10] if got.precision in ("day", "instant") else None
        if not day:
            continue
        if not 1990 <= int(day[:4]) <= datetime.now(timezone.utc).year + 1:
            continue
        out.append({"value": day, "source": "publication_meta", "kind": kind, "detail": key})
    return out


_SOURCE_PRIORITY = {"analyst": 0, "publication_meta": 1, "text_header": 2, "file_metadata": 3}


def choose_anchor(candidates: list[dict]) -> Anchor | None:
    """The document anchor from every candidate seen: publication metadata,
    then the text header, then the file's own timestamp; within one source a
    publication date before a bare date line before an update.  Every
    candidate is kept on the anchor, so a disagreement stays visible."""
    usable = [c for c in candidates if c.get("value") and c.get("source") in _SOURCE_PRIORITY]
    if not usable:
        return None
    best = min(usable, key=lambda c: (_SOURCE_PRIORITY[c["source"]],
                                      _HEADER_PRIORITY.get(c.get("kind", "published"), 3)))
    return Anchor(value=best["value"][:10], source=best["source"],
                  detail=best.get("detail"), candidates=usable)
