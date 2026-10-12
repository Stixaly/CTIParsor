"""The gazetteer's ordinary-word policy, step 2: the naming constructions that
identify an occurrence (docs/gazetteer-ordinary-words.md, "Operational
contract for context checks").

A CONTEXT form ("page", "route", "joker") is a name only when the sentence
names the object, and a form that names two ATT&CK objects ("snake",
"carbanak") only when the sentence says which.  `evidence` reads the
occurrence's unit and returns the ATT&CK IDs it names, and how:

- attached_id: "Machete (S0409)", "the Play threat actor (G1040)", a
  Markdown link label pointing to the object's ATT&CK page;
- alias: "Elise malware, also known as Page", "Turla, also called Snake",
  "Snake, the Uroburos malware" — the anchor is another name of the same
  object and must be identified itself (`anchor_ok`);
- typed: "Cuba ransomware", "the ping utility", "a ransomware called Cuba",
  "Joker, the Android billing-fraud malware" — with the nouns the form's rule
  lists, and the platform word it requires.  A form whose rule lists none
  ("play", "snake", "page") is never resolved by a type: "Play ransomware"
  does not say actor or software;
- command / executable: "ping -n 1 localhost", "The command route print",
  "expand.exe" — the command forms only.

Before them: an occurrence inside a URL, a file name or a dotted identifier
("landing_page.png", "KR.joker") is not a name (`embedded`), except an
executable for a command form; one inside a conflicting sense the rule names
("Google Play", "Joker's Stash") is `conflicting_sense`.

The unit is the sentence.  A Markdown list item, table row, heading or
indented code line is its own unit; a display-wrapped paragraph is read whole
before it is cut into sentences.  Nothing outside the unit counts: no
coreference across sentences.  Per-form rules:
pipeline/data/gazetteer_context_rules.json.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from api.logging_config import get_logger

logger = get_logger(__name__)

_PATH = Path(__file__).parent / "data" / "gazetteer_context_rules.json"

# (anchor name key, anchor start, anchor end, ATT&CK ID) -> is the anchor identified as that object
AnchorCheck = Callable[[str, int, int, str], bool]


@dataclass(frozen=True)
class Evidence:
    ids: frozenset[str] = frozenset()   # the ATT&CK IDs the unit names this occurrence as
    rule: str | None = None             # the construction that named the first one
    excluded: str | None = None         # embedded | conflicting_sense


@functools.lru_cache(maxsize=1)
def _load() -> tuple[dict, str | None]:
    try:
        raw = _PATH.read_bytes()
        return json.loads(raw), hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()[:12]
    except (OSError, ValueError) as exc:
        logger.warning(f"[gazetteer policy] {_PATH.name} unreadable, no construction qualifies a form: "
                       f"{type(exc).__name__}: {exc}")
        return {"forms": {}}, None


def rules_version() -> str | None:
    return _load()[1]


def form_rule(name_key: str) -> dict:
    return _load()[0].get("forms", {}).get(name_key, {})


# ── The unit ──────────────────────────────────────────────────────────────────

_STRUCTURAL = re.compile(r"^(?:\s*(?:[-*+]\s|\d+[.)]\s|\||#|>|```|~~~)|\t| {4})")
_SENTENCE_END = re.compile(r"[.!?][\"”’')\]]*\s+(?=[\"“'(\[]?[A-Z0-9])")


def _line(text: str, start: int, end: int) -> tuple[int, int]:
    ls = text.rfind("\n", 0, start) + 1
    le = text.find("\n", end)
    return ls, len(text) if le < 0 else le


def unit(text: str, start: int, end: int) -> tuple[int, int]:
    """Offsets of the sentence around text[start:end]."""
    ls, le = _line(text, start, end)
    if not _STRUCTURAL.match(text[ls:le]):
        while ls > 0:               # a display-wrapped paragraph: the plain lines around it
            prev = text.rfind("\n", 0, ls - 1) + 1
            line = text[prev:ls - 1]
            if not line.strip() or _STRUCTURAL.match(line):
                break
            ls = prev
        while le < len(text):
            nxt = text.find("\n", le + 1)
            nxt = len(text) if nxt < 0 else nxt
            line = text[le + 1:nxt]
            if not line.strip() or _STRUCTURAL.match(line):
                break
            le = nxt
    u0, u1 = ls, le
    for m in _SENTENCE_END.finditer(text, ls, le):
        if m.end() <= start:
            u0 = m.end()
        elif m.start() >= end:
            u1 = m.start() + 1
            break
    return u0, u1


# ── Not a name, or another sense ──────────────────────────────────────────────

def _char(text: str, i: int) -> str:
    return text[i] if 0 <= i < len(text) else ""


def _is_executable(text: str, end: int) -> bool:
    return text[end:end + 4].lower() == ".exe" and not _char(text, end + 4).isalnum()


def embedded(text: str, start: int, end: int) -> bool:
    """Inside a URL, a path, a file name or a dotted identifier — a
    Markdown link's label is not."""
    before, after = _char(text, start - 1), _char(text, end)
    if before and before in "/\\_@" or after and after in "/\\_@":
        return True
    if before == "." and _char(text, start - 2).isalnum():
        return True
    if after == "." and _char(text, end + 1).isalnum():
        return True
    if before == "[" and text.startswith("](", end):
        return False
    ts = max(text.rfind(c, 0, start) for c in " \t\n(<\"'") + 1
    return "://" in text[ts:start] or text[ts:start].lower().startswith("www.")


@functools.lru_cache(maxsize=256)
def _phrase(phrase: str) -> re.Pattern:
    body = re.escape(phrase).replace("'", "['’]").replace("’", "['’]")
    return re.compile(r"(?<![\w-])" + body + r"s?(?![\w-])", re.I)


def _conflicting(text: str, start: int, end: int, u0: int, u1: int, phrases) -> bool:
    return any(m.start() <= start and end <= m.end()
               for p in phrases for m in _phrase(p).finditer(text, u0, u1))


# ── Constructions ─────────────────────────────────────────────────────────────

_STOP = (r"(?:and|or|nor|of|in|on|to|with|for|the|a|an|by|from|is|was|are|were|as|at|that|which|this"
         r"|these|its|it|not|but|than|vs|versus)")
_ID_AFTER = re.compile(r"((?:[ \t]+[A-Za-z][\w-]*){0,3}?)[ \t]*[(\[][ \t]*(?:ID:?[ \t]*)?([GS]\d{4})[ \t]*[)\]]")
_ATTACK_LINK = re.compile(r"\]\((?:https?://)?attack\.mitre\.org/(?:software|groups)/([GS]\d{4})/?[)#]", re.I)


def _attached_id(text: str, start: int, end: int) -> str | None:
    if _char(text, start - 1) == "[":
        m = _ATTACK_LINK.match(text, end)
        if m:
            return m.group(1).upper()
    m = _ID_AFTER.match(text, end)
    if m and not re.search(rf"\b{_STOP}\b", m.group(1), re.I):
        return m.group(2)
    return None


_P = r"[\s,;:(\[\"“”'’]"
_CUE = (r"(?:also\s+known\s+as|also\s+called|also\s+referred\s+to\s+as|also\s+tracked\s+as|known\s+as"
        r"|a\.k\.a\.?|aka|dubbed)")
_NEG = r"(?:not|no|never|nor|unlike|unrelated|distinct|different)"
_ALIAS_GAP = re.compile(rf"{_P}*(?:(?!{_NEG}\b)[\w-]+{_P}+){{0,3}}?{_CUE}{_P}*(?:the\s+)?", re.I)
_APPOSITIVE_GAP = re.compile(r",\s+the\s+", re.I)
_MAX_GAP = 80


@functools.lru_cache(maxsize=4096)
def _name_re(name_key: str) -> re.Pattern:
    return re.compile(r"(?<![^\W_])(?<!-)" + re.escape(name_key) + r"(?![^\W_])(?!-)", re.I)


def _alias(text: str, start: int, end: int, u0: int, u1: int, names, cid: str,
           anchor_ok: AnchorCheck) -> bool:
    """`names` (another name of `cid`) stands in an alias relation with the occurrence."""
    for name in names:
        for m in _name_re(name).finditer(text, u0, u1):
            a0, a1 = m.span()
            if a1 <= start:
                gap = text[a1:start]
                ok = len(gap) <= _MAX_GAP and _ALIAS_GAP.fullmatch(gap)
            elif a0 >= end:
                gap = text[end:a0]
                ok = len(gap) <= _MAX_GAP and (_ALIAS_GAP.fullmatch(gap) or _APPOSITIVE_GAP.fullmatch(gap))
            else:
                continue
            if ok and anchor_ok(name, a0, a1, cid):
                return True
    return False


@functools.lru_cache(maxsize=256)
def _typed_res(nouns: tuple[str, ...]) -> tuple[re.Pattern, re.Pattern, re.Pattern]:
    alt = "|".join(re.escape(n).replace(r"\ ", r"\s+") for n in sorted(nouns, key=len, reverse=True))
    after = re.compile(rf"[ \t]+(?:(?!{_STOP}\b)[\w-]+[ \t]+)?(?:{alt})(?![\w-])", re.I)
    appositive = re.compile(rf",[ \t]+(?:the|an?)[ \t]+(?:[\w-]+[ \t]+){{0,3}}?(?:{alt})(?![\w-])", re.I)
    before = re.compile(rf"(?<![\w-])(?:{alt})[ \t]+(?:family[ \t]+)?(?:called|named|dubbed|known[ \t]+as)"
                        r"[ \t]+[\"“']?$", re.I)
    return after, appositive, before


def _typed(text: str, start: int, end: int, u0: int, u1: int, rule: dict) -> bool:
    nouns = tuple(rule.get("typed", ()))
    if not nouns:
        return False
    required = rule.get("requires")
    if required and not any(_name_re(w).search(text, u0, u1) for w in required):
        return False
    after, appositive, before = _typed_res(nouns)
    return bool(after.match(text, end, u1) or appositive.match(text, end, u1)
                or before.search(text[u0:start]))


_RUN_WORDS = frozenset({"run", "runs", "ran", "running", "execute", "executes", "executed", "executing",
                        "launch", "launches", "launched", "invoke", "invokes", "invoked", "issue", "issues",
                        "issued", "command", "commands", "use", "uses", "used", "using", "call", "calls",
                        "called", "via"})


def _command(text: str, start: int, end: int, args: str) -> bool:
    """The form in a command position, followed by the arguments its rule lists."""
    if not re.compile(r"[ \t]+" + args, re.I).match(text, end):
        return False
    ls, _ = _line(text, start, end)
    prefix = text[ls:start]
    if re.search(r"\becho\b", prefix[-40:], re.I):
        return False
    p = prefix.rstrip()
    if not p or p[-1] in "`>$#|&;:(" or re.search(r"(?:/c|/k|-c|-command)$", p, re.I):
        return True
    words = re.findall(r"[A-Za-z]+", p)
    return bool(words) and words[-1].lower() in _RUN_WORDS


def evidence(text: str, start: int, end: int, name_key: str, candidates: Mapping[str, str],
             names_by_id: Mapping[str, frozenset[str]], anchor_ok: AnchorCheck | None) -> Evidence:
    """What the unit around text[start:end] says the occurrence names, among
    `candidates` (ATT&CK ID -> entity type).  `anchor_ok` None: no alias
    construction (an anchor's own check, so as not to loop)."""
    rule = form_rule(name_key)
    single = frozenset(candidates) if len(candidates) == 1 else frozenset()
    if rule.get("command") and _is_executable(text, end):
        return Evidence(single, "executable" if single else None)
    if embedded(text, start, end):
        return Evidence(excluded="embedded")
    u0, u1 = unit(text, start, end)
    if _conflicting(text, start, end, u0, u1, rule.get("exclude", ())):
        return Evidence(excluded="conflicting_sense")

    found: dict[str, str] = {}
    attached = _attached_id(text, start, end)
    if attached is not None and attached in candidates:
        found[attached] = "attached_id"
    if anchor_ok is not None:
        for cid in candidates:
            if cid not in found and _alias(text, start, end, u0, u1,
                                           sorted(names_by_id.get(cid, frozenset()) - {name_key}),
                                           cid, anchor_ok):
                found[cid] = "alias"
    if not found and single:
        if _typed(text, start, end, u0, u1, rule):
            found = dict.fromkeys(single, "typed")
        elif rule.get("command") and _command(text, start, end, rule["command"]):
            found = dict.fromkeys(single, "command")
    return Evidence(frozenset(found), next(iter(found.values()), None))
