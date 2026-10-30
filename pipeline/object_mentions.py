"""
Descriptions for named STIX objects that the report itself never describes (ADR-0093).

An object Stage 4 emits without a `description` gets the sentences of the report
that name it, rendered as Markdown.  Matching is on the object's names alone, no
model is involved, so every sentence shown is the report's own text.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence

from pipeline.evidence_span import sentence_bounds
from pipeline.markdown_text import blockquote, collapse_whitespace, escape_inline
from pipeline.regex_safety import glued_to_a_word

#: The STIX types whose objects get a description from their mentions.
MENTION_TYPES: frozenset[str] = frozenset(
    {"malware", "threat-actor", "intrusion-set", "campaign", "tool", "infrastructure"}
)

# Shorter names are noise: "US" and "C2" occur inside ordinary sentences.
_MIN_NAME_LENGTH = 3


def find_mentions(text: str, names_by_id: Mapping[str, Sequence[str]], *,
                  limit: int = 3, max_chars: int = 400,
                  cased: Collection[str] = frozenset()) -> dict[str, list[str]]:
    """The sentences of `text` that name each id, in document order.

    A name matches case-insensitively, at a word boundary; a name in `cased`
    (compared lower-cased) only where the text writes it with an initial
    capital, since it is also an ordinary word ("Silence", not "went into
    silence").  At most `limit` sentences per id, each collapsed to one line and
    cut to `max_chars`.  Only ids with at least one sentence are in the result.
    """
    cased_keys = {collapse_whitespace(name).lower() for name in cased}
    needles: dict[str, list[tuple[str, bool]]] = {}
    for mention_id, names in names_by_id.items():
        kept = [(key, key in cased_keys)
                for key in (collapse_whitespace(name).lower() for name in names)
                if len(key) >= _MIN_NAME_LENGTH]
        if kept:
            needles[mention_id] = kept

    # The report is split once, not once per object: it can hold hundreds of
    # thousands of characters and a hundred objects.
    found: dict[str, list[str]] = {mention_id: [] for mention_id in needles}
    for start, end in sentence_bounds(text):
        # Collapsed: a PDF breaks lines inside a name ("Lazarus\nGroup"), and two
        # sentences that differ only in their line breaks are shown once.
        key = collapse_whitespace(text[start:end])
        # Lower-cased one character at a time, keeping any whose lower case is
        # longer ("İ"): the copy keeps the sentence's offsets, so the casing of
        # a match can be read in `key` at the same position.
        lowered = "".join(c if len(c.lower()) != 1 else c.lower() for c in key)
        for mention_id, kept in needles.items():
            shown = found[mention_id]
            if len(shown) < limit and key not in shown and any(
                    _named(key, lowered, name, initial_capital) for name, initial_capital in kept):
                shown.append(key)

    return {
        mention_id: [_clip(sentence, max_chars) for sentence in sentences]
        for mention_id, sentences in found.items()
        if sentences
    }


def mention_description(report_name: str, sentences: Sequence[str]) -> str | None:
    """The Markdown description of an object from its `sentences`, or None without any.

    Each sentence is a blockquote, with a blank line before the next: two `>`
    lines in a row would merge into one quote.
    """
    if not sentences:
        return None
    # Collapsed: a blank line in the name would end the paragraph before the closing `*`.
    name = collapse_whitespace(report_name)
    head = f"Mentioned in *{escape_inline(name)}*:" if name else "Mentioned in the report:"
    return "\n\n".join([head, *(blockquote(sentence) for sentence in sentences)])


def _named(sentence: str, lowered: str, name: str, initial_capital: bool) -> bool:
    """Does `name` occur in `lowered` as a whole word, written in `sentence`
    with an initial capital when `initial_capital` is set?"""
    pos = lowered.find(name)
    while pos != -1:
        if (not glued_to_a_word(lowered, pos, pos + len(name))
                and (not initial_capital or sentence[pos].isupper())):
            return True
        pos = lowered.find(name, pos + 1)
    return False


def _clip(sentence: str, max_chars: int) -> str:
    """`sentence` cut to `max_chars` characters, with an ellipsis if it was cut.

    The space left before the cut is dropped, so the ellipsis follows the word.
    """
    if len(sentence) <= max_chars:
        return sentence
    return sentence[:max_chars].rstrip() + "…"
