# pipeline/evidence_span.py
"""
Module to locate LLM-generated quotes within source text and return character
spans in the original coordinate system.
"""

from bisect import bisect_right
from dataclasses import dataclass

# Character substitutions PDF extraction introduces.  Each maps ONE source
# character to ONE replacement character, so normalising never shifts offsets —
# the index map below depends on that invariant.
_CHAR_MAP: dict[str, str] = {
    "’": "'",   # right single quote
    "‘": "'",   # left single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    "–": "-",   # en dash
    "—": "-",   # em dash
    "−": "-",         # minus sign
    # Written as escapes on purpose: as literal characters these are
    # indistinguishable in a diff and silently collapse into one duplicate key,
    # which is exactly what happened the first time this table was written.
    " ": " ",    # no-break space
    " ": " ",    # thin space
    " ": " ",    # narrow no-break space
    "​": " ",    # zero-width space
    " ": " ",    # figure space
}

# Ligatures are ONE character that must become TWO or more, so they cannot go in
# _CHAR_MAP without breaking the offset invariant.  They are handled by the
# index map, which records the original position of every emitted character.
_LIGATURES: dict[str, str] = {
    "ﬀ": "ff",
    "ﬁ": "fi",
    "ﬂ": "fl",
    "ﬃ": "ffi",
    "ﬄ": "ffl",
}


@dataclass(frozen=True)
class Span:
    """Represents a span of characters in the original text."""
    start: int          # offset into the ORIGINAL text, inclusive
    end: int            # offset into the ORIGINAL text, exclusive
    coverage: float     # fraction of the quote's words matched, 0.0..1.0
    exact: bool         # True when coverage >= 0.99


def _normalise(text: str) -> tuple[str, list[int]]:
    """
Normalise for comparison, keeping a map back to original offsets.

    Returns (normalised, index_map) where index_map[i] is the offset in the
    ORIGINAL text of the character normalised[i] — so a match found in the
    normalised string can be reported as a span of the text the caller passed in.
    """
    if not text:
        return "", []

    normalised_chars: list[str] = []
    index_map: list[int] = []

    i = 0
    n = len(text)

    while i < n:
        char = text[i]

        if char in _LIGATURES:
            replacement = _LIGATURES[char]
            for c in replacement:
                normalised_chars.append(c)
                index_map.append(i)
            i += 1
        elif char in _CHAR_MAP:
            normalised_chars.append(_CHAR_MAP[char])
            index_map.append(i)
            i += 1
        elif char.isspace():
            # Emit ONE space
            normalised_chars.append(" ")
            index_map.append(i)
            # Skip all consecutive whitespace
            while i < n and text[i].isspace():
                i += 1
        else:
            normalised_chars.append(char.lower())
            index_map.append(i)
            i += 1

    return "".join(normalised_chars), index_map


def _word_spans(normalised: str) -> list[tuple[int, int]]:
    """
    Splits normalized text into words separated by single spaces.
    Returns list of (start, end) offsets for each word.
    """
    spans = []
    if not normalised:
        return spans

    start = 0
    n = len(normalised)

    while start < n:
        # Skip spaces
        while start < n and normalised[start] == ' ':
            start += 1
        if start >= n:
            break

        end = start
        while end < n and normalised[end] != ' ':
            end += 1

        spans.append((start, end))
        start = end

    return spans


def locate(quote: str, text: str, *, min_coverage: float = 0.6) -> Span | None:
    """
Locate *quote* in *text*, returning a span in original coordinates.

    Returns None when nothing reaches *min_coverage*.  Quotes shorter than three
    words are refused outright: a one- or two-word fragment matches almost
    anywhere and would make the span meaningless.
    """
    # a) Guards
    if not isinstance(quote, str) or not isinstance(text, str):
        return None
    if not quote or not text:
        return None

    # Normalize
    nq, _ = _normalise(quote)
    nt, imap = _normalise(text)

    # Check word count of quote
    q_words = _word_spans(nq)
    total_mots = len(q_words)

    if total_mots < 3:
        return None

    # c) Exact match
    pos = nt.find(nq)
    if pos != -1:
        start_orig = imap[pos]
        end_orig = imap[pos + len(nq) - 1] + 1
        # Bound by text length
        end_orig = min(end_orig, len(text))
        return Span(start=start_orig, end=end_orig, coverage=1.0, exact=True)

    # d) Longest prefix
    # We need to find the largest k such that the first k words of nq joined by space are in nt.
    # Binary search on k? Or linear?
    # "par recherche dichotomique sur le nombre de mots"

    # Let's extract the words of nq
    # We can just split nq by space since it's normalized
    nq_words = nq.split(' ')

    def find_prefix_span(k: int) -> Span | None:
        if k <= 0:
            return None
        prefix_str = ' '.join(nq_words[:k])
        p = nt.find(prefix_str)
        if p == -1:
            return None
        start_orig = imap[p]
        end_orig = imap[p + len(prefix_str) - 1] + 1
        end_orig = min(end_orig, len(text))
        return Span(start=start_orig, end=end_orig, coverage=k / total_mots, exact=False)

    def find_suffix_span(k: int) -> Span | None:
        if k <= 0:
            return None
        suffix_str = ' '.join(nq_words[-k:])
        p = nt.find(suffix_str)
        if p == -1:
            return None
        start_orig = imap[p]
        end_orig = imap[p + len(suffix_str) - 1] + 1
        end_orig = min(end_orig, len(text))
        return Span(start=start_orig, end=end_orig, coverage=k / total_mots, exact=False)

    # Binary search for largest k in [1, total_mots] such that prefix exists
    # Note: if k works, k-1 might not? No, if a string of k words is found,
    # the string of k-1 words (prefix) is a substring of it, so it must be found.
    # So the predicate "prefix of length k is found" is monotonic: True for small k, False for large k.

    lo, hi = 1, total_mots
    best_k = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if find_prefix_span(mid) is not None:
            best_k = mid
            lo = mid + 1
        else:
            hi = mid - 1

    if best_k > 0:
        span = find_prefix_span(best_k)
        if span and span.coverage >= min_coverage:
            return span

    # e) Longest suffix
    lo, hi = 1, total_mots
    best_k = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        if find_suffix_span(mid) is not None:
            best_k = mid
            lo = mid + 1
        else:
            hi = mid - 1

    if best_k > 0:
        span = find_suffix_span(best_k)
        if span and span.coverage >= min_coverage:
            return span

    # f) None
    return None


def sentence_index_of(span: Span, sentence_bounds: list[tuple[int, int]]) -> int | None:
    """
    Finds the index of the sentence containing the span's start offset.
    """
    if not sentence_bounds:
        return None

    starts = [b[0] for b in sentence_bounds]

    # bisect_right returns the insertion point.
    # We want the last start <= span.start.
    # bisect_right(starts, span.start) gives index of first element > span.start.
    # So the candidate is at index - 1.

    idx = bisect_right(starts, span.start) - 1

    if idx < 0:
        return None

    # Check if span.start is within [start, end)
    s_start, s_end = sentence_bounds[idx]
    if s_start <= span.start < s_end:
        return idx

    return None


def sentence_bounds(text: str) -> list[tuple[int, int]]:
    """
    Splits text into sentences and returns their (start, end) offsets.
    Separators: . ! ? followed by whitespace, or double newline.
    """
    if not text:
        return []

    bounds = []
    # Regex to find sentence endings
    # Matches . ! ? followed by whitespace, or \n\n
    # We want to split on these.

    # Let's iterate manually to be safe and precise with offsets.
    i = 0
    n = len(text)
    start = 0

    while i < n:
        # Terminal punctuation followed by whitespace ends a sentence.  The
        # punctuation belongs to the span; the whitespace after it does not.
        if text[i] in ".!?" and (i + 1 < n and text[i + 1].isspace()):
            if text[start:i + 1].strip():
                bounds.append((start, i + 1))
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            start = j
            i = j
        # A blank line ends a sentence too: headings, bullet lists and IoC
        # tables in CTI reports carry no terminal punctuation at all, and
        # without this every such block would fuse into its neighbour.  The
        # newlines are the separator, so the span stops before them.
        elif text[i] == '\n' and i + 1 < n and text[i + 1] == '\n':
            if text[start:i].strip():
                bounds.append((start, i))
            start = i + 2
            i = i + 2
        else:
            i += 1

    # Handle last fragment
    if start < n:
        fragment = text[start:n]
        if fragment.strip():
            bounds.append((start, n))

    return bounds
