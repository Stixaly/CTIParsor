"""One definition of "is this string a hostname", shared by every rule format (ADR-0015).

Both the Suricata and YARA atom extractors must decide whether a literal found in
a rule is a domain or just a dotted identifier.  Getting it wrong is expensive in
one direction only: a bogus domain atom is rare *by construction*, so it earns a
high IDF in `pipeline.detection.relevance` and scores near 1.0 — the ADR-0014
failure mode of confident nonsense at the top of the list.

Measured cases this exists to reject, all of which satisfy the generic
"labels separated by dots, alphabetic last label" shape:

    aventail.epinstaller        ActiveX ProgID (ET Open browser-exploit rules)
    keyhelp.keyscript           ActiveX ProgID
    kernel32.dll                Windows import (YARA string literals)
    qexplain2.explainplandisplayx

Stricter than `stage2_extraction._DOMAIN_PATTERN`, deliberately: IoC extraction
from prose wants recall and gets human review, an atom index wants precision and
gets none.

Pure and stdlib-only.
"""
from __future__ import annotations

import re

#: Generic TLDs.  Any two-letter label is additionally accepted as a ccTLD, which
#: covers .ru/.cn/.io/.co without enumerating ~250 entries.
GTLDS: frozenset[str] = frozenset({
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "arpa",
    "top", "xyz", "online", "site", "club", "shop", "app", "dev", "cloud",
    "live", "icu", "vip", "work", "website", "space", "store", "tech", "fun",
    "pro", "news", "today", "one", "link", "click", "download", "stream",
    "win", "bid", "loan", "men", "party", "review", "trade", "date", "racing",
    "science", "accountant", "faith", "cricket", "name", "mobi", "asia", "tel",
    "email", "life", "world", "host", "press", "wiki", "blog", "agency",
    # Reserved (RFC 7686) rather than generic, but a Tor hidden service is a
    # first-class C2 indicator in CTI. Measured: on 1,399 domain-shaped Sigma
    # atoms that failed only the TLD test, `.onion` was the sole real-domain
    # category — everything else was a filename (.exe 382, .zip 163, .ps1 152).
    "onion",
})

_RE_DOMAIN = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$"
)


def looks_like_domain(s: str) -> bool:
    """Is *s* a hostname rather than a dotted identifier that resembles one?

    Args:
        s: candidate value.  Compared lowercased; callers need not pre-fold.

    Returns:
        True only when the structure is domain-shaped *and* the final label is a
        two-letter ccTLD or a member of :data:`GTLDS`.  Shape alone is not
        sufficient — see the module docstring.
    """
    if not isinstance(s, str):
        return False
    s = s.strip().lower()
    if not s or "." not in s or not _RE_DOMAIN.match(s):
        return False
    last = s.rsplit(".", 1)[-1]
    if not last.isalpha():
        return False
    return len(last) == 2 or last in GTLDS
