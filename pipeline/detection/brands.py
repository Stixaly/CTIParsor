# pipeline/detection/brands.py
"""
ADR-0031: Brand token extraction from campaign domains.

Recurrence across domains is the anti-noise filter: a substring appearing in
multiple domains of a single campaign is a theme, not a random artifact.
Measured: okta 7 domains / 31 rules, polygon 13 / 22, ms365 3 / 8.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from pipeline.detection.control import is_ubiquitous


@dataclass(frozen=True, slots=True)
class BrandToken:
    """One campaign theme that the rule corpus also names."""
    token: str
    domains: int
    rules: int


#: A substring must recur across at least this many of the report's domains to
#: count as a campaign theme. Measured: `okta` reaches 7 of UNC6671's 79 domains,
#: `polygon` 13 of aeternum's 25, `ms365` 3 of distinct-clusters' 31 -- while the
#: random single-use domain `sqfepjvmrd.xyz` contributes nothing at any threshold.
BRAND_MIN_DOMAINS = 3

#: Below four characters a substring is noise; above fourteen it is a whole
#: domain label rather than a theme.
BRAND_MIN_LEN = 4
BRAND_MAX_LEN = 14

#: A token naming more canonical rules than this is corpus vocabulary, not a
#: brand. Measured against the live store (75,127 canonical rules), which is what
#: sets the boundary: okta 31, polygon 22, ms365 8, tenderly 4 -- all real
#: identities. Against: port 160, create 155, secure 124, keys 98, portal 96,
#: gateway 81, share 77, public 75, connect 64, enable 58, pass 55 -- all generic
#: words that merely happen to appear in phishing domain names. The cut sits in
#: the gap.
BRAND_MAX_TITLE_RULES = 50

#: Words phishing domains are BUILT from. They pass the recurrence test by
#: construction -- a campaign that registers `activatepasskey.com`,
#: `enablepasskey.com` and `setpasskey.com` makes `passkey` recur 60 times -- but
#: they name a concept, never a product, so they must not become brands. This is
#: the same instrument as control.UBIQUITOUS_CATEGORY_WORDS, scoped to the
#: vocabulary of domain construction rather than of malware naming.
DOMAIN_STOPWORDS: frozenset[str] = frozenset({
    # authentication and identity concepts
    "passkey", "passkeys", "password", "passwd", "credential", "credentials",
    "login", "logon", "signin", "signon", "auth", "authentication", "oauth",
    "token", "session", "verify", "verification", "validate", "confirm",
    "secure", "security", "safety", "protect", "protection", "trust",
    "identity", "ident", "account", "accounts", "profile", "user", "users",
    "member", "members", "client", "customer", "admin", "administrator",
    "access", "permission", "role", "group", "team", "tenant", "directory",
    # the actions a phishing page asks for
    "activate", "activation", "register", "registration", "enroll",
    "enrollment", "enable", "disable", "setup", "install", "installer",
    "deploy", "deployment", "rollout", "roll", "create", "creator", "creation",
    "make", "start", "begin", "add", "assign", "set", "reset", "renew",
    "update", "upgrade", "migrate", "sync", "connect", "connection", "link",
    "check", "status", "manage", "management", "config", "settings",
    "download", "upload", "share", "sharing", "invite", "invitation",
    "request", "submit", "apply", "approve", "unlock", "recover", "recovery",
    # generic infrastructure and web nouns
    "portal", "port", "gateway", "gate", "hub", "center", "centre", "central",
    "service", "services", "server", "host", "hosting", "node", "cloud",
    "online", "web", "website", "site", "page", "home", "index", "main",
    "network", "system", "platform", "app", "apps", "application", "mobile",
    "device", "devices", "desktop", "client", "api", "endpoint", "console",
    "dashboard", "panel", "office", "work", "workspace", "desk", "helpdesk",
    "help", "support", "contact", "info", "information", "data", "file",
    "files", "document", "documents", "drive", "storage", "backup", "archive",
    "mail", "email", "webmail", "inbox", "message", "messages", "chat",
    "meet", "meeting", "call", "conference", "video", "view", "open", "click",
    "alert", "notice", "notify", "notification", "warning", "urgent",
    # qualifiers that carry no identity
    "official", "global", "world", "international", "national", "local",
    "public", "private", "internal", "external", "new", "newest", "latest",
    "best", "free", "premium", "pro", "plus", "prime", "smart", "quick",
    "fast", "easy", "simple", "direct", "live", "real", "true", "auto",
    "self", "personal", "business", "corporate", "enterprise", "company",
    "group", "solution", "solutions", "tech", "technology", "digital",
    "network", "connect", "sync", "keys", "key", "code", "codes", "pass",
})


def _label(domain: str) -> str:
    """Extract the registrable label without TLD, dots, or hyphens."""
    if "." in domain:
        domain = domain.rsplit(".", 1)[0]
    # Dots as well as hyphens: `api.zan.top` must yield `apizan`, not `api.zan`,
    # or the theme carries a separator and reads as `api.` in the output.
    return domain.replace("-", "").replace(".", "").lower()


def _substrings(label: str) -> set[str]:
    """Generate all substrings of length BRAND_MIN_LEN to BRAND_MAX_LEN."""
    if len(label) < BRAND_MIN_LEN:
        return set()
    subs = set()
    for i in range(len(label)):
        for j in range(i + BRAND_MIN_LEN, min(i + BRAND_MAX_LEN + 1, len(label) + 1)):
            subs.add(label[i:j])
    return subs


def _maximal(counts: dict[str, int]) -> dict[str, int]:
    """Remove tokens that are substrings of longer tokens with equal or higher counts."""
    tokens = list(counts.keys())
    to_remove = set()
    for s in tokens:
        for t in tokens:
            if s != t and s in t and len(t) > len(s) and counts[t] >= counts[s]:
                to_remove.add(s)
                break
    return {k: v for k, v in counts.items() if k not in to_remove}


def campaign_tokens(domains: Iterable[str]) -> dict[str, int]:
    """Recurring substrings across a campaign's domain labels → domain count."""
    valid_domains = [d for d in domains if isinstance(d, str) and d.strip()]
    if not valid_domains:
        return {}

    labels = {_label(d) for d in valid_domains}
    counter: Counter[str] = Counter()
    for label in labels:
        for sub in _substrings(label):
            counter[sub] += 1

    filtered = {k: v for k, v in counter.items() if v >= BRAND_MIN_DOMAINS}
    return _maximal(filtered)


def rule_text_built(conn: sqlite3.Connection) -> bool:
    """Return True if the rule_text FTS5 table exists and is non-empty."""
    try:
        cur = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='rule_text'"
        )
        if cur.fetchone() is None:
            return False
        cur = conn.execute("SELECT rule_id FROM rule_text LIMIT 1")
        return cur.fetchone() is not None
    except sqlite3.Error:
        return False


def brand_tokens(conn: sqlite3.Connection, domains: Iterable[str]) -> list[BrandToken]:
    """Find brand tokens that appear in a limited number of canonical rules."""
    counts = campaign_tokens(domains)
    if not counts:
        return []

    candidates = [
        tok for tok in counts
        if tok not in DOMAIN_STOPWORDS and not is_ubiquitous("name", tok)
    ]
    if not candidates:
        return []

    if not rule_text_built(conn):
        return []

    results: list[BrandToken] = []
    for tok in candidates:
        param = '"' + tok.replace('"', '') + '"'
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM rule_text WHERE body MATCH ?", (param,)
            )
            count = cur.fetchone()[0]
        except sqlite3.Error:
            continue
        if 1 <= count <= BRAND_MAX_TITLE_RULES:
            results.append(BrandToken(token=tok, domains=counts[tok], rules=count))

    results.sort(key=lambda t: (-t.rules, t.token))
    return results


def brand_evidence(
    conn: sqlite3.Connection | None, tokens: list[BrandToken]
) -> dict[str, list[dict]]:
    """Return evidence dicts mapping rule_id to a list of brand matches."""
    if not tokens:
        return {}
    if conn is None or not rule_text_built(conn):
        return {}

    evidence: dict[str, list[dict]] = {}
    for tok in tokens:
        param = '"' + tok.token.replace('"', '') + '"'
        try:
            cur = conn.execute(
                "SELECT rule_id FROM rule_text WHERE body MATCH ?", (param,)
            )
            rows = cur.fetchall()
        except sqlite3.Error:
            continue
        for (rule_id,) in rows:
            # FTS5 indexes title and description in a single 'body' column,
            # so we cannot distinguish them. The distinction was unnecessary
            # as both produced equal-weight evidence, and keeping it would
            # have required a second indexed column.
            evidence.setdefault(rule_id, []).append({
                "obs_class": "brand",
                "display": tok.token,
                "value": tok.token,
                "field": "title",
                "discriminating": False,
                "kind": "title",
            })

    for rule_id in evidence:
        evidence[rule_id].sort(key=lambda e: e["display"])

    return evidence


def cve_evidence(conn: sqlite3.Connection, cves: Iterable[str]) -> dict[str, list[dict]]:
    """rule_id → title matches for the report's CVE ids (ADR-0031).

    Same FTS mechanism as `brand_evidence`, but with no recurrence test, no
    stopword list and no rule cap: a CVE id is specific by construction, so it
    needs none of the guards a mined token does. Measured on the live store,
    `cve-2021-44228` names 120 rules and `cve-2024-3400` names 10 — while this
    report's three 2026 zero-days name none, the public corpora not having caught
    up, which is the honest answer rather than a failure.

    Like every title match it carries `discriminating: False`: the rule is ABOUT
    this CVE, it does not HOLD a value from the report.
    """
    values = sorted({c.strip().lower() for c in cves if isinstance(c, str) and c.strip()})
    if not values or not rule_text_built(conn):
        return {}

    evidence: dict[str, list[dict]] = {}
    for cve in values:
        param = '"' + cve.replace('"', "") + '"'
        try:
            rows = conn.execute(
                "SELECT rule_id FROM rule_text WHERE body MATCH ?", (param,)
            ).fetchall()
        except sqlite3.Error:
            continue
        for (rule_id,) in rows:
            evidence.setdefault(rule_id, []).append({
                "obs_class": "cve",
                "display": cve.upper(),
                "value": cve,
                "field": "title",
                "discriminating": False,
                "kind": "title",
            })

    for evs in evidence.values():
        evs.sort(key=lambda e: e["display"])
    return evidence
