# pipeline/detection/brands.py
"""
ADR-0031: Brand token extraction from campaign domains.

Recurrence across domains is the anti-noise filter: a substring appearing in
multiple domains of a single campaign is a theme, not a random artifact.
Measured: okta 7 domains / 31 rules, polygon 13 / 22, ms365 3 / 8.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from api.db import DB_ERRORS
from api.db_backend import DBConnection
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
    "device", "devices", "desktop", "api", "endpoint", "console",
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
    "solution", "solutions", "tech", "technology", "digital",
    "keys", "key", "code", "codes", "pass",
})


#: PostgreSQL's `simple` parser keeps a hyphen inside a number (`CVE-2024-3400`
#: gives '-2024' '-3400') but splits an underscore (`CVE_2024_3400` gives '2024'
#: '3400'), so the two spellings of one id never met in the index (#424). The
#: indexed body and the query both go through this table, so they meet.
_SEPARATORS = str.maketrans({"-": " ", "_": " "})


def _as_words(text: str) -> str:
    """Turn `-` and `_` into spaces, so an id tokenises the same whatever its separator."""
    return text.translate(_SEPARATORS)


def _domain_key(domain: str) -> str:
    """Normalise a full domain for counting: case, trailing dot, leading `www.`.

    Two spellings of one host are one domain; two TLDs of one name are two.
    """
    key = domain.strip().lower().rstrip(".")
    if key.startswith("www."):
        key = key[len("www."):]
    return key


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
    """Recurring substrings across a campaign's domains → distinct domain count.

    These are candidates, not yet maximal: `brand_tokens` applies `_maximal`
    after the rule filter (#423), so a longer token that names no rule cannot
    remove the substring that does.

    Deduplication happens on the full normalised domain, before the TLD is cut:
    `frostledger.com`, `.net` and `.org` are three domains (issue #361), even
    though they share one label.
    """
    valid_domains = [d for d in domains if isinstance(d, str) and d.strip()]
    if not valid_domains:
        return {}

    keys = {_domain_key(d) for d in valid_domains}
    counter: Counter[str] = Counter()
    for key in keys:
        for sub in _substrings(_label(key)):
            counter[sub] += 1

    # A brand names something: a run of digits ("2024" in three domains) is not
    # one, and since rule_text splits CVE ids into words (#424) it would match
    # every CVE-2024-* title.
    return {k: v for k, v in counter.items()
            if v >= BRAND_MIN_DOMAINS and any(ch.isalpha() for ch in k)}


def rule_text_built(conn: DBConnection) -> bool:
    """Return True if the rule_text index exists and is non-empty.

    init_db() always creates rule_text now (ADR-0053), so this only ever
    guards "not yet populated" (scripts/build_rule_text.py hasn't run) rather
    than "table absent" the way it did against an older SQLite database.
    """
    try:
        cur = conn.execute("SELECT rule_id FROM rule_text LIMIT 1")
        return cur.fetchone() is not None
    except DB_ERRORS:
        return False


def rebuild_rule_text(conn: DBConnection, *, batch: int = 2000) -> dict:
    """Replace the rule_text index with one row per canonical rule (ADR-0031).

    Deletes every row, then indexes the title and description of each rule with
    `is_canonical=1` as one lower-cased string, with `-` and `_` turned into
    spaces (#424, see `_as_words`). A rule with an empty body is not
    indexed. Returns `{"rows": <rows written>, "empty_bodies": <rules skipped>}`.

    Opens no transaction and commits none: the caller wraps it (rebuild_store and
    scripts/build_rule_text.py do), so a failure can roll the index back. Called
    after the dedup pass, it indexes only the elected canonical rules, which is
    why a rebuild of the rule store no longer leaves the index stale (#363).
    """
    conn.execute("DELETE FROM rule_text")
    rows_written = 0
    empty_bodies = 0
    pending: list[tuple[str, str]] = []

    cur = conn.execute(
        "SELECT id, COALESCE(title,''), COALESCE(description,'') "
        "FROM detection_rules WHERE is_canonical=1"
    )
    for rule_id, title, description in cur:
        body = _as_words(f"{title} {description}".strip().lower()).strip()
        if not body:
            empty_bodies += 1
            continue
        pending.append((rule_id, body))
        if len(pending) >= batch:
            conn.executemany("INSERT INTO rule_text (rule_id, body) VALUES (?,?)", pending)
            rows_written += len(pending)
            pending = []

    if pending:
        conn.executemany("INSERT INTO rule_text (rule_id, body) VALUES (?,?)", pending)
        rows_written += len(pending)
    return {"rows": rows_written, "empty_bodies": empty_bodies}


def brand_tokens(conn: DBConnection, domains: Iterable[str]) -> list[BrandToken]:
    """Find brand tokens that appear in a limited number of canonical rules.

    Order (ADR-0031): candidates → stopwords and rule count → maximality over the
    survivors. Maximality comes last so that a longer candidate naming no rule
    (`oktalogin`) cannot remove the brand it contains (`okta`) (#423).
    """
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
        try:
            cur = conn.execute(
                "SELECT COUNT(*) FROM rule_text "
                "WHERE body_tsv @@ phraseto_tsquery('simple', ?) "
                "AND EXISTS (SELECT 1 FROM detection_rules d "
                "WHERE d.id = rule_text.rule_id AND d.is_canonical = 1)",
                (tok,),
            )
            count = cur.fetchone()[0]
        except DB_ERRORS:
            continue
        if 1 <= count <= BRAND_MAX_TITLE_RULES:
            results.append(BrandToken(token=tok, domains=counts[tok], rules=count))

    kept = _maximal({t.token: t.domains for t in results})
    results = [t for t in results if t.token in kept]
    results.sort(key=lambda t: (-t.rules, t.token))
    return results


def brand_evidence(
    conn: DBConnection | None, tokens: list[BrandToken]
) -> dict[str, list[dict]]:
    """Return evidence dicts mapping rule_id to a list of brand matches."""
    if not tokens:
        return {}
    if conn is None or not rule_text_built(conn):
        return {}

    evidence: dict[str, list[dict]] = {}
    for tok in tokens:
        try:
            cur = conn.execute(
                "SELECT rule_text.rule_id FROM rule_text "
                "WHERE body_tsv @@ phraseto_tsquery('simple', ?) "
                "AND EXISTS (SELECT 1 FROM detection_rules d "
                "WHERE d.id = rule_text.rule_id AND d.is_canonical = 1)",
                (tok.token,),
            )
            rows = cur.fetchall()
        except DB_ERRORS:
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


def cve_evidence(conn: DBConnection, cves: Iterable[str]) -> dict[str, list[dict]]:
    """rule_id → title matches for the report's CVE ids (ADR-0031).

    Same FTS mechanism as `brand_evidence`, but with no recurrence test, no
    stopword list and no rule cap: a CVE id is specific by construction, so it
    needs none of the guards a mined token does. Measured on the live store,
    `cve-2021-44228` names 120 rules and `cve-2024-3400` names 10 — while this
    report's three 2026 zero-days name none, the public corpora not having caught
    up, which is the honest answer rather than a failure.

    Like every title match it carries `discriminating: False`: the rule is ABOUT
    this CVE, it does not HOLD a value from the report.

    The query id gets the same `-`/`_` to space normalisation as the indexed
    body (#424), so `CVE_2024_3400` in a title matches `CVE-2024-3400` here; the
    `value` stays the id as the report wrote it.

    Only canonical rules match (#362): `dedupe_store` can demote a rule without
    the index following, until the next `rebuild_rule_text`.
    The filter is an EXISTS, not a JOIN, so the planner enters through the
    full-text index, not `idx_detection_canon` (see store.atom_hits).
    """
    values = sorted({c.strip().lower() for c in cves if isinstance(c, str) and c.strip()})
    if not values or not rule_text_built(conn):
        return {}

    evidence: dict[str, list[dict]] = {}
    for cve in values:
        try:
            rows = conn.execute(
                "SELECT rule_text.rule_id FROM rule_text "
                # Both spellings: an index built before #424 still holds
                # 'cve' '-2024' '-3400' for a hyphenated title, until rebuilt.
                "WHERE (body_tsv @@ phraseto_tsquery('simple', ?) "
                "OR body_tsv @@ phraseto_tsquery('simple', ?)) "
                "AND EXISTS (SELECT 1 FROM detection_rules d "
                "WHERE d.id = rule_text.rule_id AND d.is_canonical = 1)",
                (_as_words(cve), cve),
            ).fetchall()
        except DB_ERRORS:
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
