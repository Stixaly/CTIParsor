"""Reduce a parsed Sigma rule to normalized detection atoms (ADR-0014).

Extracts (class, value) pairs from the ``detection:`` block and infers the target
platform from ``logsource:``.  These atoms are what a report's technical
observables are matched against, so the proposal stage can rank a rule by *what
it actually looks for* rather than by its ATT&CK tag alone.

Pure and stdlib-only: no I/O, no project imports, no third-party dependency.  A
malformed rule never raises — it just yields fewer atoms.
"""
from __future__ import annotations

import re

# ── Public constants ─────────────────────────────────────────────────────────

ATOM_CLASSES: frozenset[str] = frozenset({
    "image", "cmdline", "file", "registry", "hash",
    "domain", "ip", "url", "pipe", "service", "port", "user",
})

#: Sigma field name (lowercased, modifiers stripped) → atom class.  Covers both
#: classic Sigma fields and the ECS-style aliases used by generated corpora
#: (mthcht writes the same keyword under `process.command_line`, `url.full`, …).
FIELD_CLASSES: dict[str, str] = {
    # image — the executable itself
    "image": "image",
    "newprocessname": "image",
    "parentimage": "image",
    "parentprocessname": "image",
    "processname": "image",
    "originalfilename": "image",
    "imageloaded": "image",
    "sourceimage": "image",
    "targetimage": "image",
    "imagepath": "image",
    "processpath": "image",
    "servicefilename": "image",
    "process.executable": "image",
    "process.name": "image",
    "application": "image",
    "appname": "image",
    # cmdline — free-text command / script content
    "commandline": "cmdline",
    "parentcommandline": "cmdline",
    "processcommandline": "cmdline",
    "scriptblocktext": "cmdline",
    "contextinfo": "cmdline",
    "payload": "cmdline",
    "currentdirectory": "cmdline",
    "process.command_line": "cmdline",
    "process.args": "cmdline",
    "process.title": "cmdline",
    # file — files touched, not executed
    "targetfilename": "file",
    "sourcefilename": "file",
    "filename": "file",
    "targetpath": "file",
    "path": "file",
    "newname": "file",
    "file.path": "file",
    "file.name": "file",
    # registry — key path and value data
    "targetobject": "registry",
    "details": "registry",
    "objectname": "registry",
    "registry.value": "registry",
    "registry.path": "registry",
    "registry.key": "registry",
    # hash
    "hashes": "hash",
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "imphash": "hash",
    "filehash": "hash",
    "file_hash": "hash",
    "service_hash": "hash",
    "hash.md5": "hash",
    "hash.sha1": "hash",
    "hash.sha256": "hash",
    # domain
    "destinationhostname": "domain",
    "sourcehostname": "domain",
    "queryname": "domain",
    "query": "domain",
    "dnsqueryname": "domain",
    "targetservername": "domain",
    "servername": "domain",
    "cs-host": "domain",
    "domain": "domain",
    "url_domain": "domain",
    "http_referrer_domain": "domain",
    "dest_nt_host": "domain",
    "destination.domain": "domain",
    "dns.question.name": "domain",
    "url.domain": "domain",
    # ip
    "destinationip": "ip",
    "sourceip": "ip",
    "ipaddress": "ip",
    "destinationaddress": "ip",
    "sourceaddress": "ip",
    "destination.ip": "ip",
    "source.ip": "ip",
    # url
    "url": "url",
    "uri": "url",
    "requesturl": "url",
    "uri_query": "url",
    "uri_path": "url",
    "dest_url": "url",
    "c-uri": "url",
    "cs-uri-query": "url",
    "cs-uri-stem": "url",
    "url.full": "url",
    "url.original": "url",
    "url.query": "url",
    # pipe / service / port / user
    "pipename": "pipe",
    "servicename": "service",
    "service": "service",
    "servicedisplayname": "service",
    "destinationport": "port",
    "destport": "port",
    "dest_port": "port",
    "destination.port": "port",
    "targetusername": "user",
    "subjectusername": "user",
    "user": "user",
    "accountname": "user",
    "user.name": "user",
}

#: Windows-only `logsource.service` values — a rule with one of these is Windows
#: even when `product:` is absent.
WINDOWS_SERVICES: frozenset[str] = frozenset({
    "sysmon", "security", "system", "application", "powershell",
    "powershell-classic", "taskscheduler", "wmi", "windefend",
    "terminalservices-localsessionmanager", "ntlm", "security-mitigations",
    "msexchange-management", "dns-server-analytic", "driver-framework",
    "applocker", "codeintegrity-operational", "bits-client",
    "smbclient-security", "printservice-admin", "printservice-operational",
})

#: Windows-only `logsource.category` values (same fallback role as above).
WINDOWS_CATEGORIES: frozenset[str] = frozenset({
    "ps_script", "ps_module", "ps_classic_start", "registry_set",
    "registry_add", "registry_event", "registry_delete", "registry_rename",
    "driver_load", "image_load", "wmi_event", "pipe_created",
    "create_remote_thread", "process_access", "sysmon_error",
    "raw_access_thread", "process_tampering",
})

#: Structural keys of a detection block — never field names.
_SKIP_KEYS = frozenset({"condition", "timeframe"})

#: Tokens of a Sigma `condition` expression.  Digits are their own token so
#: `not 1 of filter_*` parses as three operands, not two.
_COND_TOKEN = re.compile(r"[A-Za-z_][\w*.]*|\d+|\(|\)")

#: Condition words that are never a selection name.
_COND_KEYWORDS: frozenset[str] = frozenset({"and", "or", "not", "of"})

#: Quantifiers that introduce an `<quantifier> of <pattern>` operand.
_COND_QUANTIFIERS: frozenset[str] = frozenset({"all", "any"})

_HASH_RE = re.compile(r"^[0-9a-f]{32,128}$")


# ── Internal helpers ─────────────────────────────────────────────────────────

def _expand_selector(pattern: str, keys: frozenset[str]) -> set[str]:
    """Resolve one condition operand to the detection keys it names."""
    if pattern == "them":
        return set(keys)
    if "*" in pattern:
        # Built by escaping each literal piece and joining with `.*`, NOT by
        # `re.escape(pattern).replace("\\*", ".*")`: re.escape stopped escaping
        # `*` in newer Pythons, which makes that replacement silently inert.
        regex = ".*".join(re.escape(p) for p in pattern.split("*"))
        compiled = re.compile(f"^{regex}$")
        return {k for k in keys if compiled.match(k)}
    return {pattern} & keys


def _negated_selections(detection: dict) -> set[str]:
    """Names of the detection selections the `condition` negates.

    Sigma puts a rule's EXCLUSIONS in the same `detection:` block as the things
    it looks for, and only the condition says which is which.  An excluded value
    is not something the rule looks for, so it must not become an atom: indexing
    it makes a report that merely mentions the excluded software match the very
    rule written to ignore it.

    Naming is not a usable signal here — measured on the 11,393 Sigma rules in
    the store, 10 use a `filter*` selection POSITIVELY and 72 negate a selection
    that is not named `filter*` — so this reads the condition and nothing else.

    Accepted limit: a double negation inside a group, `not (a and not b)`, marks
    `b` negated although it is positive.  Nine rules in the store use `not (` at
    all, and over-excluding only ever costs an atom, where under-excluding
    invents one.
    """
    cond = detection.get("condition")
    if isinstance(cond, list):
        cond = " or ".join(str(x) for x in cond)
    if not isinstance(cond, str):
        return set()

    # Lowercase BEFORE dropping the structural keys, or a rule writing
    # `Condition:` would leave "condition" in `keys` and let the word in the
    # expression resolve to a selection.
    keys = frozenset(
        k.strip().lower() for k in detection if isinstance(k, str)
    ) - _SKIP_KEYS
    if not keys:
        return set()

    tokens = _COND_TOKEN.findall(cond.lower())
    negated: set[str] = set()
    i = 0
    n = len(tokens)

    while i < n:
        if tokens[i] != "not":
            i += 1
            continue

        j = i + 1
        if j >= n:
            break

        # `not ( ... )` — every name in the group is negated.  No depth guard:
        # by De Morgan a nested operand is negated too, and over-excluding is
        # the safe direction.
        if tokens[j] == "(":
            depth = 1
            k = j + 1
            while k < n and depth > 0:
                tok = tokens[k]
                if tok == "(":
                    depth += 1
                elif tok == ")":
                    depth -= 1
                elif (
                    tok not in _COND_KEYWORDS
                    and tok not in _COND_QUANTIFIERS
                    and not tok.isdigit()
                ):
                    negated |= _expand_selector(tok, keys)
                k += 1
            i = k
            continue

        # `not <quantifier> of <pattern>`
        if (
            j + 2 < n
            and tokens[j + 1] == "of"
            and (tokens[j].isdigit() or tokens[j] in _COND_QUANTIFIERS)
        ):
            negated |= _expand_selector(tokens[j + 2], keys)
            i = j + 3
            continue

        # `not <name>`
        negated |= _expand_selector(tokens[j], keys)
        i = j + 1

    return negated


def _strip_quotes(s: str) -> str:
    """Remove one pair of surrounding single or double quotes."""
    if len(s) >= 2 and ((s[0] == "'" and s[-1] == "'") or (s[0] == '"' and s[-1] == '"')):
        return s[1:-1]
    return s


def _normalize(cls: str, raw: object) -> list[str]:
    """Normalize one raw Sigma value into 0–2 atom strings for *cls*.

    A path yields two atoms (full path *and* basename) so a report naming only
    the binary still matches a rule pinning its full install path.
    """
    try:
        s = str(raw).strip()
    except Exception:                     # noqa: BLE001 — never break a build on one value
        return []

    s = _strip_quotes(s).lower().strip("*").strip()

    # An interior wildcard means the rule matches a *shape*, not a value — there
    # is no literal left to compare a report observable against.
    if not s or "*" in s or "?" in s:
        return []

    if cls == "hash":
        # Sigma packs hashes as "MD5=…,SHA256=…" (or a bare digest).
        out = []
        for part in s.split(","):
            digest = part.strip().rsplit("=", 1)[-1].strip()
            if _HASH_RE.match(digest):
                out.append(digest)
        return out

    if cls == "port":
        return [s] if s.isdigit() and 1 <= len(s) <= 5 else []

    if cls in ("image", "file"):
        if "\\" in s or "/" in s:
            path = s.replace("\\", "/")
            # Strip the basename: `s` was stripped at its ends, but the segment
            # after the last separator can still start with a space, and an atom
            # carrying one can never equal a report observable (which is
            # stripped).  Measured on the store: 49 such values, e.g. " 2>nul"
            # and " rev_shell.py" — dead weight that also broke the documented
            # "normalized" contract of rule_atoms.value.
            base = path.rsplit("/", 1)[-1].strip()
            return [v for v in (path, base) if len(v) >= 4]
        return [s] if len(s) >= 4 else []

    if cls == "domain":
        s = s[2:] if s.startswith("*.") else s.removeprefix(".")
        s = s.removesuffix(".")
        return [s] if len(s) >= 4 else []

    if cls == "registry":
        s = s.replace("\\", "/")
        return [s] if len(s) >= 4 else []

    # url, cmdline, ip, pipe, service, user
    return [s] if len(s) >= 4 else []


def _resolve_class(key: object) -> str | None:
    """Map a Sigma field name (possibly carrying `|modifiers`) to an atom class."""
    if not isinstance(key, str):
        return None
    return FIELD_CLASSES.get(key.split("|", 1)[0].strip().lower())


def _add(cls: str, raw: object, out: list[tuple[str, str]],
         seen: set[tuple[str, str]], limit: int) -> None:
    """Normalize *raw* and append the resulting atoms, deduplicated."""
    for value in _normalize(cls, raw):
        pair = (cls, value)
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
            if len(out) >= limit:
                return


def _is_scalar(v: object) -> bool:
    """A YAML scalar we can turn into an atom (bool is not — it carries no value)."""
    return isinstance(v, (str, int, float)) and not isinstance(v, bool)


def _collect(node: object, out: list[tuple[str, str]],
             seen: set[tuple[str, str]], limit: int) -> None:
    """Walk a detection sub-tree, appending atoms until *limit* is reached.

    Stops early rather than collecting everything and truncating: generated
    keyword corpora put thousands of values under a single field, and parsing
    all of them for every one of ~11k rules would dominate the index build.
    """
    if len(out) >= limit:
        return

    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.strip().lower() in _SKIP_KEYS:
                continue
            cls = _resolve_class(key)
            if cls is not None and _is_scalar(value):
                _add(cls, value, out, seen, limit)
            elif cls is not None and isinstance(value, list):
                for item in value:
                    if _is_scalar(item):
                        _add(cls, item, out, seen, limit)
                    else:
                        _collect(item, out, seen, limit)
                    if len(out) >= limit:
                        return
            else:
                # Unknown key (a selection name) or a nested structure — descend.
                _collect(value, out, seen, limit)
            if len(out) >= limit:
                return
    elif isinstance(node, list):
        for item in node:
            _collect(item, out, seen, limit)
            if len(out) >= limit:
                return


def _logsource_values(val: object) -> set[str]:
    """Normalize a logsource field (str, or list of str) to a lowercase set."""
    if isinstance(val, str):
        return {val.strip().lower()} - {""}
    if isinstance(val, list):
        return {v.strip().lower() for v in val if isinstance(v, str) and v.strip()}
    return set()


# ── Public API ───────────────────────────────────────────────────────────────

def extract_atoms(doc: object, *, max_atoms: int = 120) -> list[tuple[str, str]]:
    """Return normalized (class, value) atoms from a parsed Sigma rule.

    Selections the rule's `condition` negates are skipped: they are what the
    rule excludes, not what it looks for.

    Args:
        doc: a parsed Sigma rule.  Anything that isn't a dict yields [].
        max_atoms: hard cap on atoms per rule — keeps auto-generated keyword
            corpora from dominating the index.

    Returns:
        Deduplicated (atom_class, value) pairs in first-seen order.
    """
    if not isinstance(doc, dict) or max_atoms <= 0:
        return []
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return []

    # A negated selection is what the rule EXCLUDES.  Dropped here rather than
    # inside `_collect` so the walk stays unaware of condition semantics, and so
    # the exclusion is confined to the top level: negation names a top-level
    # selection, never a nested field.
    negated = _negated_selections(detection)
    if negated:
        detection = {
            k: v for k, v in detection.items()
            if not (isinstance(k, str) and k.strip().lower() in negated)
        }

    out: list[tuple[str, str]] = []
    _collect(detection, out, set(), max_atoms)
    return out


def rule_platform(doc: object) -> str:
    """Infer a rule's target OS from its logsource block.

    Returns "windows", "linux", "macos", or "" when the rule is
    platform-agnostic (cloud, proxy, webserver…) or the logsource is unusable.
    """
    if not isinstance(doc, dict):
        return ""
    logsource = doc.get("logsource")
    if not isinstance(logsource, dict):
        return ""

    product = _logsource_values(logsource.get("product"))
    if "windows" in product:
        return "windows"
    if "linux" in product:
        return "linux"
    if product & {"macos", "osx"}:
        return "macos"

    # No product: fall back to Windows-only services/categories.  There is no
    # equivalent Linux fallback — Linux Sigma rules always declare `product`.
    if _logsource_values(logsource.get("service")) & WINDOWS_SERVICES:
        return "windows"
    if _logsource_values(logsource.get("category")) & WINDOWS_CATEGORIES:
        return "windows"
    return ""
