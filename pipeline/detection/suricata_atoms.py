"""Suricata rule atom extraction.

Reduces a Suricata (Snort/Suricata) rule to normalized detection atoms — the
literal values the rule searches for. This is the exact counterpart of
``pipeline/detection/atoms.py`` (Sigma).

Module PUR: no I/O beyond the shared TLD table, no third-party dependencies.
Only the standard library is used (``re``).

See ADR-0015 for the atom model.
"""

from __future__ import annotations

import re

from pipeline.detection.tlds import looks_like_domain

ATOM_CLASSES: frozenset[str] = frozenset({
    "domain", "ip", "url", "port", "strlit", "hash",
})

BUFFER_CLASSES: dict[str, str] = {
    "dns.query": "domain",
    "dns.query.name": "domain",
    "dns_query": "domain",
    "http.host": "domain",
    "http.host.raw": "domain",
    "tls.sni": "domain",
    "tls_sni": "domain",
    "tls.cert_subject": "domain",
    "tls.cert_issuer": "domain",
    "ja3.hash": "hash",
    "ja3s.hash": "hash",
    "http.uri": "url",
    "http.uri.raw": "url",
    "http.url": "url",
    "http.request_line": "url",
    "http.referer": "url",
    "http.header": "strlit",
    "http.header_names": "strlit",
    "http.user_agent": "strlit",
    "http.cookie": "strlit",
    "http.request_body": "strlit",
    "http.response_body": "strlit",
    "http.server": "strlit",
    "http.content_type": "strlit",
    "file.data": "strlit",
    "file_data": "strlit",
    "file.name": "strlit",
    "filename": "strlit",
    "smb.share": "strlit",
    "ssh.software": "strlit",
    "ftp.command": "strlit",
    "dcerpc.iface": "strlit",
}

#: Legacy content modifiers — these follow the ``content:`` they qualify, where a
#: sticky buffer precedes it.  Kept DISJOINT from BUFFER_CLASSES: a keyword in
#: both would be unresolvable by name alone.  ``dns_query`` and ``file_data`` look
#: like modifiers but are sticky buffers (measured on ET Open: dns_query precedes
#: its content 92/92 times), so they live in BUFFER_CLASSES only.
#:
#: Near-dead on current corpora — legacy syntax survives almost exclusively in
#: ET Open's commented-out block (2,910 occurrences there vs 93 active), which the
#: adapter skips.  Retained because smaller corpora still ship it.
LEGACY_MODIFIER_CLASSES: dict[str, str] = {
    "http_uri": "url",
    "http_raw_uri": "url",
    "http_host": "domain",
    "http_raw_host": "domain",
    "http_header": "strlit",
    "http_raw_header": "strlit",
    "http_user_agent": "strlit",
    "http_cookie": "strlit",
    "http_client_body": "strlit",
    "http_server_body": "strlit",
    "http_method": "strlit",
    "http_stat_code": "strlit",
}

NOISE_LITERALS: frozenset[str] = frozenset({
    "get", "post", "head", "put", "delete", "options", "connect",
    "http/1.0", "http/1.1", "http/2", "content-type", "user-agent",
    "mozilla", "mozilla/4.0", "mozilla/5.0", "text/html", "application/json",
    "keep-alive", "gzip", "deflate", "close", "localhost", "example.com",
    "true", "false", "null", "none", "admin", "index.php", "index.html",
})

# Pre-compiled regexes to avoid recompilation in hot paths.
_RE_HEX_SEGMENT = re.compile(r"\|[^|]*\|")
_RE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_HASH = re.compile(r"^[0-9a-f]{32,128}$")
_RE_MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _split_options(body: str) -> list[str]:
    """Split the rule body on top-level semicolons.

    Semicolons inside double-quoted strings are not separators.
    A backslash-escaped quote does not close the string.
    Returns non-empty, stripped fragments.
    """
    fragments: list[str] = []
    current: list[str] = []
    in_string = False
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if in_string:
            if ch == "\\" and i + 1 < n:
                current.append(ch)
                current.append(body[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            current.append(ch)
        else:
            if ch == '"':
                in_string = True
                current.append(ch)
            elif ch == ";":
                frag = "".join(current).strip()
                if frag:
                    fragments.append(frag)
                current = []
            else:
                current.append(ch)
        i += 1
    frag = "".join(current).strip()
    if frag:
        fragments.append(frag)
    return fragments


def parse_options(body: str) -> list[tuple[str, str]]:
    """Parse the rule body into (key, value) pairs.

    Args:
        body: The content between the outer parentheses of a Suricata rule.

    Returns:
        A list of (key, value) tuples in order of appearance.
        Keys are lowercased and stripped. Values are stripped.
        Fragments without a colon yield (fragment, "").
    """
    result: list[tuple[str, str]] = []
    for frag in _split_options(body):
        if ":" in frag:
            key, value = frag.split(":", 1)
            result.append((key.strip().lower(), value.strip()))
        else:
            result.append((frag.strip().lower(), ""))
    return result


def _unquote(value: str) -> str:
    """Strip one pair of enclosing double quotes if present."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _content_text(value: str) -> str:
    """Extract the textual content from a raw content: value.

    Removes quotes, strips hex segments (|...|), and decodes
    escape sequences (\\; \\" \\\\ \\:).
    """
    s = _unquote(value)
    # Remove hex segments (binary data, not text)
    s = _RE_HEX_SEGMENT.sub(" ", s)
    # Decode escape sequences
    s = s.replace("\\;", ";")
    s = s.replace('\\"', '"')
    s = s.replace("\\\\", "\\")
    s = s.replace("\\:", ":")
    return s.strip()


def _normalize(cls: str, raw: str) -> list[str]:
    """Normalize a single value into 0 to 2 atoms based on its class.

    Args:
        cls: The atom class (domain, ip, url, port, strlit, hash).
        raw: The raw string value.

    Returns:
        A list of normalized atom values (0 to 2 elements).
    """
    s = raw.strip().lower()
    if not s:
        return []
    if s in NOISE_LITERALS:
        return []

    if cls == "domain":
        # Strip trailing dot and www. prefix
        if s.endswith("."):
            s = s[:-1]
        if s.startswith("www."):
            s = s[4:]
        if looks_like_domain(s) and len(s) >= 4:
            return [s]
        return []

    if cls == "ip":
        if _RE_IP.match(s):
            octets = s.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                return [s]
        return []

    if cls == "port":
        if s.isdigit() and 1 <= int(s) <= 65535:
            return [s]
        return []

    if cls == "hash":
        if _RE_HASH.match(s):
            return [s]
        return []

    if cls == "url":
        # A URI buffer holds path fragments, but SQL-injection rules put bare
        # keywords there too ("select", "union", "from" — 4k+ atoms in ET Open).
        # Requiring a path separator keeps "/gate.php" and drops the keywords.
        if len(s) < 6 or ("/" not in s and "://" not in s):
            return []
        result = [s]
        if s.startswith("/") and s.count("/") >= 2:
            last_segment = s.rsplit("/", 1)[-1]
            if len(last_segment) >= 6:
                result.append(last_segment)
        return result

    if cls == "strlit":
        if len(s) < 8:
            return []
        return [s]

    return []


def _add(
    cls: str,
    raw: str,
    out: list[tuple[str, str]],
    seen: set[tuple[str, str]],
    limit: int,
) -> None:
    """Normalize and add atoms to the output list if not already seen.

    Stops adding once the limit is reached.
    """
    if len(out) >= limit:
        return
    for value in _normalize(cls, raw):
        pair = (cls, value)
        if pair not in seen:
            out.append(pair)
            seen.add(pair)
            if len(out) >= limit:
                break


def extract_atoms(rule_line: str, *, max_atoms: int = 40) -> list[tuple[str, str]]:
    """Extract detection atoms from a Suricata rule line.

    Args:
        rule_line: A single-line Suricata rule.
        max_atoms: Maximum number of atoms to return (default 40).

    Returns:
        A list of (class, value) tuples in order of first appearance,
        deduplicated. Returns an empty list for malformed input.
    """
    if not isinstance(rule_line, str) or max_atoms <= 0:
        return []

    # Extract body between first ( and last )
    first_open = rule_line.find("(")
    last_close = rule_line.rfind(")")
    if first_open == -1 or last_close == -1 or last_close <= first_open:
        return []
    body = rule_line[first_open + 1:last_close]

    options = parse_options(body)

    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    current_buffer: str | None = None

    # Nine keywords ("http_uri", "dns_query", …) are BOTH a sticky buffer and a
    # legacy content modifier; only their position disambiguates them.  Modern
    # syntax puts the buffer *before* its content ("http.uri; content:…"), legacy
    # puts the modifier *after* it ("content:…; nocase; http_uri;").  So a naked
    # keyword is resolved by looking ahead from each content: whichever legacy
    # modifier claims it first — before the next content: or sticky buffer —
    # decides its class.  Testing the buffer table first instead would leave the
    # atom classified as a bare `strlit` and hand every following content: a
    # buffer the rule never opened.
    n_opts = len(options)
    for i, (key, value) in enumerate(options):
        if len(out) >= max_atoms:
            break

        if key == "content":
            # `content:!"…"` is a NEGATED match — the rule fires when the value is
            # ABSENT.  Indexing it would match a report against the very rule that
            # excludes its value (ET Open ships 5,663 of these, including domains
            # such as !"101.ru").
            if value.lstrip().startswith("!"):
                continue
            text = _content_text(value)
            if not text:
                continue

            cls: str | None = None
            # Look ahead for a legacy modifier claiming this content.
            for j in range(i + 1, n_opts):
                nkey, nvalue = options[j]
                if nkey == "content" or (nvalue == "" and nkey in BUFFER_CLASSES
                                         and nkey not in LEGACY_MODIFIER_CLASSES):
                    break            # next content / unambiguous buffer — not claimed
                if nvalue == "" and nkey in LEGACY_MODIFIER_CLASSES:
                    cls = LEGACY_MODIFIER_CLASSES[nkey]
                    break

            if cls is None:
                cls = BUFFER_CLASSES.get(current_buffer, "strlit") if current_buffer else "strlit"
            # A literal that is plainly a hostname is a domain wherever it sits.
            # Compare lowercased: _RE_DOMAIN only accepts [a-z0-9].
            if cls == "strlit" and looks_like_domain(text.strip().lower()):
                cls = "domain"
            _add(cls, text, out, seen, max_atoms)
            continue

        # A naked keyword that is *only* a buffer opens one.  Ambiguous keywords
        # were already consumed by the look-ahead above, so ignoring them here is
        # what keeps legacy rules from opening a phantom buffer.
        if value == "" and key in BUFFER_CLASSES and key not in LEGACY_MODIFIER_CLASSES:
            current_buffer = key
            continue

        # pcre: — a regex carries no literal we can compare an observable against.
        # Every other key (msg, flow, sid, …) is metadata, not a match value.

    return out


def rule_header(rule_line: str) -> dict[str, str]:
    """Parse the header portion of a Suricata rule (before the first parenthesis).

    Args:
        rule_line: A single-line Suricata rule.

    Returns:
        A dict with keys: action, proto, src_ip, src_port, direction, dst_ip, dst_port.
        Values are stripped and lowercased. Returns {} if fewer than 7 fields.
    """
    if not isinstance(rule_line, str):
        return {}
    first_open = rule_line.find("(")
    if first_open == -1:
        return {}
    header_part = rule_line[:first_open]
    fields = header_part.split()
    if len(fields) < 7:
        return {}
    return {
        "action": fields[0].strip().lower(),
        "proto": fields[1].strip().lower(),
        "src_ip": fields[2].strip().lower(),
        "src_port": fields[3].strip().lower(),
        "direction": fields[4].strip().lower(),
        "dst_ip": fields[5].strip().lower(),
        "dst_port": fields[6].strip().lower(),
    }


def rule_metadata(rule_line: str) -> dict[str, str]:
    """Extract metadata key-value pairs from a Suricata rule.

    Args:
        rule_line: A single-line Suricata rule.

    Returns:
        A dict of metadata entries (key lowercased, value as-is).
        Returns {} if no metadata option is present.
    """
    if not isinstance(rule_line, str):
        return {}
    first_open = rule_line.find("(")
    last_close = rule_line.rfind(")")
    if first_open == -1 or last_close == -1 or last_close <= first_open:
        return {}
    body = rule_line[first_open + 1:last_close]
    options = parse_options(body)
    for key, value in options:
        if key == "metadata":
            result: dict[str, str] = {}
            for entry in value.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split(" ", 1)
                if len(parts) < 2:
                    continue
                result[parts[0].strip().lower()] = parts[1].strip()
            return result
    return {}


def technique_ids(rule_line: str) -> list[str]:
    """Extract MITRE ATT&CK technique IDs from rule metadata.

    Args:
        rule_line: A single-line Suricata rule.

    Returns:
        A deduplicated list of valid MITRE technique IDs (e.g. "T1071"),
        in order of first appearance. Returns [] if none found.
    """
    meta = rule_metadata(rule_line)
    raw = meta.get("mitre_technique_id", "")
    if not raw:
        return []
    result: list[str] = []
    seen: set[str] = set()
    for candidate in raw.split(","):
        candidate = candidate.strip().upper()
        if _RE_MITRE.match(candidate) and candidate not in seen:
            result.append(candidate)
            seen.add(candidate)
    return result
