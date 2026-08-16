"""YARA rule parsing and atom extraction for CTIParsor.

This module splits YARA rule files into individual rules and reduces each
rule to normalized detection atoms. It is the YARA counterpart of
``pipeline/detection/atoms.py`` (Sigma) and
``pipeline/detection/suricata_atoms.py`` (Suricata).

Pure module: no I/O, no project imports, no third-party dependencies.
Only the standard library is used.

See ADR-0015 §2 for the decision to exclude hex and regex patterns from
atom extraction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pipeline.detection.tlds import looks_like_domain

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATOM_CLASSES: frozenset[str] = frozenset({
    "domain", "ip", "url", "file", "registry", "strlit", "hash",
})

HASH_META_KEYS: frozenset[str] = frozenset({
    "hash", "hash1", "hash2", "hash3", "hash4", "hashes",
    "md5", "sha1", "sha256", "sha512",
    "reference_sample", "sample", "samples", "reference_md5",
})

OS_META_VALUES: dict[str, str] = {
    "windows": "windows",
    "win": "windows",
    "win32": "windows",
    "win64": "windows",
    "linux": "linux",
    "unix": "linux",
    "macos": "macos",
    "osx": "macos",
    "darwin": "macos",
    "macosx": "macos",
    "multi": "",
    "all": "",
    "android": "",
    "ios": "",
}

NOISE_LITERALS: frozenset[str] = frozenset({
    "microsoft", "windows", "kernel32.dll", "user32.dll", "advapi32.dll",
    "ntdll.dll", "msvcrt.dll", "getprocaddress", "loadlibrarya",
    "loadlibraryw", "virtualalloc", "createprocessa", "createprocessw",
    "cmd.exe", "powershell.exe", "rundll32.exe", "svchost.exe",
    "software\\microsoft\\windows\\currentversion\\run",
    "this program cannot be run in dos mode",
    "http://", "https://", "content-type", "user-agent", "mozilla/5.0",
    "application/x-www-form-urlencoded", "text/html", "kernel32",
    # Placeholders and language namespaces that survive the domain test.
    # Measured: these are the only non-domains among 226 distinct domain atoms —
    # the rest are genuine C2 (greensky27.vicp.net, barjuok.ryongnamsan.edu.kp),
    # so a broader namespace denylist would cost more recall than it buys.
    "system.net", "example.com", "testdomain.com", "target.com",
})

# ---------------------------------------------------------------------------
# Compiled regexes (compiled once at module level)
# ---------------------------------------------------------------------------

_RE_RULE = re.compile(
    r"(?m)^[ \t]*(?:(private|global)[ \t]+)*rule[ \t]+([A-Za-z_]\w*)[ \t]*(?::[ \t]*([^\{\n]*))?[ \t]*\{"
)
_RE_HASH = re.compile(r"^[0-9a-f]{32,128}$")
_RE_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# A path ends in an *alphabetic* extension and contains no spaces.  `[a-z0-9]{1,4}`
# alone accepted "ufasoft bitcoin-miner/0.20" and " p = document.inde" as files.
_RE_FILE_EXT = re.compile(r"^\S+\.[a-z]{1,4}$")
_RE_META_LINE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
# `\w*` not `[A-Za-z_]\w*`: YARA allows an anonymous string, declared bare as `$`.
_RE_STRING_DECL = re.compile(r"^\s*\$(\w*)\s*=\s*(.+)$")
_RE_IMPORT = re.compile(r'(?m)^\s*import\s+"(\w+)"')
_RE_SPLIT_META = re.compile(r"[,\s]+")


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class YaraRule:
    """A single parsed YARA rule."""

    name: str
    tags: list[str]
    meta: dict[str, str]
    strings: list[tuple[str, str, str]]  # (identifier, kind, value)
    body: str
    is_private: bool
    #: Modules imported by the *file* this rule came from.  Imports are file-level
    #: in YARA, never inside `rule { … }`, so they cannot be recovered from `body`.
    imports: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _strip_comments(text: str) -> str:
    """Replace ``//`` and ``/* */`` comments with spaces, preserving offsets.

    Comments inside double-quoted strings are not stripped.
    """
    result: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            result.append(c)
            if c == "\\" and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        else:
            if c == '"':
                in_string = True
                result.append(c)
                i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == "/":
                # Line comment: skip to end of line
                while i < n and text[i] != "\n":
                    result.append(" ")
                    i += 1
            elif c == "/" and i + 1 < n and text[i + 1] == "*":
                # Block comment: skip to closing */.  The two spaces stand in for
                # the "/*" itself — split_rules slices bodies out of the ORIGINAL
                # text using offsets found here, so dropping them would shift every
                # rule after a /* */ licence header by two characters.
                result.append(" ")
                result.append(" ")
                i += 2
                while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                    if text[i] == "\n":
                        result.append("\n")
                    else:
                        result.append(" ")
                    i += 1
                if i < n:
                    result.append(" ")
                    result.append(" ")
                    i += 2
            else:
                result.append(c)
                i += 1
    return "".join(result)


def _find_rule_end(text: str, start: int) -> int:
    """Find the index of the matching ``}`` for the ``{`` at ``start``.

    Ignores braces inside double-quoted strings and regexes (``/.../``
    preceded by ``=``). Returns ``-1`` if not found.
    """
    depth = 0
    i = start
    n = len(text)
    in_string = False
    in_regex = False
    while i < n:
        c = text[i]
        if in_string:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif in_regex:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "/":
                in_regex = False
            i += 1
        else:
            if c == '"':
                in_string = True
                i += 1
            elif c == "/" and i > 0:
                # Check if this is a regex start: previous non-space char is '='
                j = i - 1
                while j >= 0 and text[j] in " \t":
                    j -= 1
                if j >= 0 and text[j] == "=":
                    in_regex = True
                    i += 1
                else:
                    i += 1
            elif c == "{":
                depth += 1
                i += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
                i += 1
            else:
                i += 1
    return -1


def _parse_meta(body: str) -> dict[str, str]:
    """Extract the ``meta:`` section from a rule body.

    Returns a dict with lowercased keys. Repeated keys are joined by ``","``.
    """
    meta: dict[str, str] = {}
    # Find the meta section
    meta_start = body.find("meta:")
    if meta_start == -1:
        return meta
    # Find the end of the meta section
    end_markers = ["strings:", "condition:"]
    meta_end = len(body)
    for marker in end_markers:
        idx = body.find(marker, meta_start + 5)
        if idx != -1 and idx < meta_end:
            meta_end = idx
    section = body[meta_start + 5:meta_end]
    for line in section.splitlines():
        m = _RE_META_LINE.match(line)
        if not m:
            continue
        key = m.group(1).lower()
        raw_val = m.group(2).strip()
        # Parse value
        if raw_val.startswith('"') and raw_val.endswith('"') and len(raw_val) >= 2:
            val = raw_val[1:-1]
            val = val.replace('\\"', '"').replace("\\\\", "\\")
        elif raw_val in ("true", "false"):
            val = raw_val
        else:
            val = raw_val
        if key in meta:
            meta[key] = meta[key] + "," + val
        else:
            meta[key] = val
    return meta


def _parse_strings(body: str) -> list[tuple[str, str, str]]:
    """Extract the ``strings:`` section from a rule body.

    Returns a list of ``(identifier, kind, value)`` tuples where kind is
    ``"text"``, ``"hex"``, or ``"regex"``.
    """
    strings: list[tuple[str, str, str]] = []
    strings_start = body.find("strings:")
    if strings_start == -1:
        return strings
    strings_end = body.find("condition:", strings_start + 8)
    if strings_end == -1:
        strings_end = len(body)
    section = body[strings_start + 8:strings_end]
    for line in section.splitlines():
        m = _RE_STRING_DECL.match(line)
        if not m:
            continue
        ident = "$" + m.group(1)
        raw_val = m.group(2).strip()
        if raw_val.startswith('"'):
            # Scan to the closing UNESCAPED quote.  Testing endswith('"') instead
            # fails on every string carrying modifiers (`$s = "x" fullword ascii`),
            # which is most of them — and the fallback branch then kept the closing
            # quote and the modifier words inside the value *and* skipped
            # unescaping, so `"Software\\Microsoft"` surfaced as `software//microsoft`.
            k = 1
            m_end = -1
            while k < len(raw_val):
                if raw_val[k] == "\\":
                    k += 2
                    continue
                if raw_val[k] == '"':
                    m_end = k
                    break
                k += 1
            val = raw_val[1:m_end] if m_end != -1 else raw_val[1:]
            val = val.replace('\\"', '"').replace("\\\\", "\\")
            val = val.replace("\\n", "\n").replace("\\t", "\t")
            strings.append((ident, "text", val))
        elif raw_val.startswith("{"):
            # Hex string
            if raw_val.endswith("}"):
                val = raw_val[1:-1]
            else:
                val = raw_val[1:]
            strings.append((ident, "hex", val))
        elif raw_val.startswith("/"):
            # Regex string
            # Find the closing unescaped /
            i = 1
            n = len(raw_val)
            while i < n:
                if raw_val[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if raw_val[i] == "/":
                    break
                i += 1
            val = raw_val[1:i]
            strings.append((ident, "regex", val))
    return strings


def _classify_literal(s: str) -> str:
    """Determine the atom class of a text literal.

    Evaluation order is strict: hash, url, ip, registry, file, domain, strlit.
    """
    s_lower = s.lower()
    # 1. Hash
    if _RE_HASH.match(s_lower):
        return "hash"
    # 2. URL
    if s_lower.startswith(("http://", "https://", "ftp://")):
        return "url"
    # 3. IP
    if _RE_IP.match(s_lower):
        parts = s_lower.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"
    # 4. Registry
    s_norm = s_lower.replace("/", "\\")
    if (s_norm.startswith("hkey_") or s_norm.startswith("hklm\\")
            or s_norm.startswith("hkcu\\") or s_norm.startswith("software\\")
            or s_norm.startswith("system\\currentcontrolset")):
        return "registry"
    # 5. File — note the separator test is on a backslash, not backslash-space:
    # nearly every path literal in a YARA rule is a Windows path, and missing them
    # here sends "kernel32.dll" on to the domain test, where ".dll" passes for a TLD.
    if ("\\" in s_lower or "/" in s_lower) and _RE_FILE_EXT.match(s_lower):
        return "file"
    # 6. Domain — shape alone is not enough; see pipeline.detection.tlds.
    if looks_like_domain(s_lower):
        return "domain"
    # 7. Fallback
    return "strlit"


def _normalize(cls: str, raw: str) -> list[str]:
    """Normalize a raw literal into one or more atom values.

    Returns an empty list if the value is noise, too short, or invalid.
    """
    s = raw.strip().lower()
    if not s:
        return []
    if s in NOISE_LITERALS:
        return []
    # Control characters
    if any(ord(c) < 32 for c in s):
        return []
    if cls == "hash":
        if _RE_HASH.match(s):
            return [s]
        return []
    if cls == "ip":
        parts = s.split(".")
        # isdigit() first: _normalize is reachable with a class the caller chose,
        # so int() must never see a non-numeric label.
        if (len(parts) == 4 and all(p.isdigit() for p in parts)
                and all(int(p) <= 255 for p in parts)):
            return [s]
        return []
    if cls == "domain":
        if s.endswith("."):
            s = s[:-1]
        if s.startswith("www."):
            s = s[4:]
        if len(s) >= 4:
            return [s]
        return []
    if cls == "url":
        if len(s) >= 8:
            return [s]
        return []
    if cls == "registry":
        s = s.replace("\\", "/")
        if len(s) >= 8:
            return [s]
        return []
    if cls == "file":
        s = s.replace("\\", "/")
        result: list[str] = []
        if len(s) >= 4:
            result.append(s)
        base = s.rsplit("/", 1)[-1]
        if len(base) >= 4 and base != s:
            result.append(base)
        return result
    if cls == "strlit":
        if len(s) >= 8:
            return [s]
        return []
    return []


def _add(cls: str, raw: str, out: list[tuple[str, str]],
         seen: set[tuple[str, str]], limit: int) -> None:
    """Normalize and add atoms to ``out``, deduplicating and respecting ``limit``."""
    if len(out) >= limit:
        return
    values = _normalize(cls, raw)
    for v in values:
        if len(out) >= limit:
            return
        key = (cls, v)
        if key not in seen:
            seen.add(key)
            out.append(key)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def split_rules(text: str) -> list[YaraRule]:
    """Split a YARA rule file into individual :class:`YaraRule` objects.

    Args:
        text: The full text of a YARA rule file.

    Returns:
        A list of :class:`YaraRule` in file order. Malformed rules are
        silently skipped.
    """
    if not isinstance(text, str):
        return []
    clean = _strip_comments(text)
    # Imports are file-level and apply to every rule in the file.
    imports = tuple(dict.fromkeys(_RE_IMPORT.findall(clean)))
    rules: list[YaraRule] = []
    for m in _RE_RULE.finditer(clean):
        # Determine is_private
        prefix = m.group(1)
        is_private = prefix is not None and prefix.strip() == "private"
        name = m.group(2)
        tags_raw = m.group(3)
        tags = tags_raw.split() if tags_raw else []
        # Find the opening brace position
        brace_idx = m.end() - 1
        end = _find_rule_end(clean, brace_idx)
        if end == -1:
            continue
        # Body from the original text: from the start of "rule" to end inclusive
        # m.start() is the start of the match (including leading whitespace)
        # We want to start from the "rule" keyword
        rule_start = m.start()
        # Find the position of "rule" in the match
        rule_kw_offset = m.group(0).find("rule")
        body_start = rule_start + rule_kw_offset
        body = text[body_start:end + 1]
        meta = _parse_meta(body)
        strings = _parse_strings(body)
        rules.append(YaraRule(
            name=name,
            tags=tags,
            meta=meta,
            strings=strings,
            body=body,
            is_private=is_private,
            imports=imports,
        ))
    return rules


def extract_atoms(rule: YaraRule, *, max_atoms: int = 60) -> list[tuple[str, str]]:
    """Extract normalized detection atoms from a YARA rule.

    Hashes from metadata are extracted first, followed by text string
    literals. Hex and regex patterns are excluded (ADR-0015 §2).

    Args:
        rule: The parsed YARA rule.
        max_atoms: Maximum number of atoms to return.

    Returns:
        A list of ``(class, value)`` tuples, deduplicated, in order of
        first appearance.
    """
    if not isinstance(rule, YaraRule) or max_atoms <= 0:
        return []
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    # 1. Hashes from metadata — the highest-value atoms a YARA rule carries, so
    # they are collected before the string literals can exhaust the budget.
    for key, value in rule.meta.items():
        if key in HASH_META_KEYS:
            for part in _RE_SPLIT_META.split(value):
                part = part.strip()
                if part:
                    _add("hash", part, out, seen, max_atoms)
            if len(out) >= max_atoms:
                return out
    # 2. Text strings.  Stop as soon as the budget is spent rather than
    # classifying all of them and truncating — signature-base ships rules with
    # several hundred strings apiece.
    for _ident, kind, value in rule.strings:
        if len(out) >= max_atoms:
            break
        if kind != "text":
            continue
        _add(_classify_literal(value), value, out, seen, max_atoms)
    return out


def rule_platform(rule: YaraRule) -> str:
    """Determine the platform of a YARA rule.

    Args:
        rule: The parsed YARA rule.

    Returns:
        A normalized platform string (``"windows"``, ``"linux"``,
        ``"macos"``, or ``""`` if unknown).
    """
    if not isinstance(rule, YaraRule):
        return ""
    os_val = rule.meta.get("os", "").lower()
    if os_val in OS_META_VALUES:
        return OS_META_VALUES[os_val]
    # Fall back to the file's imports, not `body` — imports never appear inside a
    # rule block, so testing body would make this branch permanently dead.
    if "pe" in rule.imports:
        return "windows"
    if "elf" in rule.imports:
        return "linux"
    return ""


def rule_hashes(rule: YaraRule) -> list[str]:
    """Extract valid hash values from a rule's metadata.

    Args:
        rule: The parsed YARA rule.

    Returns:
        A list of lowercase hex hash strings, deduplicated, in order of
        first appearance.
    """
    if not isinstance(rule, YaraRule):
        return []
    result: list[str] = []
    seen: set[str] = set()
    for key, value in rule.meta.items():
        if key not in HASH_META_KEYS:
            continue
        for part in re.split(r"[,\s]+", value):
            part = part.strip().lower()
            if part and _RE_HASH.match(part) and part not in seen:
                seen.add(part)
                result.append(part)
    return result
