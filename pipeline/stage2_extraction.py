import os
import re
from urllib.parse import urlparse

from models.schemas import EntityType, RawEntity

_SKIP_HEAVY = os.getenv("SKIP_HEAVY_MODELS") == "1"

try:
    import re2 as _re2_module
    _RE2_AVAILABLE = True
except ImportError:
    _re2_module = None
    _RE2_AVAILABLE = False

try:
    import spacy as _spacy_module
except ImportError:
    _spacy_module = None  # type: ignore[assignment]


def _compile_pattern(pattern: str, flags: int = 0):
    """
    Compile a regex pattern, using re2 if available for ReDoS protection.

    re2 guarantees linear time matching and prevents catastrophic backtracking.
    Falls back to standard re if re2 is not installed.
    """
    if _RE2_AVAILABLE:
        try:
            return _re2_module.compile(pattern, flags)
        except Exception:
            pass
    return re.compile(pattern, flags)

# Regex to detect bare version numbers (e.g. "0.1.16", "1.167.71") that SpaCy
# sometimes tags as PRODUCT or even ORG and would otherwise pollute entity lists.
# fullmatch() is used so no anchors are needed in the pattern.
_VERSION_PATTERN = re.compile(r"\d+[\.\d\-]*\d")

# Common tokens that SpaCy labels as PRODUCT but are clearly not malware families.
# Kept intentionally conservative — only entries we're very confident about.
_NER_PRODUCT_BLOCKLIST = frozenset({
    # Generic tech acronyms
    "api", "sdk", "ide", "cli", "ui", "ux", "css", "html", "json", "xml", "yaml",
    "rest", "rpc", "grpc", "graphql", "http", "https", "tcp", "udp", "dns",
    "ssl", "tls", "oauth", "jwt", "ldap", "saml", "sso", "mfa", "2fa",
    # Languages / runtimes
    "python", "javascript", "typescript", "java", "golang", "go", "rust", "ruby",
    "node", "nodejs", "deno", "bun", "php",
    # Frameworks / libraries
    "react", "vue", "angular", "svelte", "next", "nuxt", "django", "flask",
    "fastapi", "spring", "express", "rails",
    # Platforms / infra
    "linux", "windows", "macos", "android", "ios", "ubuntu", "debian",
    "docker", "kubernetes", "terraform", "ansible",
    # Registries / package managers
    "npm", "pypi", "pip", "cargo", "nuget", "maven",
    # Cloud / CDN
    "aws", "azure", "gcp", "cloudflare", "akamai",
    # CTI / STIX meta-terms
    "ioc", "ttp", "cve", "cpe", "stix", "taxii", "c2",
    # Misc words that slip through
    "package", "library", "module", "plugin", "extension", "script",
    "binary", "executable", "payload", "dropper",
})

try:
    import iocextract
    _IOCEXTRACT_AVAILABLE = True
except ImportError:
    _IOCEXTRACT_AVAILABLE = False

_nlp = None
if _spacy_module is not None and not _SKIP_HEAVY:
    try:
        _nlp = _spacy_module.load("en_core_web_lg")
    except OSError:
        try:
            _nlp = _spacy_module.load("en_core_web_sm")
        except OSError:
            _nlp = None

# --- Patterns regex ---

# CVE IDs — tolerate the dash/hyphen variants and zero-width characters that
# "smart" typography (Word/PDF exports) and copy-paste often substitute for
# the literal hyphen between CVE / year / sequence number.
# Dashes: hyphen-minus, hyphen..horizontal bar (U+2010-2015), minus sign,
#         small/fullwidth hyphen-minus, soft hyphen.
_CVE_DASH = "\\-‐-―−﹣－­"
# Zero-width / invisible separators that can appear between CVE components.
_CVE_ZW = "​‌‍⁠﻿"
_CVE_PATTERN = re.compile(
    rf"CVE[{_CVE_ZW}]*[{_CVE_DASH}][{_CVE_ZW}]*\d{{4}}[{_CVE_ZW}]*[{_CVE_DASH}][{_CVE_ZW}]*\d{{4,7}}",
    re.IGNORECASE,
)
_CVE_ZW_PATTERN = re.compile(f"[{_CVE_ZW}]")
_CVE_DASH_PATTERN = re.compile(f"[{_CVE_DASH}]")

# MITRE ATT&CK IDs — technique (T####[.###]) and tactic (TA####).
_MITRE_TTP_PATTERN = re.compile(r"\bTA?\d{4}(?:\.\d{3})?\b")
_HASH_PATTERN = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")

# The leading/trailing (?<![\d.]) / (?![\d.]) guards stop the pattern from
# slicing four octets out of a longer dotted-number run.  Without them
# "192.168.1.1.5" (a 5-part build/sequence string) yielded a bogus IoC
# "192.168.1.1".  The guards are harmless to .fullmatch() — at the string
# boundaries the negative lookarounds always succeed — so a real dotted quad
# like "192.168.1.1" still validates.
_IPV4_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?![\d.])"
)

# Domaines : structure générique (sous-domaines + TLD ≥ 2 chars)
# Exclut les extensions de fichiers courantes (.py, .js, .exe…) et les nombres purs
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}"
    r"(?!(?:py|js|ts|go|rb|php|sh|exe|dll|bin|elf|ps1|bat|vbs|zip|tar|gz|pdf|docx?|xlsx?|png|jpg|gif|svg|css|json|xml|yml|yaml|log|txt|md|cfg|ini|conf)\b)"
    r"[a-zA-Z]{2,12}\b",
    re.IGNORECASE,
)

# URLs complètes (http/https/ftp + domaine + chemin optionnel)
_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

# Emails
_EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# MAC addresses — colon or hyphen separated (00:1A:2B:3C:4D:5E / 00-1A-2B-3C-4D-5E)
# Cisco dot notation (001A.2B3C.4D5E) included as a second alternative.
_MAC_COLON_HYPHEN = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"
)
_MAC_CISCO = re.compile(
    r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b"
)

# ASN — "AS15169", "AS 15169", "ASN15169", "ASN 15169" (1–10 digits).
# Case-sensitive on purpose: matching the lowercase English word "as" (e.g.
# "as 2024 approached", "increased as 50 percent") generated a flood of bogus
# AS numbers.  ASNs are conventionally written uppercase, so requiring "AS"/"ASN"
# in caps removes the prose false positives while keeping every real format.
_ASN_PATTERN = re.compile(r"\bAS(?:N\s*|\s*)(\d{1,10})\b")

# Windows file paths — drive letter or UNC share, at least one path component,
# and a file extension.  Spaces are excluded from path components so the match
# stops at the end of the actual filename (avoids greedy over-matching).
# Examples: C:\Windows\System32\cmd.exe  \\server\share\payload.dll
_WIN_PATH_PATTERN = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[^\\\s]+\\[^\\\s]+\\)"   # drive root or UNC root
    r"(?:[^\\\s\n\r\t<>:\"|?*\x00-\x1F]+\\)*"      # zero or more directories (no spaces)
    r"[^\\\s\n\r\t<>:\"|?*\x00-\x1F]+\.[A-Za-z]{2,10}\b",  # filename.ext (no spaces)
    re.IGNORECASE,
)

# Unix / Linux file paths — must start with a recognised system root directory
# to avoid false positives on prose fragments.
# Examples: /tmp/backdoor.elf  /usr/bin/python3  /proc/self/exe
_UNIX_PATH_PATTERN = re.compile(
    r"(?<!\w)"
    r"/(?:bin|boot|dev|etc|home|lib(?:64)?|opt|proc|root|run|sbin|srv|sys|tmp|usr|var)"
    r"(?:/[^\s\x00-\x1F<>\"'`|&;()\[\]{}\\]+)+",
)

# Windows registry keys — all standard hive abbreviations and full names.
# Examples: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
#           HKEY_CURRENT_USER\Software\Classes\...
_REG_KEY_PATTERN = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT"
    r"|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
    r"(?:\\[^\\\n\r\t<>:\"|\x00-\x1F]+)+",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Defanging — normalise all common CTI analyst conventions back to live form.
#
# Combined into a single regex for O(1) matching passes over large documents.
# ---------------------------------------------------------------------------
_DEFANG_PATTERN = re.compile(
    r"hxxps?://|h\[tt\]ps?://|https?\[s\]://|https?\[:\]://|meow://|fxx?p://|"
    r"\s+\[\.\]\s+|\s+\(\.\)\s+|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|"
    r"\[:\]|\(:\)|"
    r"\[//\]|\[/\]|"
    r"\[@\]|\(@\)|\{@\}|\[at\]|\(at\)",
    re.IGNORECASE
)

def _defang_repl(match: re.Match) -> str:
    m = match.group(0).lower()

    if m.startswith('meow'):
        return 'http://'
    if m.startswith('h') or m.startswith('f'):
        if m.startswith('f'):
            return 'ftp://'
        # Any http variation that contains 's' but is not explicitly HTTP
        if 's' in m and m != 'http[:]//' and m != 'hxxp://' and m != 'h[tt]p://':
            return 'https://'
        return 'http://'

    # Check '@' forms before '.'/'{' — "{@}" and "(@)" would otherwise be
    # mistaken for the dot-replacement branch below.
    if 'at' in m or '@' in m:
        return '@'
    if 'dot' in m or '.' in m or '{' in m:
        return '.'
    if '//' in m:
        return '//'
    if '/' in m:
        return '/'
    if ':' in m:
        return ':'
    return m

def refang(text: str) -> str:
    """
    Normalise defanged IoCs back to their live form.
    Handles all common CTI analyst conventions in a single fast regex pass.
    """
    if not text:
        return text
    return _DEFANG_PATTERN.sub(_defang_repl, text)


def extract_entities(text: str) -> list[RawEntity]:
    """
    Extrait toutes les entités IoC du texte.

    Stratégie :
    - Refanging d'abord  → normalise hxxps, [.], etc.
    - Hashes             → regex fixe, toujours fiable
    - Réseau (IP/URL/…)  → iocextract + regex complémentaires
    - CVE / TTP          → regex
    - NER                → spaCy pour malwares et acteurs
    """
    refanged = refang(text)

    entities: list[RawEntity] = []
    entities.extend(_extract_hashes_regex(refanged))
    entities.extend(_extract_network_iocs(refanged))
    entities.extend(_extract_cves(refanged))
    entities.extend(_extract_mitre_ttps(refanged))
    entities.extend(_extract_mac_addresses(refanged))
    entities.extend(_extract_asns(refanged))
    entities.extend(_extract_file_paths(refanged))
    entities.extend(_extract_registry_keys(refanged))

    if _nlp is not None:
        entities.extend(_extract_ner_entities(refanged))

    return _deduplicate(entities)


def _extract_hashes_regex(text: str) -> list[RawEntity]:
    """
    Extract SHA256, SHA1, and MD5 hashes in a single pass.
    The regex naturally enforces that hashes of different lengths cannot overlap
    because they are strictly bounded by word boundaries (`\\b`), and hex characters
    contain no internal word boundaries.
    """
    results = []
    seen_values: set[str] = set()

    for m in _HASH_PATTERN.finditer(text):
        v = m.group(1).lower()
        if v not in seen_values:
            seen_values.add(v)
            length = len(v)
            if length == 64:
                results.append(RawEntity(value=v, entity_type=EntityType.SHA256))
            elif length == 40:
                results.append(RawEntity(value=v, entity_type=EntityType.SHA1))
            else:
                results.append(RawEntity(value=v, entity_type=EntityType.MD5))

    return results


def _extract_network_iocs(text: str) -> list[RawEntity]:
    """
    Extrait IP, URL, domaines et emails.
    iocextract est utilisé s'il est disponible, mais les regex tournent
    toujours en complément pour ne rien manquer.
    """
    results: list[RawEntity] = []

    # --- iocextract (gère le defanging résiduel) ---
    if _IOCEXTRACT_AVAILABLE:
        try:
            for ip in iocextract.extract_ipv4s(text, refang=True):
                ip = ip.strip()
                if _IPV4_PATTERN.fullmatch(ip):
                    results.append(RawEntity(value=ip, entity_type=EntityType.IPV4))

            for ip in iocextract.extract_ipv6s(text, refang=True):
                if ip.strip():
                    results.append(RawEntity(value=ip.strip(), entity_type=EntityType.IPV6))

            for url in iocextract.extract_urls(text, refang=True):
                url = url.strip()
                if url.startswith(("http://", "https://", "ftp://")):
                    results.append(RawEntity(value=url, entity_type=EntityType.URL))

            for email in iocextract.extract_emails(text, refang=True):
                if "@" in email:
                    results.append(RawEntity(value=email.strip(), entity_type=EntityType.EMAIL))
        except Exception:
            pass

    # --- Regex complémentaires (toujours actifs) ---

    # IPv4 par regex (complète iocextract sur certains formats)
    for m in _IPV4_PATTERN.finditer(text):
        results.append(RawEntity(value=m.group(), entity_type=EntityType.IPV4))

    # URLs complètes
    for m in _URL_PATTERN.finditer(text):
        url = m.group()
        # Only strip trailing punctuation that cannot be part of a URL
        # Keep trailing slash, hash, query params
        while url and url[-1] in '".),;}\'':
            url = url[:-1]
        results.append(RawEntity(value=url, entity_type=EntityType.URL))

    # Emails
    for m in _EMAIL_PATTERN.finditer(text):
        results.append(RawEntity(value=m.group().lower(), entity_type=EntityType.EMAIL))

    # Domaines isolés (pas déjà capturés dans une URL)
    # Extract hostnames properly via urlparse so path components don't cause
    # false suppression (e.g. url "/data/evil.com/log" wouldn't suppress evil.com).
    url_hostnames = set()
    for e in results:
        if e.entity_type == EntityType.URL:
            host = urlparse(e.value).netloc.lower().split(":")[0]  # strip port
            if host:
                url_hostnames.add(host)
        elif e.entity_type == EntityType.EMAIL:
            parts = e.value.split("@")
            if len(parts) == 2:
                url_hostnames.add(parts[1].lower())
    for m in _DOMAIN_PATTERN.finditer(text):
        domain = m.group().lower()
        if domain not in url_hostnames:
            results.append(RawEntity(value=domain, entity_type=EntityType.DOMAIN))

    return results


def _extract_mac_addresses(text: str) -> list[RawEntity]:
    """
    Extract MAC addresses in colon/hyphen (00:1A:2B:3C:4D:5E) and
    Cisco dot (001A.2B3C.4D5E) notation.
    All values are normalised to lower-case colon form for deduplication.
    """
    results: list[RawEntity] = []
    seen: set[str] = set()

    for m in _MAC_COLON_HYPHEN.finditer(text):
        v = m.group().lower().replace("-", ":")
        if v not in seen:
            seen.add(v)
            results.append(RawEntity(value=v, entity_type=EntityType.MAC_ADDR))

    for m in _MAC_CISCO.finditer(text):
        raw = m.group().replace(".", "").lower()
        # Convert "001a2b3c4d5e" → "00:1a:2b:3c:4d:5e"
        v = ":".join(raw[i:i+2] for i in range(0, 12, 2))
        if v not in seen:
            seen.add(v)
            results.append(RawEntity(value=v, entity_type=EntityType.MAC_ADDR))

    return results


def _extract_asns(text: str) -> list[RawEntity]:
    """
    Extract Autonomous System Numbers: AS15169, AS 15169, ASN 15169.
    Stores the canonical "AS{n}" form.
    """
    results: list[RawEntity] = []
    seen: set[str] = set()
    for m in _ASN_PATTERN.finditer(text):
        v = f"AS{m.group(1)}"
        if v not in seen:
            seen.add(v)
            results.append(RawEntity(value=v, entity_type=EntityType.ASN))
    return results


def _extract_file_paths(text: str) -> list[RawEntity]:
    """
    Extract Windows absolute paths (C:\\...) and common Unix system paths
    (/tmp/..., /usr/bin/..., etc.).

    Note: bare filenames without a path (e.g. "payload.exe") are intentionally
    NOT extracted here — they generate too many false positives in prose.
    Filenames found inside an extracted path are captured implicitly via the
    full path value.
    """
    results: list[RawEntity] = []
    seen: set[str] = set()

    for pattern in (_WIN_PATH_PATTERN, _UNIX_PATH_PATTERN):
        for m in pattern.finditer(text):
            v = m.group().strip()
            key = v.lower()
            if key not in seen:
                seen.add(key)
                results.append(RawEntity(value=v, entity_type=EntityType.FILE))

    return results


def _extract_registry_keys(text: str) -> list[RawEntity]:
    """
    Extract Windows registry key paths starting with any recognised hive
    abbreviation or full name (HKLM, HKCU, HKEY_LOCAL_MACHINE, …).
    """
    results: list[RawEntity] = []
    seen: set[str] = set()
    for m in _REG_KEY_PATTERN.finditer(text):
        v = m.group().strip()
        key = v.upper()
        if key not in seen:
            seen.add(key)
            results.append(RawEntity(value=v, entity_type=EntityType.REGISTRY_KEY))
    return results


def _extract_cves(text: str) -> list[RawEntity]:
    seen: set[str] = set()
    results: list[RawEntity] = []
    for m in _CVE_PATTERN.finditer(text):
        # Strip zero-width separators and normalise any dash variant to "-"
        # so "CVE​‑ 2024– 1234" becomes the canonical "CVE-2024-1234".
        v = _CVE_ZW_PATTERN.sub("", m.group())
        v = _CVE_DASH_PATTERN.sub("-", v).upper()
        if v not in seen:
            seen.add(v)
            results.append(RawEntity(value=v, entity_type=EntityType.CVE))
    return results


def _extract_mitre_ttps(text: str) -> list[RawEntity]:
    seen: set[str] = set()
    results: list[RawEntity] = []
    for m in _MITRE_TTP_PATTERN.finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            # TA#### IDs are ATT&CK tactics; T####[.###] are techniques/sub-techniques.
            etype = EntityType.TACTIC if v.startswith("TA") else EntityType.TTP
            results.append(RawEntity(value=v, entity_type=etype, mitre_id=v))
    return results



# Countries / geopolitical names that spaCy labels as GPE but are too generic
# or are frequently false-positives in CTI reports.
_GPE_BLOCKLIST = frozenset({
    # Vague directional / regional terms
    "west", "east", "north", "south", "western", "eastern", "northern", "southern",
    "central", "middle", "far east", "southeast", "southwest", "northeast", "northwest",
    # Internet / cyber meta-terms
    "internet", "web", "dark web", "darknet",
    # Overly generic
    "worldwide", "global", "international", "overseas",
})


def _extract_ner_entities(text: str) -> list[RawEntity]:
    """
    spaCy NER for named entities.

    Extracts two kinds of entities:

    PRODUCT → MALWARE
        Malware family hints.  Filtered against a blocklist of common tech
        terms that spaCy frequently mislabels as PRODUCT.
        NOTE: ORG is intentionally NOT mapped to THREAT_ACTOR — spaCy's
        en_core_web labels every victim company, cloud provider, and package
        registry as ORG.  CTI-specific named entity recognition is handled
        by Stage 2b (Gazetteer) and Stage 2d (CyNER), which are far more
        precise.  Any remaining novel actors are found by the Stage 3 LLM.

    GPE → LOCATION
        Countries, cities, and geopolitical entities — used to populate
        targeted_countries / location STIX objects without LLM involvement.
        Filtered against a small blocklist of directional / generic terms
        that spaCy often mislabels as GPE.
    """
    if _nlp is None:
        # Guards mypy (the module-level None-check in the caller can't be
        # narrowed across the function boundary) and protects against direct
        # calls when spaCy failed to load / SKIP_HEAVY_MODELS is set.
        return []

    doc = _nlp(text[:100_000])
    results = []

    label_map = {
        "PRODUCT": EntityType.MALWARE,
        "GPE":     EntityType.LOCATION,   # country / city / geopolitical entity
    }

    for ent in doc.ents:
        etype = label_map.get(ent.label_)
        if etype is None:
            continue

        value = ent.text.strip()

        # Skip bare version strings ("0.1.16", "1.167.71")
        if _VERSION_PATTERN.fullmatch(value):
            continue
        # Skip npm/Python package scopes/names starting with "@"
        if value.startswith("@"):
            continue
        # Skip very short tokens (single letters, abbreviations < 3 chars) and pure numbers
        if len(value) <= 2 or value.isdigit():
            continue

        if etype == EntityType.MALWARE:
            if value.lower() in _NER_PRODUCT_BLOCKLIST:
                continue
            results.append(RawEntity(
                value=value,
                entity_type=etype,
                context=ent.sent.text[:200],
                confidence=0.6,
                source="spacy",
            ))

        elif etype == EntityType.LOCATION:
            if value.lower() in _GPE_BLOCKLIST:
                continue
            results.append(RawEntity(
                value=value,
                entity_type=etype,
                context=ent.sent.text[:200],
                confidence=0.72,   # GPE labels are reliable; still below gazetteer (0.88+)
                source="spacy",
            ))

    return results


def _deduplicate(entities: list[RawEntity]) -> list[RawEntity]:
    seen: set[tuple] = set()
    unique = []
    for entity in entities:
        key = (entity.value.lower(), entity.entity_type)
        if key not in seen:
            seen.add(key)
            unique.append(entity)
    return unique


# ---------------------------------------------------------------------------
# ExtractionStage class wrapper — consumed by pipeline.registry
# ---------------------------------------------------------------------------

from pipeline.base import BaseExtractionStage  # noqa: E402


class RegexExtractionStage(BaseExtractionStage):
    """Stage-2 regex extractor as an ExtractionStage implementation."""

    name = "regex"

    def __init__(self, config=None) -> None:  # config ignored; regex has no model
        pass

    def available(self) -> bool:
        return True

    def extract(self, text: str) -> list[RawEntity]:
        return extract_entities(text)
