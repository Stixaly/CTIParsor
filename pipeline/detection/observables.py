"""Normalize a report's CTI entities into detection observables (ADR-0014).

The output vocabulary deliberately mirrors `pipeline.detection.atoms`: what a
report *contains* and what a rule *looks for* are expressed the same way, so the
relevance stage can compare them directly instead of falling back to the ATT&CK
tag.

Pure and stdlib-only: no I/O: callers pass rows they already read.  A malformed
row never raises — it just yields no observable.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from pipeline.detection.tlds import looks_like_domain

OBS_CLASSES: frozenset[str] = frozenset({
    "hash", "ip", "domain", "url", "file", "image",
    "registry", "user", "port", "name", "cve",
})

EXECUTABLE_SUFFIXES: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".msi", ".sh", ".elf", ".bin", ".py", ".jsp", ".war",
})
_EXEC_SUFFIXES: tuple[str, ...] = tuple(sorted(EXECUTABLE_SUFFIXES))

#: Suffixes that disqualify a domain-shaped value in `_is_report_domain`.
#:
#: `.com` is deliberately NOT here even though it is an executable suffix: it is
#: also the most common TLD in existence, so blocking it would silently drop the
#: majority of real domains from the evidence path — far worse than accepting the
#: occasional DOS COM filename, which must still pass `looks_like_domain` first.
#: `.sh` and `.py` are assigned ccTLDs and stay blocked: as CTI report values they
#: are shell and Python scripts essentially every time.
_DOMAIN_BLOCKING_SUFFIXES: tuple[str, ...] = tuple(
    sorted(EXECUTABLE_SUFFIXES - {".com"})
)

WINDOWS_HINTS: tuple[str, ...] = (
    "c:/", "d:/", "\\", ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd",
    "hklm", "hkcu", "hkey_", "system32", "syswow64", "%appdata%", "%temp%",
    "%programdata%", "appdata/roaming", "program files",
)
LINUX_HINTS: tuple[str, ...] = (
    "/etc/", "/usr/", "/var/", "/tmp/", "/bin/", "/sbin/", "/dev/",
    "/opt/", "/home/", ".sh", ".elf", "/proc/",
)
MACOS_HINTS: tuple[str, ...] = (
    "/applications/", "/library/", ".plist", ".app/", "/users/shared/",
)

#: Observable classes that carry filesystem shape — the only ones that say
#: anything about the report's platform.
_PLATFORM_CLASSES = frozenset({"file", "image", "registry"})

#: Pseudo-filesystems. Extractors routinely pick `/dev/null` or `/proc/self` out
#: of a shell one-liner and store them as `file` entities, but nothing under
#: these trees is a dropped artifact — matching a rule on them is always noise,
#: and IDF cannot catch it because they are rare *as whole field values*.
_PSEUDO_FS = ("/dev/", "/proc/", "/sys/")

_HASH_RE = re.compile(r"^[0-9a-f]{32,128}$")
_CVE_RE = re.compile(r"^cve-\d{4}-\d{4,7}$")
_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s\[dot\]\s|\[dot\]", re.IGNORECASE)
_AT_RE = re.compile(r"\[@\]|\[at\]", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class Observable:
    """One normalized technical element of a report, ready to match rule atoms."""

    obs_class: str      # a member of OBS_CLASSES
    value: str          # normalized, lowercase — the comparison key
    entity_type: str    # originating EntityType, verbatim
    display: str        # original entity value, for the UI


def _refang(text: str) -> str:
    """Undo the usual IoC defanging so a report value matches a rule literal."""
    text = re.sub(r"hxxp", "http", text, flags=re.IGNORECASE)   # hxxps → https too
    text = _DOT_RE.sub(".", text)
    text = text.replace("[:]", ":").replace("[//]", "//")
    return _AT_RE.sub("@", text).strip()


def _non_indicator_ip(value: str) -> bool:
    """Is this address one that can never be an indicator?

    Loopback, unspecified, link-local, multicast and reserved addresses appear
    in reports as incidental artifacts of a command line ("bash -i >& /dev/tcp/
    127.0.0.1/…") and in rules as boilerplate, so matching on them is noise.
    IDF cannot catch them: `127.0.0.1` is a whole atom value in only 22 of 11k
    rules, which reads as *specific*.

    RFC 1918 private ranges are deliberately kept — an internal pivot target is
    real incident content, and those addresses are rare enough in rule atoms
    that IDF handles them.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False        # unparseable — keep it rather than silently drop
    return (ip.is_loopback or ip.is_unspecified or ip.is_link_local
            or ip.is_multicast or ip.is_reserved)


def _extract_host(url: str) -> str:
    """Host of a URL: scheme, userinfo, path/query/fragment and port removed."""
    if "://" in url:
        url = url.split("://", 1)[1]
    # Cut at the *leftmost* delimiter — scanning separators in a fixed order
    # would truncate "host?a=/b" at the slash and keep "host?a=".
    cuts = [i for i in (url.find(c) for c in "/?#") if i != -1]
    if cuts:
        url = url[:min(cuts)]
    url = url.rsplit("@", 1)[-1]          # strip userinfo (may itself contain @)
    return url.split(":", 1)[0].strip().lower()


def _is_report_domain(value: str) -> bool:
    """Is this value a hostname, or a filename that merely looks like one?

    The same gate `pipeline.detection.tlds` applies to *rule* atoms (ADR-0015),
    applied here to the *report* side — an asymmetry ADR-0025 measured: the
    extractor typed `agent.ashx`, `exfil.tar.zst` and `psemhub.war` as `domain`
    entities on one real report. A bogus domain is rare by construction, so its
    IDF is ~1.0 and it ranks at the top with maximum confidence.

    `looks_like_domain` alone is not enough here: it accepts any two-letter
    final label as a ccTLD, so `meshctrl.js` passes it. Requiring the value not
    to end in an executable/script suffix closes that, and costs nothing real —
    `.js`, `.sh`, `.py` and `.pl` are ccTLDs no CTI report uses as such.

    Erring toward rejection is safe here only because it was measured: on 1,399
    domain-shaped Sigma atoms that fail the TLD test, every category but
    `.onion` was a filename, and `.onion` is now in GTLDS.
    """
    if not looks_like_domain(value):
        return False
    return not value.endswith(_DOMAIN_BLOCKING_SUFFIXES)


def _is_executable_name(value: str) -> bool:
    """Does this filesystem value name an executable?

    The mirror of `_is_report_domain`, and it needs the same `.com` carve-out for
    the same reason. `.com` is a DOS executable suffix, so a value the extractor
    typed as a `file` was emitted as an `image` too — measured on a real report,
    `pastebin.com` and `curity.com` became "executables" that way, each turning
    one domain into three artifacts.

    A `.com` value that is also a well-formed hostname is a domain essentially
    every time; genuine `.com` executables are a DOS-era rarity.
    """
    if not value.endswith(_EXEC_SUFFIXES):
        return False
    return not (value.endswith(".com") and looks_like_domain(value))


def observables_from_entities(rows: Iterable[Mapping[str, object]]) -> list[Observable]:
    """Convert entity rows into deduplicated, normalized observables.

    Args:
        rows: mappings with at least "value" and "entity_type" keys.

    Returns:
        Observables in first-seen order, unique on (obs_class, value).  One
        entity can yield several — a URL gives both a `url` and a `domain`, an
        executable path gives its full path and its basename, as `file` and
        `image`.
    """
    seen: set[tuple[str, str]] = set()
    out: list[Observable] = []

    def add(obs_class: str, value: str, entity_type: str, display: str) -> None:
        key = (obs_class, value)
        if key not in seen:
            seen.add(key)
            out.append(Observable(obs_class, value, entity_type, display))

    for row in rows:
        try:
            raw_value = row.get("value")
            raw_type = row.get("entity_type")
        except Exception:                       # noqa: BLE001 — not a mapping
            continue
        if not isinstance(raw_value, str) or not raw_value.strip():
            continue
        if not isinstance(raw_type, str) or not raw_type.strip():
            continue

        etype = raw_type.strip().lower()
        display = raw_value

        try:
            if etype in ("md5", "sha1", "sha256"):
                val = _refang(raw_value).lower()
                if _HASH_RE.match(val):
                    add("hash", val, etype, display)

            elif etype in ("ipv4", "ipv6"):
                val = _refang(raw_value).lower()
                if val and not _non_indicator_ip(val):
                    add("ip", val, etype, display)

            elif etype == "domain":
                val = _refang(raw_value).lower().removeprefix("www.").removesuffix(".")
                if len(val) >= 4 and _is_report_domain(val):
                    add("domain", val, etype, display)

            elif etype == "url":
                val = _refang(raw_value).lower()
                if len(val) >= 4:
                    add("url", val, etype, display)
                host = _extract_host(val)
                if len(host) >= 4 and _is_report_domain(host):
                    add("domain", host, etype, display)

            elif etype == "email":
                val = _refang(raw_value).lower()
                if "@" in val:
                    host = val.rsplit("@", 1)[-1]
                    if len(host) >= 4 and _is_report_domain(host):
                        add("domain", host, etype, display)

            elif etype == "file":
                val = _refang(raw_value).lower().replace("\\", "/")
                if val.startswith(_PSEUDO_FS):
                    continue
                # A hostname typed as a file is not a file. ADR-0025 put this
                # gate on the domain side, so `agent.ashx` cannot become a
                # domain; ADR-0031 measured the mirror defect. On the UNC6671
                # report all 78 `file` entities were the campaign's phishing
                # domains, and 77 were already emitted as `domain` observables —
                # duplicates that inflated the observable count and opened a
                # substring-match path (`file: gmail.com` matched an lsassy
                # rule). A value carrying a path separator is always kept: a
                # path is a file, whatever its final segment looks like.
                # Re-routed, never dropped: `add` dedups on (class, value), so
                # when a `domain` entity already produced it this is a no-op,
                # and when the extractor typed it ONLY as a file the observable
                # survives in the class it actually belongs to.
                if "/" not in val and _is_report_domain(val):
                    add("domain", val, etype, display)
                    continue
                # Index the full path *and* the basename: a report naming only
                # the binary must still match a rule pinning its install path.
                candidates = [val]
                if "/" in val:
                    base = val.rsplit("/", 1)[-1]
                    if base and base != val:
                        candidates.append(base)
                for cand in candidates:
                    if len(cand) < 4:
                        continue
                    add("file", cand, etype, display)
                    if _is_executable_name(cand):
                        add("image", cand, etype, display)

            elif etype == "registry_key":
                val = raw_value.strip().lower().replace("\\", "/")
                if len(val) >= 4:
                    add("registry", val, etype, display)

            elif etype == "user_account":
                val = raw_value.strip().lower()
                if len(val) >= 4:
                    add("user", val, etype, display)

            elif etype == "network_traffic":
                val = raw_value.strip()
                if val.isdigit() and 1 <= len(val) <= 5:
                    add("port", val, etype, display)

            elif etype == "cve":
                val = raw_value.strip().lower()
                if _CVE_RE.match(val):
                    add("cve", val, etype, display)

            elif etype in ("tool", "malware"):
                val = raw_value.strip().lower()
                if len(val) >= 4:
                    add("name", val, etype, display)
                    if _is_executable_name(val):
                        add("image", val, etype, display)

            # Every other entity type (ttp, threat_actor, campaign, …) is not a
            # detection observable — it says who, not what to look for.
        except Exception:                       # noqa: BLE001 — one bad row, not a crash
            continue

    return out


def report_platform(observables: Iterable[Observable]) -> str:
    """Infer the report's dominant OS from the shape of its paths and keys.

    Returns "windows", "linux", "macos", "multi" (mixed or too weak to call), or
    "" when nothing in the report says anything about a platform.
    """
    # One vote per *source entity*, not per derived observable.  A Windows path
    # expands to two values that both carry the hint ("c:/a/x.exe" and "x.exe"
    # each contain ".exe") while a Linux path expands to one ("/usr/bin/pv" then
    # a hint-free basename) — counting values would inflate Windows roughly 2×.
    marks: dict[str, set[str]] = {}
    for obs in observables:
        if obs.obs_class not in _PLATFORM_CLASSES:
            continue
        hit = marks.setdefault(obs.display, set())
        for name, hints in (("windows", WINDOWS_HINTS),
                            ("linux", LINUX_HINTS),
                            ("macos", MACOS_HINTS)):
            if any(h in obs.value for h in hints):
                hit.add(name)

    scores = {"windows": 0, "linux": 0, "macos": 0}
    for hit in marks.values():
        for name in hit:
            scores[name] += 1

    top_score = max(scores.values())
    if top_score == 0:
        return ""
    leaders = [n for n, s in scores.items() if s == top_score]
    if len(leaders) > 1:
        return "multi"
    second = max(s for n, s in scores.items() if n != leaders[0])
    # Require a clear margin: a couple of stray Windows-looking strings in a
    # Linux report must not flip the whole ranking.
    return leaders[0] if top_score >= 2 and top_score >= 2 * second else "multi"
