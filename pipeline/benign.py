"""Values a report names without accusing them (audit B 8.1.7).

A report says "the malware checks connectivity with www.google.com", "the
victim host 10.0.0.5", "see https://www.mandiant.com/resources/blog/apt29":
Stage 2 extracts every one, and Stage 4 used to give each an Indicator typed
`malicious-activity`.  An Indicator is a detection: a consumer that loads the
bundle would alert on Google.

`benign_reason` names why a value is not one:

- a non-routable address (private, loopback, link-local, documentation,
  shared, reserved, multicast): Python's `ipaddress`, not a list;
- the four big public DNS resolvers (Google, Cloudflare, Quad9, OpenDNS),
  which malware queries to test its connectivity: named here, since MISP's
  public-dns-v4 lists 62,780 open resolvers, a compromised C2 among them
  possibly;
- a vendor's, researcher's or sandbox's site, the host of a reference link
  (MISP warninglists security-provider-blogpost, automated-malware-analysis;
  the host or any subdomain of it), except the platforms anyone publishes on
  that the blogpost list also carries (GitHub and its gist/raw hosts, Google
  Sites, Medium, Twitter, S3…): a payload on `raw.githubusercontent.com` or
  `sites.google.com` is a payload;
- one of the 10,000 most popular domains (MISP warninglist tranco10k), for
  that exact domain only: `x.duckdns.org` or `evil.blogspot.com` are not
  popular because their parent is, and a URL on a popular domain keeps its
  Indicator (a payload on GitHub is still a payload).

A leading `www.` is ignored on both sides of the comparison: `alienvault.com`
and `www.alienvault.com` are the same site (#411).

A legitimate observable is not one either (ADR-0095), from a list written for
this project, `data/legitimate_observables.json`:

- a Windows system binary or DLL, bare or in its standard directory
  (`rundll32.exe`, `C:\\Windows\\System32\\comsvcs.dll`), a standard Unix
  file (`.bash_history`, `/usr/bin/curl`): `legitimate_file:windows|unix`;
- a standard registry key, exactly (`...\\CurrentVersion\\Run`, not a
  subkey of it): `legitimate_registry_key`.  The SAM, SECURITY and SYSTEM
  hives are never listed: their copy is what an attacker steals;
- a value no sensor matches as an IoC: a GUID, a device name (`\\\\.\\X`), a
  messenger handle (`@name`): `no_ioc_type:guid|device|messenger_handle`.

The observable still ships, without an Indicator; Stage 4's ledger says why.
`BENIGN_IOC_FILTER=false` turns this off.  The warning lists are vendored by
`scripts/build_warninglists.py` (CC0 1.0).
"""
from __future__ import annotations

import functools
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from api.logging_config import get_logger
from models.schemas import EntityType
from pipeline.env_flags import env_bool

logger = get_logger(__name__)

_PATH = Path(__file__).parent / "data" / "warninglists.json"
_REFERENCE_LISTS = ("security-provider-blogpost", "automated-malware-analysis")
_POPULAR_LIST = "tranco10k"

# Entries of the reference lists where anyone can publish: a link there is a
# reference only as often as it is a payload.  A named author's page on such a
# platform (gchq.github.io, a blog on blogspot) stays a reference.
_USER_CONTENT = frozenset({
    "github.com", "raw.githubusercontent.com", "gist.githubusercontent.com", "medium.com",
    "gist.github.com", "raw.github.com", "sites.google.com",
    "twitter.com", "t.co", "facebook.com", "www.facebook.com", "stackoverflow.com",
    "dropbox.com", "www.dropbox.com", "pastebin.lu",
    "s3-eu-west-1.amazonaws.com", "s3-us-west-2.amazonaws.com",
})


_PUBLIC_RESOLVERS = frozenset({
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2620:fe::fe", "2620:fe::9",
})


def enabled() -> bool:
    return env_bool("BENIGN_IOC_FILTER", default=True)


def _bare(host: str) -> str:
    """`host` without a leading `www.` (#411)."""
    return host[4:] if host.startswith("www.") else host


@functools.lru_cache(maxsize=1)
def _lists() -> dict[str, frozenset[str]]:
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"[benign] {_PATH.name} unreadable, no warninglist applies: "
                       f"{type(exc).__name__}: {exc}")
        return {}
    lists = {name: frozenset(_bare(v) for v in entry.get("values", []))
             for name, entry in data.get("lists", {}).items()}
    user_content = frozenset(_bare(v) for v in _USER_CONTENT)
    for name in _REFERENCE_LISTS:
        if name in lists:
            lists[name] = lists[name] - user_content
    return lists


def _host_in(host: str, values: frozenset[str]) -> bool:
    """`host` or one of its parent domains is listed."""
    parts = host.split(".")
    return any(".".join(parts[i:]) in values for i in range(len(parts) - 1))


def _reference_site(host: str) -> str | None:
    lists = _lists()
    host = _bare(host)
    for name in _REFERENCE_LISTS:
        if _host_in(host, lists.get(name, frozenset())):
            return f"reference_site:{name}"
    return None


def benign_reason(entity_type: EntityType, value: str) -> str | None:
    """Why `value` is not an indicator of compromise, or None."""
    if not enabled() or not isinstance(value, str) or not value.strip():
        return None
    v = value.strip().lower()
    if entity_type in (EntityType.IPV4, EntityType.IPV6):
        try:
            address = ipaddress.ip_address(v)
        except ValueError:
            return None
        if not address.is_global:
            return "non_routable_address"
        return "public_dns_resolver" if str(address) in _PUBLIC_RESOLVERS else None
    if entity_type == EntityType.DOMAIN:
        host = v.rstrip(".")
        reference = _reference_site(host)
        if reference:
            return reference
        if _bare(host) in _lists().get(_POPULAR_LIST, frozenset()):
            return f"popular_domain:{_POPULAR_LIST}"
        return None
    if entity_type == EntityType.URL:
        try:
            host = (urlsplit(v).hostname or "").rstrip(".")
        except ValueError:
            return None
        return _reference_site(host) if host else None
    if entity_type == EntityType.FILE:
        return _file_reason(v)
    if entity_type == EntityType.REGISTRY_KEY:
        if _GUID.fullmatch(v):
            return "no_ioc_type:guid"
        key = registry_path(v)
        return "legitimate_registry_key" if key and key in _legit().registry_keys else None
    if entity_type == EntityType.USER_ACCOUNT:
        if _GUID.fullmatch(v):
            return "no_ioc_type:guid"
        return "no_ioc_type:messenger_handle" if _HANDLE.fullmatch(v) else None
    return None


# ── Legitimate observables (ADR-0095) ────────────────────────────────────────
# A Windows binary at its standard place, a standard registry key, a shell's
# history file: present on every system of their kind, so an Indicator on one
# matches every machine.  And values no sensor can match as an IoC: a GUID, a
# device name, a messenger handle.  The lists are pipeline/data/
# legitimate_observables.json, matched exactly: `C:\Users\Public\svchost.exe`
# (a system name outside its directory) and `schtask.exe` (a near miss) keep
# their Indicator; so does a file with a hash, which this module never sees
# (Stage 4 asks only for hashless files).

_LEGIT_PATH = Path(__file__).parent / "data" / "legitimate_observables.json"
_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HANDLE = re.compile(r"@[a-z0-9_]{3,64}")
_DRIVE = re.compile(r"[a-z]:\\")
_HIVES = frozenset({"hkey_local_machine", "hklm", "hkey_current_user", "hkcu", "hkey_users", "hku",
                    "hkey_classes_root", "hkcr", "hkey_current_config", "hkcc"})
_CONTROL_SET = re.compile(r"controlset\d{3}")


@dataclass(frozen=True)
class _Legit:
    windows_roots: tuple[str, ...] = ()
    windows_files: dict[str, frozenset[str]] = field(default_factory=dict)  # name -> dirs under the root
    unix_files: dict[str, frozenset[str]] = field(default_factory=dict)     # name -> dir patterns
    registry_keys: frozenset[str] = frozenset()


def _by_name(groups: list) -> dict[str, frozenset[str]]:
    out: dict[str, set[str]] = {}
    for group in groups:
        dirs = {str(d).lower() for d in group.get("dirs", [])}
        for name in group.get("names", []):
            out.setdefault(str(name).lower(), set()).update(dirs)
    return {name: frozenset(dirs) for name, dirs in out.items()}


@functools.lru_cache(maxsize=1)
def _legit() -> _Legit:
    try:
        data = json.loads(_LEGIT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning(f"[benign] {_LEGIT_PATH.name} unreadable, no file or key is legitimate: "
                       f"{type(exc).__name__}: {exc}")
        return _Legit()
    # Longest root first: `\windows` must not match before `c:\windows`.
    roots = tuple(sorted((str(r).lower() for r in data.get("windows_roots", [])), key=len, reverse=True))
    return _Legit(
        windows_roots=roots,
        windows_files=_by_name(data.get("windows_files", [])),
        unix_files=_by_name(data.get("unix_files", [])),
        registry_keys=frozenset(registry_path(k) for k in data.get("windows_registry_keys", [])),
    )


def registry_path(value: str) -> str:
    """A registry key without its hive, lower-cased, in one spelling:
    `HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\...\\Run` and
    `HKCU\\Software\\Microsoft\\...\\Run` are both `software\\microsoft\\...\\run`.
    The hive is dropped because the list's keys exist under either; a key under
    `HKU\\<SID>` loses the SID too.  `HKLM\\SYSTEM` is `system`."""
    v = value.strip().strip("\"'").lower().replace("/", "\\")
    parts = [p for p in v.split("\\") if p]
    if parts[:1] == ["registry"] and parts[1:2] in (["machine"], ["user"]):  # kernel spelling
        parts = (["hklm"] if parts[1] == "machine" else ["hku"]) + parts[2:]
    if parts and parts[0] in _HIVES:
        hive = parts.pop(0)
        if hive in ("hkey_users", "hku") and parts:
            parts.pop(0)
    if parts[:2] == ["software", "wow6432node"]:
        del parts[1]
    if len(parts) >= 2 and parts[0] == "system" and _CONTROL_SET.fullmatch(parts[1]):
        parts[1] = "currentcontrolset"
    return "\\".join(parts)


def _windows_dir(directory: str) -> str | None:
    """`directory` relative to the Windows directory, or None if it is
    elsewhere.  A relative `System32` counts as the system one."""
    legit = _legit()
    d = directory
    if d.startswith("\\??\\"):
        d = d[4:]
    if _DRIVE.match(d):
        d = "c" + d[1:]  # Windows is installed on C: or elsewhere, same layout
    for root in legit.windows_roots:
        if d == root:
            return ""
        if d.startswith(root + "\\"):
            return d[len(root) + 1:]
    return None if _DRIVE.match(d) or d.startswith("\\") or d.startswith("%") else d


def _unix_dir_matches(directory: str, patterns: frozenset[str]) -> bool:
    d = directory.rstrip("/") or "/"
    if d == "$home":
        d = "~"
    for pattern in patterns:
        want, got = pattern.split("/"), d.split("/")
        if len(want) == len(got) and all(w == g or (w == "*" and g) for w, g in zip(want, got, strict=True)):
            return True
    return False


def _file_reason(v: str) -> str | None:
    v = v.strip("\"'")
    if v.startswith(("\\\\.\\", "\\\\?\\globalroot", "\\device\\")):
        return "no_ioc_type:device"
    if _GUID.fullmatch(v):
        return "no_ioc_type:guid"
    legit = _legit()
    windows = "\\" in v or bool(_DRIVE.match(v.replace("/", "\\")))
    if windows:
        directory, _, name = v.replace("/", "\\").rpartition("\\")
        dirs = legit.windows_files.get(name)
        if dirs is None or directory.startswith("\\\\"):  # a UNC share is another machine
            return None
        rel = _windows_dir(directory)
        return "legitimate_file:windows" if rel is not None and rel in dirs else None
    if "/" in v:
        directory, _, name = v.rpartition("/")
        dirs = legit.unix_files.get(name)
        if dirs is None:
            return None
        return "legitimate_file:unix" if _unix_dir_matches(directory or "/", dirs) else None
    if v in legit.windows_files:
        return "legitimate_file:windows"
    if v in legit.unix_files:
        return "legitimate_file:unix"
    return None
