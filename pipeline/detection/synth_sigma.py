"""Generate draft Sigma rules from CTI report observables (ADR-0016).

This module is a pure function: no I/O, no database, no network, no randomness.
It converts a list of :class:`Observable` into a list of :class:`DraftRule`
objects, each carrying a hand-serialized YAML Sigma rule.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Container, Iterable
from dataclasses import dataclass

from pipeline.detection.observables import Observable
from pipeline.detection.tlds import looks_like_domain

#: A "kind" = a telemetry type = one rule. logsource + Sigma field.
KIND_SPECS: dict[str, dict[str, str]] = {
    "dns_query": {
        "category": "dns_query",
        "field": "QueryName",
        "noun": "DNS query",
    },
    "proxy_url": {
        "category": "proxy",
        "field": "c-uri",
        "noun": "HTTP request",
    },
    "network_connection": {
        "category": "network_connection",
        "field": "DestinationIp",
        "noun": "network connection",
    },
    "process_hash": {
        "category": "process_creation",
        "field": "Hashes|contains",
        "noun": "process hash",
    },
    "process_image": {
        "category": "process_creation",
        "field": "Image|endswith",
        "noun": "process image",
    },
    "file_event": {
        "category": "file_event",
        "field": "TargetFilename|endswith",
        "noun": "file artefact",
    },
    "registry_set": {
        "category": "registry_set",
        "field": "TargetObject|contains",
        "noun": "registry value",
    },
}

#: Severity by kind. A hash is near-proof, a filename is not.
LEVEL_BY_KIND: dict[str, str] = {
    "process_hash": "high",
    "dns_query": "medium",
    "proxy_url": "medium",
    "network_connection": "medium",
    "process_image": "medium",
    "registry_set": "medium",
    "file_event": "low",
}

#: observable class -> kind. Missing classes produce NO rule
#: ("name", "user", "port", "cve"): a tool name is not a field value.
CLASS_TO_KIND: dict[str, str] = {
    "domain": "dns_query",
    "url": "proxy_url",
    "ip": "network_connection",
    "hash": "process_hash",
    "image": "process_image",
    "file": "file_event",
    "registry": "registry_set",
}

EXECUTABLE_SUFFIXES: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".msi", ".sh", ".elf", ".bin", ".py", ".jsp", ".war",
})

MAX_VALUES_PER_RULE: int = 50

#: Tactic tag per kind — emitted INSTEAD of the report's technique list.
#:
#: Stamping every generated rule with all of a report's techniques produced, on a
#: real report, a `file_event` rule tagged with 34 techniques including
#: `attack.t0866` (an ICS technique) and `attack.t1110.003` (password spraying).
#: An observable does not record which technique it served, so that tagging is
#: not merely noisy, it is wrong.
#:
#: An empty string means "not determinable" and emits NO `tags:` block: a dropped
#: file or a registry value could serve persistence, evasion or collection, and
#: Sigma does not require the field.  The report's techniques are still carried on
#: `DraftRule.techniques` for the UI, and counted in the description.
TACTIC_BY_KIND: dict[str, str] = {
    "dns_query": "attack.command_and_control",
    "proxy_url": "attack.command_and_control",
    "network_connection": "attack.command_and_control",
    "process_hash": "attack.execution",
    "process_image": "attack.execution",
    "file_event": "",
    "registry_set": "",
}

#: Fixed namespace for UUIDv5 — do NOT regenerate.
NAMESPACE_UUID = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
#: A Windows drive prefix, anchored — "c:/users/..." but not "/usr/bin:/bin".
_DRIVE_RE = re.compile(r"^[a-z]:/")


@dataclass(frozen=True, slots=True)
class DraftRule:
    kind: str
    title: str
    rule_id: str
    level: str
    logsource: dict[str, str]
    field: str
    values: tuple[str, ...]
    sources: tuple[str, ...]
    techniques: tuple[str, ...]
    yaml_text: str


def _escape_sigma(value: str) -> str:
    """Escape Sigma wildcards ``*`` and ``?`` (and backslashes)."""
    value = value.replace("\\", "\\\\")
    value = value.replace("*", "\\*")
    value = value.replace("?", "\\?")
    return value


def _to_windows_path(value: str) -> str:
    """Convert forward slashes to backslashes for Windows Sigma fields."""
    return value.replace("/", "\\")


def _hash_prefix(value: str) -> str:
    """Return the Sigma hash prefix for the given digest length."""
    length = len(value)
    if length == 32:
        return "MD5="
    if length == 40:
        return "SHA1="
    if length == 64:
        return "SHA256="
    if length == 128:
        return "SHA512="
    return ""


def _specific_enough(value: str) -> bool:
    """Would this path value produce a rule worth writing?

    `observables.py` emits a path's basename alongside its full path, so a report
    naming ``/etc/hosts`` also yields the bare token ``hosts``.  Keyed on that,
    ``TargetFilename|endswith: '/hosts'`` matches any file called hosts anywhere —
    technically valid, operationally worthless.

    A rooted path is always specific enough.  A bare basename must carry an
    extension or real length to earn a rule.
    """
    if "/" in value:
        return True
    return "." in value or len(value) >= 8


def _path_variants(value: str, platform: str) -> list[str]:
    """Field values for a path-shaped observable, with the right separator.

    `observables.py` normalises every path to forward slashes, so the separator
    has to be re-derived rather than trusted.  Converting unconditionally turned
    the real observable ``/etc/hosts`` into ``\\hosts`` — a Windows pattern
    matching any file called "hosts" on a Linux intrusion.

    Args:
        value: normalised observable value (lowercase, forward slashes).
        platform: report platform; "" or "multi" when undecided.

    Returns:
        One value for a rooted path, or — for a bare basename on an undecided
        platform — both separator forms, since the field is a YAML list anyway.
    """
    if value.startswith("/"):
        return [value]                       # POSIX absolute path: leave it alone
    if ":/" in value:
        return [_to_windows_path(value)]     # drive-letter path: Windows
    if "/" in value:
        return [_to_windows_path(value)] if platform == "windows" else [value]
    # Bare basename: `|endswith` needs a leading separator so "agent.exe" cannot
    # match "myagent.exe".  Which separator depends on an OS we may not know.
    if platform == "windows":
        return ["\\" + value]
    if platform in ("linux", "macos"):
        return ["/" + value]
    return ["\\" + value, "/" + value]


def _is_executable(value: str) -> bool:
    """Return True if *value* ends with a known executable suffix."""
    lower = value.lower()
    return any(lower.endswith(suffix) for suffix in EXECUTABLE_SUFFIXES)


def _eligible(obs: Observable, exclude_values: Container[str]) -> str | None:
    """Apply the ADR-0016 gates and return the retained kind, or None."""
    # Gate 1: class must be mapped.
    kind = CLASS_TO_KIND.get(obs.obs_class)
    if kind is None:
        return None

    # Gate 2: already covered by an existing rule.
    if obs.value in exclude_values:
        return None

    # Gate 3: domain must actually look like a domain.
    if obs.obs_class == "domain" and not looks_like_domain(obs.value):
        return None

    # Gate 4: class-specific checks.
    if obs.obs_class == "hash":
        if not _hash_prefix(obs.value):
            return None
    elif obs.obs_class == "ip":
        if not _IPV4_RE.match(obs.value):
            return None
        if any(int(octet) > 255 for octet in obs.value.split(".")):
            return None
    elif obs.obs_class == "file":
        if _is_executable(obs.value):
            return None
        # A colon outside a *drive prefix* means this is not a path.  The check
        # must be positional: "/usr/bin:/bin" — a real $PATH fragment from the
        # corpus — contains ":/" and slipped through a substring test, yielding
        # the field value "\usr\bin:\bin", a rule that can never fire.
        if ":" in obs.value and not _DRIVE_RE.match(obs.value):
            return None
        if not _specific_enough(obs.value):
            return None
    elif obs.obs_class == "image" and not _specific_enough(obs.value):
        return None
    elif obs.obs_class == "url":
        if len(obs.value) < 8:
            return None
    elif obs.obs_class == "registry":
        if len(obs.value) < 8:
            return None
    elif obs.obs_class == "image":
        if len(obs.value) < 5:
            return None

    return kind


def _group(
    observables: Iterable[Observable],
    exclude_values: Container[str],
) -> dict[str, list[Observable]]:
    """Group eligible observables by kind, deduplicating on value."""
    groups: dict[str, list[Observable]] = {}
    seen: dict[str, set[str]] = {}
    for obs in observables:
        if not isinstance(obs, Observable):
            continue
        kind = _eligible(obs, exclude_values)
        if kind is None:
            continue
        if kind not in groups:
            groups[kind] = []
            seen[kind] = set()
        if obs.value in seen[kind]:
            continue
        seen[kind].add(obs.value)
        groups[kind].append(obs)
    return groups


def _rule_uuid(job_id: str, kind: str) -> str:
    """Deterministic UUIDv5 for a (job_id, kind) pair."""
    return str(uuid.uuid5(NAMESPACE_UUID, f"{job_id}:{kind}"))


def _yaml_scalar(value: str) -> str:
    """Serialize a string as a single-quoted YAML scalar."""
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def _render_yaml(
    title: str,
    rule_id: str,
    description_lines: list[str],
    references: list[str],
    author: str,
    date: str,
    tags: list[str],
    logsource: dict[str, str],
    field: str,
    values: list[str],
    level: str,
) -> str:
    """Render the Sigma rule as a YAML string."""
    lines: list[str] = []
    # title/author/references are free text taken from the report filename, so
    # they must be quoted: an unquoted value containing ": " or a leading "*"
    # silently produces a different document — or no valid YAML at all.
    lines.append(f"title: {_yaml_scalar(title)}")
    lines.append(f"id: {rule_id}")
    lines.append("status: experimental")
    lines.append("description: |")
    for line in description_lines:
        # A literal block keeps ':' and '#' safe, but an embedded newline would
        # break the indentation and end the block early.
        lines.append(f"    {line.replace(chr(10), ' ').replace(chr(13), ' ')}")
    if references:
        lines.append("references:")
        for ref in references:
            lines.append(f"    - {_yaml_scalar(ref)}")
    lines.append(f"author: {_yaml_scalar(author)}")
    lines.append(f"date: {date}")
    if tags:
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")
    lines.append("logsource:")
    for key, value in logsource.items():
        lines.append(f"    {key}: {value}")
    lines.append("detection:")
    lines.append("    selection:")
    lines.append(f"        {field}:")
    for value in values:
        lines.append(f"            - {_yaml_scalar(value)}")
    lines.append("    condition: selection")
    lines.append("falsepositives:")
    lines.append("    - Unknown")
    lines.append(f"level: {level}")
    return "\n".join(lines) + "\n"


def synthesize_sigma(
    observables: Iterable[Observable],
    *,
    job_id: str,
    report_title: str = "",
    techniques: Iterable[str] = (),
    platform: str = "",
    date: str = "1970-01-01",
    exclude_values: Container[str] = frozenset(),
    max_values_per_rule: int = MAX_VALUES_PER_RULE,
) -> list[DraftRule]:
    """Generate draft Sigma rules from CTI report observables.

    Args:
        observables: Iterable of :class:`Observable` from the report.
        job_id: Unique identifier of the report/job.
        report_title: Human-readable title of the report.
        techniques: MITRE ATT&CK technique IDs (e.g. ``"T1059.001"``).
        platform: Target platform (``"windows"``, ``"linux"``, ``"macos"``,
            ``"multi"``, or ``""``).
        date: ISO date string for the rule.
        exclude_values: Values already covered by existing rules.
        max_values_per_rule: Maximum number of values per rule.

    Returns:
        A list of :class:`DraftRule` objects, one per kind present.
    """
    if observables is None:
        return []

    groups = _group(observables, exclude_values)

    # Materialise once, before the per-kind loop.  `techniques` is typed Iterable,
    # so a generator would be drained by the first rule and leave every later rule
    # untagged.  Computing the tags here also keeps them off the hot path.
    tech_tuple = tuple(techniques)

    rules: list[DraftRule] = []
    for kind in KIND_SPECS:
        if kind not in groups:
            continue
        spec = KIND_SPECS[kind]
        obs_list = groups[kind]

        # Build field values.
        raw_values: list[str] = []
        for obs in obs_list:
            v = obs.value
            if kind == "process_hash":
                raw_values.append(_hash_prefix(v) + v)
            elif kind in ("process_image", "file_event"):
                raw_values.extend(_escape_sigma(p) for p in _path_variants(v, platform))
            elif kind == "registry_set":
                raw_values.append(_escape_sigma(_to_windows_path(v)))
            else:
                raw_values.append(_escape_sigma(v))

        # Deduplicate preserving order, then truncate.
        seen: set[str] = set()
        deduped: list[str] = []
        for val in raw_values:
            if val not in seen:
                seen.add(val)
                deduped.append(val)
        values = deduped[:max_values_per_rule]

        if not values:
            continue

        # Truncate the *report name*, not the finished title — slicing the whole
        # string cut the closing parenthesis off and left a ragged title.
        label = (report_title or job_id).rsplit("/", 1)[-1]
        for suffix in (".pdf", ".html", ".htm", ".txt"):
            if label.lower().endswith(suffix):
                label = label[: -len(suffix)]
                break
        if len(label) > 60:
            label = label[:57].rstrip() + "..."
        title = f"Report IoC — {spec['noun']} ({label})"
        level = LEVEL_BY_KIND[kind]
        rule_id = _rule_uuid(job_id, kind)

        logsource: dict[str, str] = {"category": spec["category"]}
        if platform in ("windows", "linux", "macos"):
            logsource["product"] = platform

        sources = tuple(obs.display for obs in obs_list)

        # Description lines.
        desc_line1 = f"Generated from CTI report observables ({spec['noun']})."
        if len(sources) <= 8:
            desc_line2 = f"Source observables: {', '.join(sources)}"
        else:
            desc_line2 = f"Source observables: {', '.join(sources[:8])}..."
        description_lines = [desc_line1, desc_line2]
        if tech_tuple:
            # Recorded, not tagged: which of the report's techniques this
            # observable served is not knowable from the observable.
            description_lines.append(
                f"Report techniques ({len(tech_tuple)}): "
                f"{', '.join(sorted(tech_tuple)[:6])}"
                f"{'...' if len(tech_tuple) > 6 else ''}"
            )

        tactic = TACTIC_BY_KIND.get(kind, "")
        tags = [tactic] if tactic else []

        references: list[str] = []
        if report_title:
            references.append(report_title)

        author = f"CTIParsor (generated from report {job_id})"

        yaml_text = _render_yaml(
            title=title,
            rule_id=rule_id,
            description_lines=description_lines,
            references=references,
            author=author,
            date=date,
            tags=tags,
            logsource=logsource,
            field=spec["field"],
            values=values,
            level=level,
        )

        rules.append(
            DraftRule(
                kind=kind,
                title=title,
                rule_id=rule_id,
                level=level,
                logsource=logsource,
                field=spec["field"],
                values=tuple(values),
                sources=sources,
                techniques=tech_tuple,
                yaml_text=yaml_text,
            )
        )

    return rules
