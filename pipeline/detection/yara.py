from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from models.detection import DetectionRule, Severity
from pipeline.detection.base import RuleCorpusAdapter
from pipeline.detection.yara_atoms import (
    YaraRule,
    extract_atoms,
    rule_platform,
    split_rules,
)
from pipeline.regex_safety import compile_pattern

_YARA_GLOBS = ("*.yar", "*.yara", "*.rule")

#: Clés de `meta` susceptibles de porter une technique ATT&CK. YARA n'a pas de
#: champ standard ; mesuré, la grande majorité des règles n'en portent aucune.
_TECHNIQUE_META_KEYS = frozenset({
    "attack", "mitre", "mitre_att", "mitre_attack", "mitre_technique",
    "att&ck", "technique", "techniques",
})

# re.ASCII: `re` reads `\b` as RE2 does (ADR-0049, 2026-10-18).
_TECHNIQUE_RE = compile_pattern(r"\bT[0-9]{4}(?:\.[0-9]{3})?\b", re.IGNORECASE | re.ASCII)


class YaraAdapter(RuleCorpusAdapter):
    """Adapter for YARA rule corpora (ADR-0015 §1).

    Parses `.yar`, `.yara`, and `.rule` files and yields `DetectionRule` objects.
    Private rules are ignored because they are auxiliary predicates that cannot
    trigger independently; counting them would distort coverage metrics.
    """

    format = "yara"

    def parse(
        self,
        root: Path,
        *,
        corpus: str,
        license: str = "unknown",
    ) -> Iterable[DetectionRule]:
        """Parse a YARA corpus directory.

        Args:
            root: Root directory containing YARA rule files.
            corpus: Corpus identifier for rule IDs.
            license: License string for the corpus.

        Returns:
            Iterable of `DetectionRule` objects.
        """
        root = Path(root)
        for pattern in _YARA_GLOBS:
            for path in root.rglob(pattern):
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for rule in split_rules(text):
                    if rule.is_private:
                        continue
                    r = self._to_rule(rule, path, corpus, license)
                    if r is not None:
                        yield r

    def _to_rule(
        self,
        rule: YaraRule,
        path: Path,
        corpus: str,
        license: str,
    ) -> DetectionRule | None:
        if not rule.name:
            return None

        content_hash = hashlib.sha256(rule.body.encode()).hexdigest()
        # The rule body is the key, NOT `meta.id`. YARA has no uniqueness rule for
        # it and corpora reuse it across a family: in signature-base, the eleven
        # distinct rules APT30_Sample_10..19 all declare the same `id`, and 57 such
        # groups exist. Keying on it made them collide on `detection_rules.id`,
        # where `INSERT OR REPLACE` would keep one and silently drop the rest.
        # Logical identity is `dedup_key`'s job (ADR-0010/0017); the native key
        # only has to be unique and stable, which the content hash is by
        # construction. The upstream id stays visible in `raw`.
        native_key = content_hash[:16]

        title = rule.name
        description = rule.meta.get("description", "")
        atoms = extract_atoms(rule)
        technique_ids = self._techniques(rule)
        platform = rule_platform(rule)
        data_sources = ["file"]
        severity = Severity.UNKNOWN

        return DetectionRule(
            id=f"{corpus}:{native_key}",
            corpus=corpus,
            format="yara",
            title=title,
            description=description,
            technique_ids=technique_ids,
            tactic_shortnames=[],
            data_sources=data_sources,
            platform=platform,
            atoms=atoms,
            severity=severity,
            license=license,
            source_ref=str(path),
            content_hash=content_hash,
            dedup_key=self._dedup_key(rule) or content_hash,
            related=[],
            raw=rule.body,
        )

    def _techniques(self, rule: YaraRule) -> list[str]:
        result: list[str] = []
        seen: set[str] = set()
        for key, value in rule.meta.items():
            if key.lower() not in _TECHNIQUE_META_KEYS:
                continue
            if not isinstance(value, str):
                continue
            for match in _TECHNIQUE_RE.findall(value):
                upper = match.upper()
                if upper not in seen:
                    seen.add(upper)
                    result.append(upper)
        return result

    def _dedup_key(self, rule: YaraRule) -> str:
        if not rule.strings:
            return ""
        strings = _normalized_strings(rule.body)
        if not strings:
            return ""
        # The condition is part of the rule's semantics: two rules with the
        # same strings but different conditions ("$a and $b" vs "$a or $b")
        # are NOT duplicates and must not be folded into one.
        m = _CONDITION_RE.search(rule.body)
        if m:
            cond = " ".join(rule.body[m.end():].split())
        else:
            ci = rule.body.find("condition:")
            cond = " ".join(rule.body[ci + len("condition:"):].split()) if ci >= 0 else ""
        payload = json.dumps(
            {"format": "yara", "strings": strings, "condition": cond},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


_STRINGS_RE = compile_pattern(r"(?m)^[ \t]*strings[ \t]*:")
_CONDITION_RE = compile_pattern(r"(?m)^[ \t]*condition[ \t]*:")
_DECL_RE = compile_pattern(r"^[ \t]*(\$[A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$")


def _literal_end(rest: str) -> int:
    """Index just past the string literal opening `rest` (quote, hex or regex)."""
    closer = {'"': '"', "{": "}", "/": "/"}.get(rest[:1])
    if closer is None:
        return 0
    k = 1
    while k < len(rest):
        if rest[k] == "\\" and closer != "}":
            k += 2
            continue
        if rest[k] == closer:
            return k + 1
        k += 1
    return len(rest)


def _normalized_strings(body: str) -> list[str]:
    """The `strings:` declarations of a rule: identifier, value AND modifiers.

    Spacing is normalized outside the literal and the list is sorted, so a
    reordering or a re-indentation does not change the result, while `$a = "x"`
    and `$a = "x" nocase wide` (or `/x/` and `/x/i`) stay distinct.
    """
    m = _STRINGS_RE.search(body)
    if not m:
        return []
    section = body[m.end():]
    end = _CONDITION_RE.search(section)
    if end:
        section = section[:end.start()]
    out: list[str] = []
    for line in section.splitlines():
        if line.strip().startswith("//"):
            continue          # a comment line is not part of the rule's logic
        d = _DECL_RE.match(line)
        if not d:
            # A hex string (or a long literal) can run over several lines: the
            # continuation belongs to the declaration above, or two rules that
            # differ only past the first line would share a key.
            if out and line.strip():
                out[-1] = f"{out[-1]} {' '.join(line.split())}"
            continue
        rest = d.group(2)
        cut = _literal_end(rest)
        # The tail is outside the literal: a `//` there starts a comment.
        head, tail = rest[:cut], " ".join(rest[cut:].split("//", 1)[0].split())
        if head.startswith("{"):
            head = " ".join(head.split())
        out.append(f"{d.group(1)} = {head} {tail}".strip())
    out.sort()
    return out
