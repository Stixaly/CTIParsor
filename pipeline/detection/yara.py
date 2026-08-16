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

_YARA_GLOBS = ("*.yar", "*.yara", "*.rule")

#: Clés de `meta` susceptibles de porter une technique ATT&CK. YARA n'a pas de
#: champ standard ; mesuré, la grande majorité des règles n'en portent aucune.
_TECHNIQUE_META_KEYS = frozenset({
    "attack", "mitre", "mitre_att", "mitre_attack", "mitre_technique",
    "att&ck", "technique", "techniques",
})

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


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
        strings = [(kind, value) for _ident, kind, value in rule.strings]
        if not strings:
            return ""
        strings.sort()
        payload = json.dumps(
            {"format": "yara", "strings": strings},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()
