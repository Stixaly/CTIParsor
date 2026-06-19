"""SigmaAdapter — parse SigmaHQ-format YAML rules (https://sigmahq.io).

Sigma is the only format implemented today (ADR-0006 Rev 1).  Parsing is plain
PyYAML + field extraction — pySigma is only needed for *converting* rules to a
SIEM backend, which is out of scope for ingestion/coverage.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path

import yaml

from models.detection import DetectionRule, Severity
from pipeline.detection.base import RuleCorpusAdapter

# Sigma technique tag → ATT&CK technique id, e.g. "attack.t1059.001" → "T1059.001"
_TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
# attack.g0016 (group) / attack.s0002 (software) tags — not tactics
_GROUP_SOFTWARE_RE = re.compile(r"^[gs]\d{4}$", re.IGNORECASE)

_LEVEL_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SIGMA_GLOBS = ("*.yml", "*.yaml")


class SigmaAdapter(RuleCorpusAdapter):
    format = "sigma"

    def parse(
        self,
        root: Path,
        *,
        corpus: str,
        license: str = "unknown",
    ) -> Iterable[DetectionRule]:
        root = Path(root)
        for path in self._iter_rule_files(root):
            try:
                text = path.read_text(encoding="utf-8")
                docs = list(yaml.safe_load_all(text))
            except (OSError, yaml.YAMLError):
                continue  # unreadable / malformed file — skip, don't crash the build
            for doc in docs:
                rule = self._to_rule(doc, text, path, corpus, license)
                if rule is not None:
                    yield rule

    @staticmethod
    def _iter_rule_files(root: Path) -> Iterable[Path]:
        for pattern in _SIGMA_GLOBS:
            yield from root.rglob(pattern)

    @staticmethod
    def _to_rule(
        doc: object,
        text: str,
        path: Path,
        corpus: str,
        license: str,
    ) -> DetectionRule | None:
        # A Sigma rule is a mapping with at least a title and a detection block.
        if not isinstance(doc, dict) or "title" not in doc or "detection" not in doc:
            return None

        techniques, tactics = SigmaAdapter._split_tags(doc.get("tags") or [])

        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        native_id = str(doc.get("id") or "").strip()
        rule_key = native_id or content_hash[:16]

        ls = doc.get("logsource") or {}
        data_sources = [
            v for v in (ls.get("category"), ls.get("product"), ls.get("service"))
            if isinstance(v, str) and v
        ]

        level = str(doc.get("level") or "").lower().strip()

        return DetectionRule(
            id=f"{corpus}:{rule_key}",
            corpus=corpus,
            format="sigma",
            title=str(doc["title"]).strip(),
            description=str(doc.get("description") or "").strip(),
            technique_ids=techniques,
            tactic_shortnames=tactics,
            data_sources=data_sources,
            severity=_LEVEL_MAP.get(level, Severity.UNKNOWN),
            license=license,
            source_ref=str(path),
            content_hash=content_hash,
            raw=text,
        )

    @staticmethod
    def _split_tags(tags: list) -> tuple[list[str], list[str]]:
        techniques: list[str] = []
        tactics: list[str] = []
        for tag in tags:
            if not isinstance(tag, str):
                continue
            tag = tag.strip()
            m = _TECHNIQUE_RE.match(tag)
            if m:
                techniques.append("T" + m.group(1).upper())
            elif tag.lower().startswith("attack."):
                short = tag.split(".", 1)[1].strip().lower()
                if short and not _GROUP_SOFTWARE_RE.match(short):
                    tactics.append(short)
        # dedup, preserve first-seen order
        return list(dict.fromkeys(techniques)), list(dict.fromkeys(tactics))
