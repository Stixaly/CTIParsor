"""SigmaAdapter — parse SigmaHQ-format YAML rules (https://sigmahq.io).

Sigma is the only format implemented today (ADR-0006 Rev 1).  Parsing is plain
PyYAML + field extraction — pySigma is only needed for *converting* rules to a
SIEM backend, which is out of scope for ingestion/coverage.
"""
from __future__ import annotations

import hashlib
import json
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
# attack.ta0001 — a tactic *ID*.  tactic_shortnames holds kill-chain shortnames
# like "defense_evasion", so the numeric ID form is skipped to avoid mixing the
# two representations in one list.
_TACTIC_ID_RE = re.compile(r"^ta\d{4}$", re.IGNORECASE)

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
        dedup_key = SigmaAdapter._dedup_key(doc) or content_hash

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
            dedup_key=dedup_key,
            raw=text,
        )

    @staticmethod
    def _dedup_key(doc: dict) -> str:
        """Stable hash of a rule's *detection logic* (logsource + detection block).

        Two rules collapse to one logical rule iff they would match the same
        events — so volatile metadata (title, author, date, references, id) is
        excluded. Used by the ADR-0010 dedup pass to fold copies/conversions
        (e.g. hayabusa's converted SigmaHQ rules) across corpora *without*
        collapsing genuinely-independent rules that happen to share a technique.

        Returns "" when there's no usable detection logic — the caller then
        falls back to the content hash so such rules never all cluster together.
        """
        ls = doc.get("logsource") or {}
        logsource = {
            k: str(ls[k]).strip().lower()
            for k in ("category", "product", "service")
            if isinstance(ls, dict) and ls.get(k)
        }
        detection = SigmaAdapter._canonicalize(doc.get("detection"))
        if not detection:
            return ""
        payload = json.dumps({"logsource": logsource, "detection": detection},
                             sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonicalize(node: object) -> object:
        """Order-insensitive, case-folded normal form of a detection sub-tree.

        Sigma string matching is case-insensitive by default, and selection /
        list order is not semantically meaningful — so we lowercase scalars and
        keys and sort lists, making formatting-only differences hash-identical.
        """
        if isinstance(node, dict):
            return {str(k).strip().lower(): SigmaAdapter._canonicalize(v)
                    for k, v in sorted(node.items(), key=lambda kv: str(kv[0]).lower())}
        if isinstance(node, list):
            items = [SigmaAdapter._canonicalize(v) for v in node]
            return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
        if isinstance(node, str):
            return node.strip().lower()
        return node

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
                if (short
                        and not _GROUP_SOFTWARE_RE.match(short)
                        and not _TACTIC_ID_RE.match(short)):
                    tactics.append(short)
        # dedup, preserve first-seen order
        return list(dict.fromkeys(techniques)), list(dict.fromkeys(tactics))
