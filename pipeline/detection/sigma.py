"""SigmaAdapter — parse SigmaHQ-format YAML rules (https://sigmahq.io).

Sigma is the only format implemented today (ADR-0006 Rev 1).  Parsing is plain
PyYAML + field extraction — pySigma is only needed for *converting* rules to a
SIEM backend, which is out of scope for ingestion/coverage.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from pathlib import Path

import yaml

from api.logging_config import get_logger
from models.detection import DetectionRule, Severity
from pipeline.detection.atoms import extract_atoms, rule_platform
from pipeline.detection.base import RuleCorpusAdapter
from pipeline.regex_safety import compile_pattern

logger = get_logger(__name__)

# Sigma technique tag → ATT&CK technique id, e.g. "attack.t1059.001" → "T1059.001"
_TECHNIQUE_RE = compile_pattern(r"^attack\.t([0-9]{4}(?:\.[0-9]{3})?)$", re.IGNORECASE)
# attack.g0016 (group) / attack.s0002 (software) tags — not tactics
_GROUP_SOFTWARE_RE = compile_pattern(r"^[gs][0-9]{4}$", re.IGNORECASE)
# attack.ta0001 — a tactic *ID*.  tactic_shortnames holds kill-chain shortnames
# like "defense_evasion", so the numeric ID form is skipped to avoid mixing the
# two representations in one list.
_TACTIC_ID_RE = compile_pattern(r"^ta[0-9]{4}$", re.IGNORECASE)
# `|re` and `|cased` make the case of a value part of the match (see _canonicalize).
_CASE_SENSITIVE_MODIFIERS = frozenset({"re", "cased"})

_LEVEL_MAP = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_SIGMA_GLOBS = ("*.yml", "*.yaml")


def _case_sensitive_key(key: object) -> bool:
    """True when a field key such as `CommandLine|re` carries a case-sensitive modifier.
    `|re|i` is a case-insensitive regex, so it folds like a plain value."""
    modifiers = str(key).strip().lower().split("|")[1:]
    if "i" in modifiers and "cased" not in modifiers:
        return False
    return not _CASE_SENSITIVE_MODIFIERS.isdisjoint(modifiers)


def _one_line(error: Exception) -> str:
    """A parser error on one line: PyYAML's message spans several (marks and snippet)."""
    return " ".join(str(error).split())


def _file_error(path: Path, message: str, on_file_error: Callable[[Path, str], None] | None) -> None:
    """Warn about a file that was skipped or partly read, and tell the caller (#373)."""
    logger.warning(f"[detection] sigma file {path} {message}")
    if on_file_error is not None:
        on_file_error(path, message)


class SigmaAdapter(RuleCorpusAdapter):
    format = "sigma"

    def parse(
        self,
        root: Path,
        *,
        corpus: str,
        license: str = "unknown",
        on_file_error: Callable[[Path, str], None] | None = None,
    ) -> Iterable[DetectionRule]:
        """Yield the rules of every Sigma file under `root`.

        A file that cannot be read, is not UTF-8 or is not YAML is reported with a
        warning and through `on_file_error(path, message)` (#373). A YAML error stops
        the reading of that file only: the documents before it are kept. So does an
        invalid date (`date: 2024-13-45`, a ValueError from PyYAML) or a nesting too
        deep for the parser (a RecursionError).

        `_to_rule` receives the rank of each rule among the rules of its file: 0 for
        the first rule produced, then 1, 2… Non-rule documents (a `action: global`
        collection, say) do not count, so they do not shift the ids (#375). Two rules
        without an `id` in the same file still get distinct ids.
        """
        root = Path(root)
        for path in self._iter_rule_files(root):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError as e:
                # Not UTF-8 (a stray 0xff, or UTF-16 with a BOM): skipped, never decoded (#372).
                _file_error(path, f"not UTF-8, skipped: {e}", on_file_error)
                continue
            except OSError as e:
                _file_error(path, f"unreadable, skipped: {e}", on_file_error)  # don't crash the build
                continue
            documents = yaml.safe_load_all(text)
            rank = 0
            while True:
                try:
                    doc = next(documents)
                except StopIteration:
                    break
                except (yaml.YAMLError, ValueError, RecursionError) as e:
                    # The rules read before this one are already yielded; the rest of the file is lost (#373).
                    _file_error(path, f"YAML error, partially imported: {_one_line(e)}", on_file_error)
                    break
                try:
                    rule = self._to_rule(doc, text, path, corpus, license, rank)
                except Exception as e:  # noqa: BLE001 — one bad document must not stop the corpus
                    logger.warning(f"[detection] sigma document in {path} skipped: {e}")
                    continue
                if rule is not None:
                    yield rule
                    rank += 1

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
        index: int = 0,
    ) -> DetectionRule | None:
        """Build the rule of one YAML document of `text`, or None when it is not a rule.

        `index` is the rank of the rule among the rules of its file (0 for the first
        rule produced, 1 for the next one…); `parse` counts only the documents that
        return a rule, so a non-rule document before it does not change its id. It
        only matters for a document without a native `id`: index 0 keeps the file's
        `content_hash[:16]` as its key, so single-document files and first rules keep
        their ids; later ones hash their rank in the file. Two rules without an `id`
        in one file used to share the file's hash and so one storage id (#375).

        Known limit: `raw` and `content_hash` stay those of the whole file, so every
        rule of a multi-document file carries the same body (Sigma `action: global`
        collections need it). `dedup_key` is computed from the document alone.
        """
        # A Sigma rule is a mapping with at least a title and a detection block.
        if not isinstance(doc, dict) or "title" not in doc or "detection" not in doc:
            return None

        techniques, tactics = SigmaAdapter._split_tags(doc.get("tags") or [])

        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        native_id = str(doc.get("id") or "").strip()
        # #375: the file hash is shared by every document of the file, so a later
        # document without an `id` would take the same storage id as the first one and
        # replace it in the store. Its position in the file makes its key distinct.
        if native_id:
            rule_key = native_id
        elif index == 0:
            rule_key = content_hash[:16]
        else:
            rule_key = hashlib.sha256(f"{content_hash}:{index}".encode("utf-8")).hexdigest()[:16]
        dedup_key = SigmaAdapter._dedup_key(doc) or content_hash

        ls = doc.get("logsource") or {}
        if not isinstance(ls, dict):
            ls = {}
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
            platform=rule_platform(doc),
            atoms=extract_atoms(doc),
            severity=_LEVEL_MAP.get(level, Severity.UNKNOWN),
            related=SigmaAdapter._split_related(doc.get("related")),
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
                             sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _canonicalize(node: object, keep_case: bool = False) -> object:
        """Order-insensitive, case-folded normal form of a detection sub-tree.

        Sigma string matching is case-insensitive by default, and selection /
        list order is not semantically meaningful — so we lowercase scalars and
        keys and sort lists, making formatting-only differences hash-identical.
        Values under a `|re` or `|cased` key keep their case: there it is part
        of the match, so `Foo.*bar` and `foo.*bar` are different rules.
        """
        if isinstance(node, dict):
            return {str(k).strip().lower(): SigmaAdapter._canonicalize(
                        v, keep_case or _case_sensitive_key(k))
                    for k, v in sorted(node.items(), key=lambda kv: str(kv[0]).lower())}
        if isinstance(node, list):
            items = [SigmaAdapter._canonicalize(v, keep_case) for v in node]
            return sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str))
        if isinstance(node, str):
            return node.strip() if keep_case else node.strip().lower()
        return node

    @staticmethod
    def _split_related(related: object) -> list[tuple[str, str]]:
        """Normalize a rule's `related:` block into (id, type) pairs (ADR-0017).

        Args:
            related: raw value of the `related` key. Expected to be a list of
                dicts, but may be None, a dict, a str — third-party YAML.

        Returns:
            (bare_rule_id, type) pairs, deduplicated on the full pair, in
            first-seen order.  The type is normalized but *not* filtered here:
            which relations fold is the dedup pass's decision, not the adapter's,
            so `similar` and `obsolete` are carried through and dropped later.
        """
        if not isinstance(related, list):
            return []

        seen: set[tuple[str, str]] = set()
        result: list[tuple[str, str]] = []
        for element in related:
            if not isinstance(element, dict):
                continue
            rid = element.get("id")
            if not isinstance(rid, str) or not rid.strip():
                continue
            rtype = element.get("type")
            rtype = rtype.strip().lower() if isinstance(rtype, str) else ""
            pair = (rid.strip(), rtype)
            if pair not in seen:
                seen.add(pair)
                result.append(pair)
        return result

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
