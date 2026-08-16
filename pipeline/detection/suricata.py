from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

from models.detection import DetectionRule, Severity
from pipeline.detection.base import RuleCorpusAdapter
from pipeline.detection.suricata_atoms import (
    extract_atoms,
    parse_options,
    rule_header,
    rule_metadata,
    technique_ids,
)

_SURICATA_GLOBS = ("*.rules",)

#: `metadata: signature_severity <V>` -> Severity.
#: Mesuré sur ET Open 7.0.3 (règles actives) : Major 29234, Informational 13560,
#: Critical 5279, Minor 3576, Unknown 150.
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "major": Severity.HIGH,
    "minor": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}

#: Options exclues du dedup_key : elles changent sans que la détection change.
#: `sid`/`rev` sont l'identité et la version, `msg`/`reference`/`metadata` sont
#: de la documentation, `classtype` est une étiquette.
_VOLATILE_OPTIONS = frozenset({"sid", "rev", "msg", "reference", "metadata", "classtype", "target"})

#: Une règle commence par une de ces actions.
_ACTIONS = ("alert", "drop", "reject", "pass", "log")

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


class SuricataAdapter(RuleCorpusAdapter):
    """Adapter for Suricata rule corpora (ADR-0015 §1).

    Parses `.rules` files and yields `DetectionRule` objects.
    Commented-out rules (lines starting with `#`) are ignored because
    ET Open ships ~19,479 disabled rules; ingesting them would inflate
    the detection count by 38%.
    """

    format = "suricata"

    def parse(
        self,
        root: Path,
        *,
        corpus: str,
        license: str = "unknown",
    ) -> Iterable[DetectionRule]:
        """Parse a Suricata corpus directory.

        Args:
            root: Root directory containing `.rules` files.
            corpus: Corpus identifier for rule IDs.
            license: License string for the corpus.

        Returns:
            Iterable of `DetectionRule` objects.
        """
        root = Path(root)
        for pattern in _SURICATA_GLOBS:
            for path in root.rglob(pattern):
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if not s:
                        continue
                    if s.startswith("#"):
                        continue
                    if s.split(None, 1)[0].lower() not in _ACTIONS:
                        continue
                    rule = self._to_rule(s, path, lineno, corpus, license)
                    if rule is not None:
                        yield rule

    def _to_rule(
        self,
        line: str,
        path: Path,
        lineno: int,
        corpus: str,
        license: str,
    ) -> DetectionRule | None:
        header = rule_header(line)
        if not header:
            return None

        # Extract body between first '(' and last ')'
        first_open = line.find("(")
        last_close = line.rfind(")")
        if first_open == -1 or last_close == -1 or last_close <= first_open:
            return None
        body = line[first_open + 1 : last_close]

        opts = dict(parse_options(body))
        sid = opts.get("sid", "").strip()
        msg = opts.get("msg", "").strip()
        # Strip surrounding quotes from msg
        if len(msg) >= 2 and msg[0] == '"' and msg[-1] == '"':
            msg = msg[1:-1]
        title = msg if msg else (f"suricata sid {sid}" if sid else f"suricata rule {lineno}")

        content_hash = hashlib.sha256(line.encode()).hexdigest()
        native_key = sid if sid.isdigit() else content_hash[:16]

        atoms = extract_atoms(line)
        header_atoms = self._header_atoms(header)
        seen: set[tuple[str, str]] = set()
        for a in atoms:
            if a not in seen:
                seen.add(a)
        for a in header_atoms:
            if a not in seen:
                seen.add(a)
                atoms.append(a)

        techs = technique_ids(line)
        data_sources = [header["proto"]] if header.get("proto") else []
        severity = self._severity(line)
        description = opts.get("metadata", "")

        return DetectionRule(
            id=f"{corpus}:{native_key}",
            corpus=corpus,
            format="suricata",
            title=title,
            description=description,
            technique_ids=techs,
            tactic_shortnames=[],
            data_sources=data_sources,
            platform="",
            atoms=atoms,
            severity=severity,
            license=license,
            source_ref=f"{path}:{lineno}",
            content_hash=content_hash,
            dedup_key=self._dedup_key(body, header) or content_hash,
            related=[],
            raw=line,
        )

    def _header_atoms(self, header: dict[str, str], *, max_ips: int = 64) -> list[tuple[str, str]]:
        """IP/port atoms from the rule header, including bracketed address lists.

        ET Open ships its blocklists as one rule per group with the addresses in a
        bracketed header list — `alert tcp [1.2.3.4,5.6.7.8,…] any -> …`. Skipping
        anything containing "[" (the obvious reading of "not a literal") threw away
        exactly the C2 and Tor exit-node addresses this index exists to match: the
        854 `ET TOR Known Tor Exit Node Traffic` rules yielded zero atoms each.

        Capped at *max_ips* per field — a single group can list hundreds, and one
        rule must not dominate the atom index (the same reasoning as
        `extract_atoms`' own cap).
        """
        result: list[tuple[str, str]] = []
        for key in ("src_ip", "dst_ip", "src_port", "dst_port"):
            val = header.get(key, "")
            if not val or val == "any" or val.startswith("$") or "!" in val:
                continue
            # A bracketed list is a set of literals, not a variable: unpack it.
            parts = [p.strip() for p in val.strip("[]").split(",")] if "[" in val else [val]
            kept = 0
            for part in parts:
                if kept >= max_ips:
                    break
                if not part or part.startswith("$") or "/" in part:   # skip vars and CIDR
                    continue
                if key in ("src_ip", "dst_ip"):
                    if _IP_RE.match(part) and all(0 <= int(o) <= 255 for o in part.split(".")):
                        result.append(("ip", part))
                        kept += 1
                elif part.isdigit() and 1 <= int(part) <= 65535:
                    result.append(("port", part))
                    kept += 1
        return result

    def _severity(self, line: str) -> Severity:
        meta = rule_metadata(line)
        sev = meta.get("signature_severity", "").lower()
        return _SEVERITY_MAP.get(sev, Severity.UNKNOWN)

    def _dedup_key(self, body: str, header: dict[str, str] | None = None) -> str:
        """Hash of the rule's detection logic — options AND header.

        The header is part of the logic, not metadata. ET Open's blocklists share
        one option body across hundreds of rules and differ *only* in their header
        address list, so hashing the options alone collapsed the 854
        `ET TOR Known Tor Exit Node Traffic` rules into a single cluster — ADR-0017
        would then have kept one and demoted 853, discarding thousands of distinct
        exit-node addresses.

        Option order is preserved (unlike Sigma's sorted form): it is semantic
        here, since a sticky buffer applies to the `content` matches that follow it.
        """
        opts = parse_options(body)
        filtered = [(k.lower(), v) for k, v in opts if k not in _VOLATILE_OPTIONS]
        if not filtered:
            return ""
        scope = {
            k: (header or {}).get(k, "")
            for k in ("proto", "src_ip", "src_port", "direction", "dst_ip", "dst_port")
        }
        payload = json.dumps(
            {"format": "suricata", "header": scope, "opts": filtered},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()
