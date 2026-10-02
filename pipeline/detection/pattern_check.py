"""
A Sigma, Suricata or Snort rule quoted in a report ships only if the parser
OpenCTI uses for its ``pattern_type`` accepts it (ADR-0070, extending ADR-0067
from YARA to the three other formats Stage 4 quotes).

OpenCTI checks every Indicator with ``check_indicator.py`` and refuses the ones
whose parser raises: Sigma with ``SigmaCollection.from_yaml`` (pysigma),
Suricata with ``parsuricata.parse_rules``, Snort with its own parser
(`pipeline.detection.opencti_snort`).  A refused Indicator takes every edge to
it down with it on import.

Measured (ADR-0070): corpus rules quoted in clean text all pass, but a rule
quoted through a PDF layout that wraps long lines reaches Stage 4 truncated.
All 20 such Suricata rules and 14 of 110 such Sigma rules were refused. A
Suricata rule quoted near the word "Snort" was typed ``snort``, and OpenCTI's
Snort parser refuses Suricata's application-layer protocols (``http``, ``dns``,
``tls``...): 1,833 of 2,000 ET Open rules.

Without the parser installed the status is ``unverified``, never ``accepted``.
"""
from __future__ import annotations

from collections.abc import Callable

from api.logging_config import get_logger

logger = get_logger(__name__)

ACCEPTED = "accepted"
REFUSED = "refused"
UNVERIFIED = "unverified"

# OpenCTI's Snort parser is quadratic on a line with no ";)" (0.14 s at 32,000
# characters).  A real rule is a few hundred; the bound keeps a hostile report
# from turning one line into minutes.
_MAX_NET_RULE = 16384

_warned: set[str] = set()


def _sigma(pattern: str) -> None:
    from sigma.collection import SigmaCollection
    SigmaCollection.from_yaml(pattern)


def _suricata(pattern: str) -> None:
    from parsuricata import parse_rules
    parse_rules(pattern)


def _snort(pattern: str) -> None:
    from pipeline.detection.opencti_snort import Parser
    Parser(pattern)


_CHECKERS: dict[str, tuple[str, Callable[[str], None]]] = {
    "sigma": ("pysigma", _sigma),
    "suricata": ("parsuricata", _suricata),
    "snort": ("OpenCTI's Snort parser", _snort),
}


def check_pattern(pattern_type: str, pattern: str) -> tuple[str, str | None]:
    """(status, the parser's message when it refused) for one quoted rule."""
    library, parse = _CHECKERS[pattern_type]
    if pattern_type in ("suricata", "snort") and len(pattern) > _MAX_NET_RULE:
        return REFUSED, f"longer than {_MAX_NET_RULE} characters"
    try:
        parse(pattern)
    except ImportError:
        if library not in _warned:
            _warned.add(library)
            logger.warning(f"{library} is not installed: {pattern_type} rules quoted in "
                           "reports ship without a check, and OpenCTI may refuse them")
        return UNVERIFIED, None
    except Exception as exc:  # noqa: BLE001 — OpenCTI refuses on any exception
        return REFUSED, f"{type(exc).__name__}: {exc}".strip()[:500]
    return ACCEPTED, None


def net_rule_dialect(typed: str, pattern: str) -> tuple[str, str, str | None, str | None]:
    """Check a one-line Suricata/Snort rule, and fix its dialect when only the
    other parser accepts it.

    Stage 4 types a rule ``snort`` when that word precedes it (ADR-0042),
    because the two dialects share one syntax.  The parsers do tell them apart:
    Snort's refuses Suricata's application-layer protocols.

    Returns (pattern_type, status, error, the type it was given when it changed).
    """
    status, error = check_pattern(typed, pattern)
    if status != REFUSED:
        return typed, status, error, None
    other = "suricata" if typed == "snort" else "snort"
    if check_pattern(other, pattern)[0] == ACCEPTED:
        return other, ACCEPTED, None, typed
    return typed, REFUSED, error, None


def ledger_info(status: str, retyped_from: str | None = None) -> dict:
    """What the mapping ledger records about a shipped rule's check."""
    info: dict = {}
    if status == UNVERIFIED:
        info["pattern_check"] = UNVERIFIED
    if retyped_from:
        info["retyped_from"] = retyped_from
    return info
