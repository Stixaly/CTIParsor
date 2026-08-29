"""Verify that replacing seven boolean flag reads with env_bool is behaviourally identical."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.env_flags import env_bool  # noqa: E402

OLD_SEMANTICS: list[tuple[str, bool, Callable[[str], bool], bool]] = [
    # SKIP_HEAVY_MODELS — five identical copies across the stage modules.
    ("SKIP_HEAVY_MODELS", False,
     lambda v: v == "1", False),
    # stage3d / stage3f — read once at import into _VERIFY_ENABLED.
    ("ENABLE_STIX_VERIFICATION", False,
     lambda v: v.lower() in ("true", "1", "yes"), False),
    ("ENABLE_TTP_VERIFICATION", False,
     lambda v: v.lower() in ("true", "1", "yes"), False),
    # stage3e — the strictest of the seven: only the literal "true".
    ("ENABLE_CONSENSUS", False,
     lambda v: v.strip().lower() == "true", False),
    # stage2d / stage2e — default ON, an unrecognised value stayed ON.
    ("CYNER_ENABLED", True,
     lambda v: v.lower() not in ("false", "0", "no"), True),
    ("GLINER_ENABLED", True,
     lambda v: v.lower() not in ("false", "0", "no"), True),
    # stage2c — measurement escape hatches, read on every call.
    ("TTP_UNWRAP_LINES", True,
     lambda v: v.strip().lower() not in {"0", "off", "false", "no"}, True),
    ("TTP_KEYWORD_GATE", True,
     lambda v: v.strip().lower() not in {"0", "off", "false", "no"}, True),
]

VALUES: tuple[str, ...] = (
    "1", "0", "true", "false", "TRUE", "FALSE", "True", "False",
    "yes", "no", "YES", "NO", "on", "off", "ON", "OFF",
    " true ", " 1 ", "  ", "", "maybe", "2", "-1", "enabled", "disabled",
    "t", "f", "y", "n", "null", "none",
)

#: Values each flag is actually documented with, in `.env.example`,
#: `README.md` and `CLAUDE.md`.  A discrepancy on one of these is a real
#: regression; a discrepancy on any other value only means the operator
#: typed something the old code silently ignored.
DOCUMENTED: dict[str, frozenset[str]] = {
    "SKIP_HEAVY_MODELS": frozenset({"1"}),
    "ENABLE_STIX_VERIFICATION": frozenset({"true", "false"}),
    "ENABLE_TTP_VERIFICATION": frozenset({"true", "false"}),
    "ENABLE_CONSENSUS": frozenset({"true", "false"}),
    "CYNER_ENABLED": frozenset({"true", "false"}),
    "GLINER_ENABLED": frozenset({"true", "false"}),
    "TTP_UNWRAP_LINES": frozenset({"0", "1"}),
    "TTP_KEYWORD_GATE": frozenset({"0", "1"}),
}


def _compare_one(
    flag: str,
    default: bool,
    old_pred: Callable[[str], bool],
    new_default: bool,
) -> list[tuple[str, bool, bool]]:
    """Compare old and new semantics for one flag across all values."""
    rows: list[tuple[str, bool, bool]] = []
    saved = os.environ.get(flag)
    try:
        for v in VALUES:
            os.environ[flag] = v
            old = old_pred(v)
            new = env_bool(flag, default=new_default)
            if old != new:
                rows.append((v, old, new))
        os.environ.pop(flag, None)
        old = default
        new = env_bool(flag, default=new_default)
        if old != new:
            rows.append(("<unset>", old, new))
    finally:
        if saved is None:
            os.environ.pop(flag, None)
        else:
            os.environ[flag] = saved
    return rows


def _print_table(rows: dict[str, list[tuple[str, bool, bool]]]) -> None:
    """Print the comparison table for all flags."""
    for flag, deltas in rows.items():
        if not deltas:
            print(f"{flag} — identical on all {len(VALUES) + 1} values")
            continue
        print(flag)
        print(f"  {'value':<12} {'old':<6} {'new':<6}")
        for v, old, new in deltas:
            print(f"  {repr(v):<12} {str(old):<6} {str(new):<6}")


def _print_verdict(all_deltas: dict[str, list[tuple[str, bool, bool]]]) -> None:
    """Print the final verdict summarising all discrepancies."""
    total = sum(len(d) for d in all_deltas.values())
    total_pairs = len(OLD_SEMANTICS) * (len(VALUES) + 1)
    print(f"\nTotal discrepancies: {total} / {total_pairs} (flag, value) pairs")

    documented = [
        (flag, v, old, new)
        for flag, deltas in all_deltas.items()
        for v, old, new in deltas
        if v in DOCUMENTED.get(flag, frozenset())
    ]
    if not documented:
        print("OK — no documented configuration changes behaviour.")
    else:
        print("REGRESSION — a documented value changed behaviour:")
        for flag, v, old, new in documented:
            print(f"  {flag}: {repr(v)} old={old} new={new}")

    narrowed = [
        (flag, v, old, new)
        for flag, deltas in all_deltas.items()
        for v, old, new in deltas
        if old is True and new is False
    ]
    print("\nNARROWED (a config that used to be ON is now OFF):")
    if not narrowed:
        print("  (none)")
    else:
        for flag, v, old, new in narrowed:
            print(f"  {flag}: {repr(v)} old={old} new={new}")

    widened = [
        (flag, v, old, new)
        for flag, deltas in all_deltas.items()
        for v, old, new in deltas
        if old is False and new is True
    ]
    print("\nWIDENED (a config that used to be OFF is now ON):")
    if not widened:
        print("  (none)")
    else:
        for flag, v, old, new in widened:
            print(f"  {flag}: {repr(v)} old={old} new={new}")


def main() -> int:
    """Run the equivalence check and return exit code."""
    all_deltas: dict[str, list[tuple[str, bool, bool]]] = {}
    for flag, default, old_pred, new_default in OLD_SEMANTICS:
        all_deltas[flag] = _compare_one(flag, default, old_pred, new_default)

    _print_table(all_deltas)
    _print_verdict(all_deltas)

    has_documented_regression = any(
        v in DOCUMENTED.get(flag, frozenset())
        for flag, deltas in all_deltas.items()
        for v, _, _ in deltas
    )
    return 1 if has_documented_regression else 0


if __name__ == "__main__":
    sys.exit(main())
