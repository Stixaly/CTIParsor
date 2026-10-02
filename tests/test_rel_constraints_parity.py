"""The verbs the UI offers are the verbs Stage 4 ships.

`frontend/src/stix/relConstraints.ts` is a second copy of the STIX 2.1 tables
in `pipeline/stix_rel_spec.py`.  When the two disagree, an analyst can pick a
verb in the review UI that Stage 4 then ships as `related-to`: the UI used to
offer `duplicate-of` and `derived-from` for every pair, while §3.7 and the
backend keep them for two objects of the same type.
"""
import json
import re
import sys
from pathlib import Path

from models.schemas import STIX_RELATIONSHIP_TYPES
from pipeline.stix_rel_spec import _SUGGESTED, SCO_TYPES, rel_is_suggested

_STIX = Path(__file__).resolve().parent.parent / "frontend" / "src" / "stix"
_TS = _STIX / "relConstraints.ts"
# Which verbs ship as written, per pair of types, computed from Stage 4 itself.
# `relConstraints.test.ts` holds `shippedVerbs` to the same file.
_FIXTURE = _STIX / "shippedVerbs.fixture.json"


def _shipped_matrix() -> dict:
    from pipeline.stage4_stix_mapping import _OBSERVABLE_SCO_TYPES, verb_ships_as_written

    types = sorted(
        set(_SUGGESTED) | {t for v in _SUGGESTED.values() for ts in v.values() for t in ts}
        | set(SCO_TYPES) | set(_OBSERVABLE_SCO_TYPES) | {"incident"}
    )
    types.remove("*SCO*")
    pairs = {}
    for s in types:
        for t in types:
            verbs = sorted(v for v in STIX_RELATIONSHIP_TYPES if verb_ships_as_written(s, v, t))
            if verbs != ["related-to"]:   # the default, left out to keep the file small
                pairs[f"{s}>{t}"] = verbs
    return {"types": types, "default": ["related-to"], "pairs": pairs}


def _frontend_table() -> dict[tuple[str, str], set[str]]:
    text = _TS.read_text(encoding="utf-8")
    body = text[text.index("STIX_REL_CONSTRAINTS"):text.index("\n}\n")]
    return {
        (m.group(1), m.group(2)): set(re.findall(r"'([a-z0-9-]+)'", m.group(3)))
        for m in re.finditer(r"'([a-z0-9-]+)>([a-z0-9-]+)':\s*\[([^\]]*)\]", body)
    }


def _backend_table() -> dict[tuple[str, str], set[str]]:
    out: dict[tuple[str, str], set[str]] = {}
    for src, verbs in _SUGGESTED.items():
        for verb, targets in verbs.items():
            for tgt in targets:
                for t in (sorted(SCO_TYPES) if tgt == "*SCO*" else [tgt]):
                    out.setdefault((src, t), set()).add(verb)
    return out


def test_the_frontend_table_is_the_backend_table():
    assert _frontend_table() == _backend_table()


def test_the_frontend_sco_list_is_the_spec_list():
    text = _TS.read_text(encoding="utf-8")
    block = text[text.index("export const SCO_TYPES"):]
    block = block[:block.index("])")]
    assert set(re.findall(r"'([a-z0-9-]+)'", block)) == set(SCO_TYPES)


def test_the_frontend_observables_are_stage4s():
    """`shippedVerbs` routes an observable through its Indicator exactly when
    Stage 4 does, so both must agree on what an observable is."""
    from pipeline.stage4_stix_mapping import _OBSERVABLE_SCO_TYPES

    text = _TS.read_text(encoding="utf-8")
    block = text[text.index("export const OBSERVABLE_TYPES"):]
    block = block[:block.index("])")]
    assert set(re.findall(r"'([a-z0-9-]+)'", block)) == set(_OBSERVABLE_SCO_TYPES)


def test_the_shipped_verbs_fixture_is_stage4s():
    """Regenerate with: python -m tests.test_rel_constraints_parity --write"""
    assert json.loads(_FIXTURE.read_text(encoding="utf-8")) == _shipped_matrix()


def test_common_verbs_follow_the_backend():
    text = _TS.read_text(encoding="utf-8")
    assert "return src === tgt ? UNIVERSAL_VERBS : ['related-to']" in text
    for verb in ("duplicate-of", "derived-from"):
        assert rel_is_suggested("malware", verb, "malware")
        assert not rel_is_suggested("malware", verb, "tool")
    assert rel_is_suggested("malware", "related-to", "tool")


if __name__ == "__main__" and "--write" in sys.argv:
    _FIXTURE.write_text(json.dumps(_shipped_matrix(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {_FIXTURE}")
