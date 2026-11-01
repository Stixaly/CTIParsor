"""Reference builds of Stage 4 (ADR-0090, invariant I1: full mode does not change).

`build(scenario)` runs `pipeline.orchestrator.build_bundle` on a scenario's
inputs; `canonical()` turns the result into a form two builds of the same
inputs share, although Stage 4 is not byte-deterministic: the SROs and the
Report get random uuid4 ids from stix2, and `created` / `modified` /
`published` / `valid_from` carry the build time.  The canonical form is what
tests/fixtures/stage4_reference/expected/ freezes.

    python -m tests.stage4_reference <file> [scenario ...]
        canonical forms ({name: form}) of the scenarios (all by default), written to <file>
"""
from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

FIXTURES = Path(__file__).parent / "fixtures" / "stage4_reference"
SCENARIOS = FIXTURES / "scenarios"
EXPECTED = FIXTURES / "expected"

BUILD_TIME = "<build-time>"
TIME_MARGIN = timedelta(seconds=2)

# Environment Stage 4 reads that a developer's shell or .env can set.
ENV_PINNED = ("ATTACK_RELEASE", "STIX_TLP", "STIX_AUTHOR_NAME", "BENIGN_IOC_FILTER")

# Every cache an ATT&CK file feeds on the way through Stage 4.
ATTACK_CACHES = (
    ("pipeline.mitre_db", "_load"), ("pipeline.mitre_db", "_revoked"),
    ("pipeline.aliases", "_load"), ("pipeline.aliases", "_load_techniques"),
    ("pipeline.stage4b_graph_completion", "_attack_pairs"),
)

# The types for which Stage 4 lets stix2 draw a uuid4 id: a relationship and
# the Report take none from stix_ids (ADR-0066).  Every other id is
# deterministic (uuid5, a fixed standard marking), an AttackPattern included:
# a uuid4 of another type stays literal, so a random id appearing where there
# was none fails the reference.
RANDOM_TYPES = frozenset({"relationship", "report"})

_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")
_STIX_ID = re.compile(r"\b([a-z][a-z0-9-]*)--([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b")
_ROUNDS = 10


# ── Scenarios ────────────────────────────────────────────────────────────────

def scenario_names() -> list[str]:
    return sorted(p.stem for p in SCENARIOS.glob("*.json"))


def load_scenario(name: str) -> dict:
    return json.loads((SCENARIOS / f"{name}.json").read_text(encoding="utf-8"))


def expected_path(name: str) -> Path:
    return EXPECTED / f"{name}.json"


def dump(canon: dict) -> str:
    """The text of an expected file."""
    return json.dumps(canon, sort_keys=True, indent=1, ensure_ascii=False) + "\n"


def forget_attack_caches() -> None:
    """The release the process fixed and what the loaders read from it."""
    from pipeline import attack_data
    attack_data.reset()
    for module, name in ATTACK_CACHES:
        getattr(importlib.import_module(module), name).cache_clear()


def pin_environment() -> None:
    """The shipped ATT&CK release and no TLP / author override, whatever the
    developer's shell or `.env` says.  For a process of its own; a test pins
    with monkeypatch (see `ENV_PINNED`).  pipeline.stage3_llm loads `.env` at
    import, so it comes first: what it injects is removed after."""
    importlib.import_module("pipeline.stage3_llm")
    for key in ENV_PINNED:
        os.environ.pop(key, None)
    forget_attack_caches()


# ── Build ────────────────────────────────────────────────────────────────────

def build(scenario: dict) -> tuple[str, dict, datetime, datetime]:
    """(serialized bundle, ledger, time before the build, time after it).

    Optional scenario keys: `source_bytes` (text, with `source_hash`: the
    artifact SCO), `document_anchor` (an Anchor as a dict), `cve_metadata` (as
    `lookup_cves` returns it), and `long_distance_answer`: the LLM's JSON answer
    to every Stage 4c question, served by a stub in place of the provider (the
    real inferer runs, only the network call is replaced)."""
    from models.schemas import RawEntity
    from pipeline.bundle_ledger import MappingLedger
    from pipeline.orchestrator import build_bundle
    from pipeline.stage3_llm import LLMEnrichmentResult
    from pipeline.temporal import Anchor

    entities = [RawEntity.model_validate(e) for e in scenario["entities"]]
    llm_result = LLMEnrichmentResult.model_validate(scenario["llm_result"])
    anchor = scenario.get("document_anchor")
    source = scenario.get("source_bytes")
    answer = scenario.get("long_distance_answer")
    ledger = MappingLedger()

    stub = mock.patch.multiple(
        "pipeline.stage3_llm",
        _call_llm=lambda system, user, *a, **kw: json.dumps(answer),
        _provider_ready=lambda *a, **kw: True,
    ) if answer else contextlib.nullcontext()
    t_before = datetime.now(timezone.utc)
    with stub:
        bundle = build_bundle(
            entities, llm_result,
            report_name=scenario["report_name"],
            report_text=scenario["report_text"],
            original_filename=scenario["original_filename"],
            source_hash=scenario.get("source_hash"),
            source_bytes=source.encode("utf-8") if source else None,
            policy=scenario.get("policy"),
            tlp_level=scenario.get("tlp"),
            pap_level=scenario.get("pap"),
            cve_metadata=scenario.get("cve_metadata") or {},
            graph_completion=True,
            long_distance=bool(answer),
            ledger=ledger,
            document_anchor=Anchor.model_validate(anchor) if anchor else None,
        )
    t_after = datetime.now(timezone.utc)
    return bundle.serialize(pretty=True), ledger.to_dict(), t_before, t_after


# ── Canonical form ───────────────────────────────────────────────────────────

def _is_build_time(text: str, low: datetime, high: datetime) -> bool:
    if not _TIMESTAMP.fullmatch(text):
        return False
    try:
        instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    if instant.tzinfo is None:
        return False
    return low <= instant <= high


def _map_strings(value, fn):
    """`value` with `fn` applied to every string, dict keys included."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_map_strings(v, fn) for v in value]
    if isinstance(value, dict):
        return {fn(k): _map_strings(v, fn) for k, v in value.items()}
    return value


def _is_random(match: re.Match) -> bool:
    if match.group(1) not in RANDOM_TYPES:
        return False
    try:
        return uuid.UUID(match.group(2)).version == 4
    except ValueError:
        return False


def _random_ids(value) -> set[str]:
    found: set[str] = set()

    def scan(text: str) -> str:
        found.update(m.group(0) for m in _STIX_ID.finditer(text) if _is_random(m))
        return text

    _map_strings(value, scan)
    return found


def _rename(value, labels: dict[str, str], keep: str | None = None):
    """`value` with every random id replaced by its label; `keep` becomes "<self>"."""
    def sub(text: str) -> str:
        def one(m: re.Match) -> str:
            if m.group(0) == keep:
                return "<self>"
            return labels.get(m.group(0), m.group(0)) if _is_random(m) else m.group(0)
        return _STIX_ID.sub(one, text)

    return _map_strings(value, sub)


def _ledger_records(ledger: dict) -> list:
    """The ledger cut into the records one id can be mentioned in."""
    records: list = [{"objects": {k: v}} for k, v in ledger.get("objects", {}).items()]
    for key in ("entities", "relationships", "removed"):
        records += [{key: item} for item in ledger.get(key, [])]
    return records


def _label_random_ids(objects: list, ledger: dict) -> dict[str, str]:
    """Stable names for the random ids, by content and not by order of arrival.

    The signature of an id is what is known about it besides its value: the
    object that carries it (its own id left out), and the ledger records that
    mention it, each with every other random id replaced by the label that id
    has for now.  Ids are sorted by (type, signature), labelled in that order,
    and the signatures recomputed under the new labels until nothing moves.
    Raises when the labels do not settle, or when two ids end with the same
    signature: they could not be told apart, and which one is `R1` would be
    chance.
    """
    ids = _random_ids(objects) | _random_ids(ledger)
    records = _ledger_records(ledger)
    by_id = {o["id"]: o for o in objects}
    mentions: dict[str, list] = {i: [] for i in ids}
    for r in records:
        for i in _random_ids(r):
            mentions[i].append(r)
    labels = {i: f"{i.split('--')[0]}--R0" for i in ids}
    for _ in range(_ROUNDS):
        signatures = {}
        for i in ids:
            parts = []
            if i in by_id:
                parts.append(json.dumps(_rename({k: v for k, v in by_id[i].items() if k != "id"}, labels, i),
                                        sort_keys=True))
            parts += sorted(json.dumps(_rename(r, labels, i), sort_keys=True) for r in mentions[i])
            signatures[i] = json.dumps(parts)
        counters: dict[str, int] = {}
        new: dict[str, str] = {}
        for i in sorted(ids, key=lambda i: (i.split("--")[0], signatures[i])):
            stix_type = i.split("--")[0]
            counters[stix_type] = counters.get(stix_type, 0) + 1
            new[i] = f"{stix_type}--R{counters[stix_type]}"
        if new == labels:
            keys = [(i.split("--")[0], signatures[i]) for i in ids]
            if len(set(keys)) != len(keys):
                twins = sorted(i for i in ids if keys.count((i.split("--")[0], signatures[i])) > 1)
                raise AssertionError(f"indistinguishable random objects, labelled by chance: {twins}")
            return labels
        labels = new
    raise AssertionError(f"the labels of the random ids did not settle in {_ROUNDS} rounds")


def canonical(bundle_json: str, ledger: dict, t_before: datetime, t_after: datetime) -> dict:
    """{"objects": [...], "ledger": {...}}, equal for two builds of the same inputs.

    * a timestamp within two seconds of the build becomes "<build-time>"; the
      others are deterministic and stay;
    * a uuid4 id of a type in `RANDOM_TYPES` becomes `<type>--R<n>`, numbered
      by content; every other id stays;
    * objects are sorted by (type, id), the ledger's lists by their JSON.
    """
    objects = json.loads(bundle_json)["objects"]
    ledger = json.loads(json.dumps(ledger, default=str))
    low, high = t_before - TIME_MARGIN, t_after + TIME_MARGIN

    def times(text: str) -> str:
        return BUILD_TIME if _is_build_time(text, low, high) else text

    objects = _map_strings(objects, times)
    ledger = _map_strings(ledger, times)

    labels = _label_random_ids(objects, ledger)
    objects = _rename(objects, labels)
    ledger = _rename(ledger, labels)

    objects.sort(key=lambda o: (o["type"], o["id"]))
    for key in ("entities", "relationships", "removed"):
        if key in ledger:
            ledger[key].sort(key=lambda item: json.dumps(item, sort_keys=True))
    return {"objects": objects, "ledger": ledger}


def canonical_build(scenario: dict) -> dict:
    return canonical(*build(scenario))


if __name__ == "__main__":
    pin_environment()
    # A file, not stdout: the pipeline's logging goes to stdout.
    names = sys.argv[2:] or scenario_names()
    forms = {name: canonical_build(load_scenario(name)) for name in names}
    Path(sys.argv[1]).write_text(json.dumps(forms, sort_keys=True), encoding="utf-8")
