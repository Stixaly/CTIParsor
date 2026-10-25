"""
The measurement of ADR-0090 lot 7 in scripts/baseline_ablation.py (measures A3 and
A2).  The unit of the ablation is the index entry: an observable, its Indicator and
the based-on between them leave together.  Tested here: the draw (round(ratio x
candidate entries), fixed by the seed and the job), the candidate entries, the
removal of whole entries (with their relationships and Report references), and the
classification of a reconciliation against the ledger (recovered, duplicate,
ambiguous, unmapped, mismatch) at entry level.

Pure and fast: the hand-built classification uses hand-built entries, and the
entry tests read the OpenCTI fixture through `intake` (validate=False).  No database.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pipeline import baseline_stix as bs
from scripts.baseline_ablation import (
    _derive,
    _type_tables,
    ablate,
    candidate_entries,
    classify,
    draw,
    fixture_originals,
    owners,
    removed_objects,
    render_fixture,
    row_originals,
)

BASELINES = Path(__file__).parent / "fixtures" / "baselines"

MAL = "malware--00000000-0000-4000-8000-000000000004"          # "Alpha", its own entry, removed
MAL2 = "malware--00000000-0000-4000-8000-000000000005"         # "Beta", its own entry, kept
IP = "ipv4-addr--00000000-0000-4000-8000-000000000006"         # "1.2.3.4", removed with IND and REL_IND
IND = "indicator--00000000-0000-4000-8000-000000000007"        # the Indicator of IP (and of DOM, below)
REL_IND = "relationship--00000000-0000-4000-8000-000000000008"  # based-on: IND -> IP
AP = "attack-pattern--00000000-0000-4000-8000-00000000000a"    # kept, its own entry
DOM = "domain-name--00000000-0000-4000-8000-00000000000b"      # "evil.example", kept with IND, the other entry
REL_DOM = "relationship--00000000-0000-4000-8000-00000000000c"  # based-on: IND -> DOM


def _fixture() -> dict:
    return json.loads((BASELINES / "opencti_report.json").read_text(encoding="utf-8"))


def _entry(entry_id: str, stix_type: str, object_ids: tuple[str, ...]) -> bs.Entry:
    return bs.Entry(entry_id=entry_id, stix_type=stix_type, entity_type=stix_type, value=entry_id, mitre_id=None,
                    keys=frozenset(), weak_keys=frozenset(), sco_id=None, indicator_ids=(),
                    object_ids=object_ids, surface_forms=())


def _index(entries) -> bs.BaselineIndex:
    return bs.BaselineIndex(version=bs.INDEX_VERSION, sha256="", bundle_id="", entries=list(entries),
                            relations=[], imported_ids=frozenset(), passthrough_ids=frozenset(), report_ids=())


def _without(index: bs.BaselineIndex, drawn) -> bs.BaselineIndex:
    """The index of the ablated bundle, for the hand-built cases where no entry shares an object."""
    return _index([e for e in index.entries if e.entry_id not in drawn])


@pytest.mark.parametrize("count", [0, 1, 10, 115])
@pytest.mark.parametrize("ratio", [0.0, 0.3, 0.5])
def test_the_draw_takes_round_of_the_ratio_times_the_candidate_entries(ratio, count):
    candidate_ids = [f"malware--{i:08d}-0000-4000-8000-000000000000" for i in range(count)]
    drawn = draw("job-a", candidate_ids, ratio, 20261025)
    assert len(drawn) == round(ratio * count)
    assert drawn <= set(candidate_ids)


def test_the_draw_is_fixed_by_the_seed_and_the_job():
    candidate_ids = sorted(f"malware--{i:08d}-0000-4000-8000-000000000000" for i in range(60))
    first = draw("job-a", candidate_ids, 0.3, 7)
    assert first == draw("job-a", candidate_ids, 0.3, 7)
    assert first != draw("job-a", candidate_ids, 0.3, 8)
    assert first != draw("job-b", candidate_ids, 0.3, 7)


def test_the_candidate_entries_are_the_entries_holding_a_ledger_object_but_not_the_report_identity_or_marking():
    bundle = _fixture()
    objects = {o["id"]: o for o in bundle["objects"]}
    index, _intake, _bundle = bs.intake(json.dumps(bundle).encode(), validate=False)
    sco = next(o["id"] for o in bundle["objects"] if o["type"] == "ipv4-addr")
    malware = next(o["id"] for o in bundle["objects"] if o["type"] == "malware")
    identity = next(o["id"] for o in bundle["objects"] if o["type"] == "identity")
    ledger = {"entities": [
        {"value": "198.18.12.77", "entity_type": "ipv4", "outcome": "emitted", "stix_id": sco},
        {"value": "WellMess", "entity_type": "malware", "outcome": "emitted", "stix_id": malware},
        {"value": "Someone", "entity_type": "identity", "outcome": "emitted", "stix_id": identity},
    ]}

    candidates = candidate_entries(index, row_originals(ledger, objects), objects)

    ipv4_entry = next(e.entry_id for e in index.entries if sco in e.object_ids)
    assert candidates == sorted([ipv4_entry, malware])


def test_an_observable_and_its_indicator_leave_together():
    bundle = _fixture()
    index, _intake, _bundle = bs.intake(json.dumps(bundle).encode(), validate=False)
    entry = next(e for e in index.entries if e.stix_type == "ipv4-addr")
    assert len(entry.object_ids) > 1                  # the observable, its Indicator, the based-on between them

    gone = removed_objects(index, {entry.entry_id})
    data = ablate(bundle, gone)
    after, _intake, _bundle = bs.intake(json.dumps(data).encode(), validate=False)

    assert gone == set(entry.object_ids)
    ids = {o["id"] for o in data["objects"]}
    assert not gone & ids
    assert all(entry.value != e.value for e in after.entries)
    malware = next(o["id"] for o in bundle["objects"] if o["type"] == "malware")
    assert malware in ids                            # the entries that touch no removed object stay


def test_the_ablation_drops_the_relationships_and_report_references_of_a_removed_entry():
    bundle = _fixture()
    before = copy.deepcopy(bundle)
    index, _intake, _bundle = bs.intake(json.dumps(bundle).encode(), validate=False)
    entry = next(e for e in index.entries if e.stix_type == "ipv4-addr")
    gone = removed_objects(index, {entry.entry_id})
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert gone & set(report["object_refs"])         # the Report names them, before

    data = ablate(bundle, gone)

    after = next(o for o in data["objects"] if o["type"] == "report")
    assert not gone & set(after["object_refs"])
    touching = [o for o in data["objects"]
                if o.get("type") == "relationship" and gone & {o.get("source_ref"), o.get("target_ref")}]
    assert touching == []
    assert bundle == before                          # the input is not changed


def _classify_case():
    """A baseline of four entries: an observable with its Indicator (removed), Alpha
    (removed), Beta and an attack-pattern (kept)."""
    entries = [
        _entry("entry-ip", "ipv4-addr", (IP, IND, REL_IND)),
        _entry("entry-alpha", "malware", (MAL,)),
        _entry("entry-beta", "malware", (MAL2,)),
        _entry("entry-ap", "attack-pattern", (AP,)),
    ]
    index = _index(entries)
    originals = {
        ("malware", "alpha"): frozenset({MAL}),
        ("malware", "beta"): frozenset({MAL2}),
        ("location", "nowhere"): frozenset(),
        ("ipv4", "1.2.3.4"): frozenset({IP}),
        ("malware", "gamma"): frozenset({MAL}),
        ("ttp", "phishing"): frozenset({AP}),
        ("malware", "delta"): frozenset({MAL2, AP}),
    }
    status = {
        ("malware", "alpha"): (bs.NEW, None),                 # recovered: its entry is removed
        ("malware", "beta"): (bs.NEW, None),                  # duplicate: its entry is kept
        ("location", "nowhere"): (bs.NEW, None),              # unmapped
        ("ipv4", "1.2.3.4"): (bs.NEW, None),                  # recovered: the observable's entry is removed
        ("malware", "gamma"): (bs.MATCHED, "entry-beta"),     # mismatch: its original is in entry-alpha
        ("ttp", "phishing"): (bs.MATCHED, "entry-ap"),        # right
        ("malware", "delta"): (bs.NEW, None),                 # ambiguous: two originals
    }
    return index, originals, status


def test_classification_counts_at_entry_level():
    index, originals, status = _classify_case()
    drawn = {"entry-ip", "entry-alpha"}

    counts = classify(status, originals, index, drawn, _without(index, drawn))

    assert counts["rows"] == 7
    assert counts["new"] == 5
    assert counts["matched"] == 2
    assert counts["recovered"] == 2
    assert counts["reachable"] == 2
    assert counts["reachable_not_recovered"] == 0
    assert counts["duplicates"] == 1
    assert counts["ambiguous"] == 1
    assert counts["unmapped_new"] == 1
    assert counts["other_new"] == 0
    assert counts["mismatch"] == 1
    assert counts["removed_objects"] == 4
    assert counts["by_type"]["removed"] == {"ipv4-addr": 1, "malware": 1}
    assert counts["by_type"]["recovered"] == {"ipv4-addr": 1, "malware": 1}
    assert counts["by_type"]["duplicates"] == {"malware": 1}
    assert counts["details"]["duplicates"] == [
        {"row": ["malware", "beta"], "original": MAL2, "entry_id": "entry-beta"}]
    assert counts["details"]["ambiguous"] == [
        {"row": ["malware", "delta"], "originals": sorted([MAL2, AP])}]
    assert counts["details"]["mismatch"][0]["entry_of_original"] == ["entry-alpha"]


def test_a_row_of_a_removed_entry_is_recovered_not_a_duplicate():
    index, _originals, _status = _classify_case()
    status = {("ipv4", "1.2.3.4"): (bs.NEW, None)}
    originals = {("ipv4", "1.2.3.4"): frozenset({IP})}

    counts = classify(status, originals, index, {"entry-ip"}, _without(index, {"entry-ip"}))

    assert counts["recovered"] == 1
    assert counts["duplicates"] == 0


def test_an_entry_keeping_an_object_of_a_drawn_entry_is_kept_not_other_new():
    # The Indicator IND states two observable types: it is held by entry-ip and by entry-dom.
    # Drawing entry-ip removes IND, but entry-dom keeps its domain name: a row for it is a duplicate.
    index = _index([_entry("entry-ip", "ipv4-addr", (IP, IND, REL_IND)),
                    _entry("entry-dom", "domain-name", (DOM, IND, REL_DOM))])
    originals = {("ipv4", "1.2.3.4"): frozenset({IP}), ("domain", "evil.example"): frozenset({DOM})}
    status = {("ipv4", "1.2.3.4"): (bs.NEW, None), ("domain", "evil.example"): (bs.NEW, None)}
    remaining = _index([_entry("entry-dom", "domain-name", (DOM,))])     # what the ablated bundle holds

    counts = classify(status, originals, index, {"entry-ip"}, remaining)

    assert counts["recovered"] == 1
    assert counts["duplicates"] == 1
    assert counts["other_new"] == 0
    assert counts["details"]["duplicates"][0]["entry_id"] == "entry-dom"
    assert counts["reachable"] == 1


def test_a_reachable_entry_no_row_came_back_to_is_listed_with_the_rows_that_reach_it():
    index, originals, _status = _classify_case()
    status = {("malware", "gamma"): (bs.MATCHED, "entry-beta")}      # gamma's original is Alpha, in entry-alpha
    originals = {("malware", "gamma"): frozenset({MAL})}
    drawn = {"entry-alpha"}

    counts = classify(status, originals, index, drawn, _without(index, drawn))

    assert counts["reachable"] == 1
    assert counts["reachable_not_recovered"] == 1
    assert counts["details"]["not_recovered"] == [{
        "entry_id": "entry-alpha", "stix_type": "malware", "value": "entry-alpha",
        "rows": [{"row": ["malware", "gamma"], "status": bs.MATCHED, "entry_id": "entry-beta", "originals": [MAL]}],
    }]


def test_the_rates_are_recovery_over_reachable_and_duplicates_over_new():
    index, originals, status = _classify_case()
    counts = classify(status, originals, index, {"entry-ip", "entry-alpha"},
                      _without(index, {"entry-ip", "entry-alpha"}))

    rates = _derive({**counts, "removed": 2})

    assert rates["recovery"] == pytest.approx(1.0)          # both removed entries came back as new rows
    assert rates["duplicate_rate"] == pytest.approx(1 / 5)  # one of five new rows designates a kept entry


def test_a_fixture_original_is_the_entry_a_row_matches_in_the_full_fixture():
    rec = bs.Reconciliation(entity_status={
        ("malware", "alpha"): (bs.MATCHED, MAL),
        ("location", "nowhere"): (bs.NEW, None),
    })

    assert fixture_originals(rec) == {("malware", "alpha"): frozenset({MAL})}


def test_the_type_tables_are_two_tables_with_their_own_headers():
    total = {"by_type": {"removed": {"malware": 2}, "reachable": {"malware": 2}, "recovered": {"malware": 1},
                         "new": {"location": 3}, "duplicates": {"malware": 1}}}

    lines = _type_tables(total)

    assert "### Removed entries by STIX type" in lines
    assert "| malware | 2 | 2 | 1 | 50.0 % |" in lines
    assert "### New rows by entity type" in lines
    assert "| location | 3 | 0 | 0.0 % |" in lines
    assert "| malware | 0 | 1 | - |" in lines


def test_the_fixture_report_has_a_row_per_seed_and_the_sum_and_the_detail():
    index, originals, status = _classify_case()
    status = {key: value for key, value in status.items() if key != ("malware", "beta")}     # no duplicate to show
    drawn = {"entry-ip", "entry-alpha"}     # the IP row and the Alpha row come back: no duplicate left
    run = _derive({**classify(status, originals, index, drawn, _without(index, drawn)), "removed": len(drawn)})
    case = {"candidates": 3, "matched_in_full": 2, "raw_rows": 7, "skipped_rows": 0, "round_trip": run,
            "runs": [{"seed": 4, "ablation": run}, {"seed": 5, "ablation": run}]}

    text = render_fixture(case, [4, 5], 0.3, Path("out.json"))

    assert "| seed 4 |" in text and "| seed 5 |" in text
    assert "| **total** |" in text
    assert "### Removed entries by STIX type" in text
    assert "### Reachable, not recovered, ablation" in text
    assert text.endswith("JSON: out.json")


def test_an_entry_answers_to_its_own_id_when_that_id_is_no_object_of_the_bundle():
    # The observable of a compound Indicator is named `<indicator>#<type>` (no object has that id).
    url = "indicator--00000000-0000-4000-8000-00000000000d#url"
    index = _index([_entry(url, "url", ("indicator--00000000-0000-4000-8000-00000000000d",))])

    assert owners(index)[url] == {url}
