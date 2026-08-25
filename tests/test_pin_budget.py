"""Tests for the pin-budget allocation logic in pipeline.stage4_stix_mapping."""


from pipeline.stage4_stix_mapping import (
    PinRuleStat,
    PinStats,
    _fair_share,
    _materialise_pinned_edges,
    _pin_edge_key,
)


class _Obj:
    """Minimal stand-in for a STIX object: an id and a type."""

    def __init__(self, otype: str, n: int) -> None:
        self.type = otype
        self.id = f"{otype}--{n:08d}-0000-4000-8000-000000000000"


def test_fair_share_worked_example() -> None:
    assert _fair_share([8, 24, 507, 96], 200) == [8, 24, 84, 84]


def test_fair_share_serves_every_rule_when_budget_allows() -> None:
    assert _fair_share([3, 4, 5], 100) == [3, 4, 5]


def test_fair_share_zero_budget_grants_nothing() -> None:
    assert _fair_share([10, 20], 0) == [0, 0]


def test_fair_share_never_exceeds_demand_or_budget() -> None:
    demands = [1, 2, 3, 400, 500]
    result = _fair_share(demands, 50)
    assert sum(result) == 50
    for r, d in zip(result, demands):
        assert r <= d


def test_fair_share_leftover_pass_distributes_remainder() -> None:
    result = _fair_share([1, 1, 1], 2)
    assert sum(result) == 2
    for r in result:
        assert r in (0, 1)


def test_fair_share_is_deterministic() -> None:
    a = _fair_share([5, 5, 5, 5], 7)
    b = _fair_share([5, 5, 5, 5], 7)
    assert a == b


def test_fair_share_empty_demands() -> None:
    assert _fair_share([], 100) == []


def test_pin_edge_key_rejects_self_pair() -> None:
    o = _Obj("malware", 1)
    assert _pin_edge_key(o, "uses", o) is None


def test_pin_edge_key_downgrades_non_suggested_verb() -> None:
    src = _Obj("domain-name", 1)
    tgt = _Obj("malware", 2)
    key = _pin_edge_key(src, "uses", tgt)
    assert key is not None
    assert key[1] == "related-to"


def test_pin_edge_key_keeps_suggested_verb() -> None:
    src = _Obj("malware", 1)
    tgt = _Obj("attack-pattern", 2)
    key = _pin_edge_key(src, "uses", tgt)
    assert key is not None
    assert key[1] == "uses"


def test_materialise_respects_global_auto() -> None:
    stix_objects = [
        _Obj("malware", 1),
        _Obj("attack-pattern", 2),
    ]
    policy = {
        "global": "auto",
        "rules": [
            {
                "src": "malware",
                "verb": "uses",
                "tgt": "attack-pattern",
                "mode": "pin",
                "enabled": True,
            }
        ],
    }
    stats = _materialise_pinned_edges(stix_objects, policy, set())
    assert stats.total_emitted == 0


def test_materialise_no_rule_is_starved_by_list_order() -> None:
    stix_objects = (
        [_Obj("malware", i) for i in range(13)]
        + [_Obj("attack-pattern", i) for i in range(39)]
        + [_Obj("domain-name", i) for i in range(4)]
        + [_Obj("ipv4-addr", i) for i in range(7)]
    )
    rules = [
        {"src": "malware", "verb": "uses", "tgt": "attack-pattern",
         "mode": "pin", "enabled": True},
        {"src": "domain-name", "verb": "resolves-to", "tgt": "ipv4-addr",
         "mode": "pin", "enabled": True},
    ]

    # Sequential mode: first rule consumes the entire budget.
    policy_seq = {
        "pin_budget_mode": "sequential",
        "max_pinned_edges": 200,
        "rules": rules,
    }
    stats_seq = _materialise_pinned_edges(stix_objects, policy_seq, set())
    assert stats_seq.total_emitted <= 200
    second_seq = next(
        (r for r in stats_seq.rules if r.rule == "domain-name resolves-to ipv4-addr"),
        None,
    )
    assert second_seq is not None
    assert second_seq.emitted == 0

    # Fair-share mode (default): both rules receive a share.
    policy_fs = {
        "max_pinned_edges": 200,
        "rules": rules,
    }
    stats_fs = _materialise_pinned_edges(stix_objects, policy_fs, set())
    assert stats_fs.total_emitted <= 200
    second_fs = next(
        (r for r in stats_fs.rules if r.rule == "domain-name resolves-to ipv4-addr"),
        None,
    )
    assert second_fs is not None
    assert second_fs.emitted == 28


def test_materialise_dedups_against_existing_edges() -> None:
    src = _Obj("malware", 1)
    tgt = _Obj("attack-pattern", 2)
    key = _pin_edge_key(src, "uses", tgt)
    assert key is not None
    seen = {key}
    stix_objects = [src, tgt]
    policy = {
        "max_pinned_edges": 10,
        "rules": [
            {
                "src": "malware",
                "verb": "uses",
                "tgt": "attack-pattern",
                "mode": "pin",
                "enabled": True,
            }
        ],
    }
    stats = _materialise_pinned_edges(stix_objects, policy, seen)
    rule = next(
        (r for r in stats.rules if r.rule == "malware uses attack-pattern"),
        None,
    )
    assert rule is not None
    assert rule.candidates == 0


def test_materialise_skips_malformed_rule_entries() -> None:
    stix_objects = [
        _Obj("malware", 1),
        _Obj("attack-pattern", 2),
    ]
    policy = {
        "max_pinned_edges": 10,
        "rules": [
            "oops",
            None,
            {
                "src": "malware",
                "verb": "uses",
                "tgt": "attack-pattern",
                "mode": "pin",
                "enabled": True,
            },
        ],
    }
    stats = _materialise_pinned_edges(stix_objects, policy, set())
    rule = next(
        (r for r in stats.rules if r.rule == "malware uses attack-pattern"),
        None,
    )
    assert rule is not None
    assert rule.candidates == 1
    assert rule.emitted == 1


def test_materialise_skips_non_spec_verb() -> None:
    stix_objects = [
        _Obj("malware", 1),
        _Obj("attack-pattern", 2),
    ]
    policy = {
        "max_pinned_edges": 10,
        "rules": [
            {
                "src": "malware",
                "verb": "frobnicates",
                "tgt": "attack-pattern",
                "mode": "pin",
                "enabled": True,
            }
        ],
    }
    stats = _materialise_pinned_edges(stix_objects, policy, set())
    assert stats.total_emitted == 0
    for r in stats.rules:
        assert r.candidates == 0


def test_to_dict_sorts_by_candidates_desc_and_drops_empty_rules() -> None:
    stats = PinStats(
        budget=100,
        mode="fair-share",
        rules=[
            PinRuleStat(rule="a", candidates=5, emitted=5, truncated=0),
            PinRuleStat(rule="b", candidates=0, emitted=0, truncated=0),
            PinRuleStat(rule="c", candidates=50, emitted=50, truncated=0),
        ],
    )
    d = stats.to_dict()
    rules = d["rules"]
    assert len(rules) == 2
    assert rules[0]["rule"] == "c"
    assert rules[1]["rule"] == "a"
