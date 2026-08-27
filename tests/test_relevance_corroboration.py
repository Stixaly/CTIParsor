from pipeline.detection.relevance import (
    Match,
    Proposal,
    combine,
    corroborate,
)


def test_corroborate_is_zero_on_empty():
    assert corroborate([]) == 0.0


def test_corroborate_saturates_below_one():
    result = corroborate([10.0])
    assert result < 1.0
    assert result > 0.99


def test_corroborate_keeps_rewarding_a_fourth_match():
    three = corroborate([0.7] * 3)
    four = corroborate([0.7] * 4)
    assert three < four


def test_corroborate_beats_noisy_or_on_headroom():
    noisy_or_gain = combine([0.7] * 4) - combine([0.7] * 3)
    corroborate_gain = corroborate([0.7] * 4) - corroborate([0.7] * 3)
    assert noisy_or_gain < corroborate_gain


def test_a_technique_only_rule_cannot_outrank_one_discriminating_match():
    tech_only = corroborate([0.30])
    discriminating_match = corroborate([0.85 * 0.9])
    assert tech_only < discriminating_match


def test_match_defaults_to_discriminating():
    m = Match(
        obs_class="domain",
        atom_class="domain",
        value="example.com",
        display="example.com",
        exact=True,
        weight=0.85,
    )
    assert m.discriminating is True


def test_ubiquitous_match_carries_weight_but_is_flagged():
    m = Match(
        obs_class="file",
        atom_class="file",
        value="cmd.exe",
        display="cmd.exe",
        exact=True,
        weight=0.5,
        discriminating=False,
    )
    assert m.discriminating is False
    assert m.weight == 0.5


def test_proposal_as_dict_exposes_counts_and_flags():
    m1 = Match(
        obs_class="domain",
        atom_class="domain",
        value="malware.com",
        display="malware.com",
        exact=True,
        weight=0.85,
        discriminating=True,
    )
    m2 = Match(
        obs_class="file",
        atom_class="file",
        value="cmd.exe",
        display="cmd.exe",
        exact=True,
        weight=0.5,
        discriminating=False,
    )
    p = Proposal(
        rule_id="rule-1",
        corpus="test",
        title="Test Rule",
        severity="high",
        license="mitre",
        source_ref="ref-1",
        platform="windows",
        score=0.5,
        tier="direct",
        techniques=["T1059"],
        matches=[m1, m2],
        format="sigma",
        evidence_count=1,
        support_count=1,
    )
    d = p.as_dict()
    assert d["evidence_count"] == 1
    assert d["support_count"] == 1
    assert d["matches"][0]["discriminating"] is True
    assert d["matches"][1]["discriminating"] is False
