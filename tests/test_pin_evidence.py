from pipeline.stage4_stix_mapping import (
    PinRuleStat,
    PinStats,
    _build_sentence_index,
    _evidence_terms,
    _materialise_pinned_edges,
    _pair_is_grounded,
    _split_sentences,
)


class _Obj:
    """Minimal stand-in for a STIX object: attributes only, no stix2."""
    def __init__(self, otype: str, n: int, **fields) -> None:
        self.type = otype
        self.id = f"{otype}--{n:08d}-0000-4000-8000-000000000000"
        for k, v in fields.items():
            setattr(self, k, v)


# --- _evidence_terms ---

def test_terms_for_indicator_come_from_pattern_not_name():
    obj = _Obj("indicator", 1, name="Indicator: evil.com", pattern="[domain-name:value = 'evil.com']")
    terms = _evidence_terms(obj)
    assert terms == ["evil.com"]
    assert "Indicator: evil.com" not in terms


def test_terms_for_indicator_with_numeric_pattern():
    obj = _Obj("indicator", 1, name="Indicator: AS64512", pattern="[autonomous-system:number = 64512]")
    terms = _evidence_terms(obj)
    assert terms == ["64512"]


def test_terms_for_indicator_without_pattern_is_empty():
    obj = _Obj("indicator", 1, name="Indicator: something")
    terms = _evidence_terms(obj)
    assert terms == []


def test_terms_for_attack_pattern_is_empty():
    obj = _Obj("attack-pattern", 1, name="Phishing")
    terms = _evidence_terms(obj)
    assert terms == []


def test_terms_for_course_of_action_is_empty():
    obj = _Obj("course-of-action", 1, name="Isolate host")
    terms = _evidence_terms(obj)
    assert terms == []


def test_terms_include_name_and_aliases():
    obj = _Obj("malware", 1, name="ROOTSAW", aliases=["EnvyScout", "X"])
    terms = _evidence_terms(obj)
    assert "ROOTSAW" in terms
    assert "EnvyScout" in terms
    assert "X" not in terms


def test_terms_include_file_hashes():
    obj = _Obj("file", 1, name="a.exe", hashes={"MD5": "d41d8cd98f00b204e9800998ecf8427e"})
    terms = _evidence_terms(obj)
    assert "a.exe" in terms
    assert "d41d8cd98f00b204e9800998ecf8427e" in terms


def test_terms_drop_short_and_deduplicate():
    obj = _Obj("tool", 1, name="psexec", aliases=["psexec", "ab"])
    terms = _evidence_terms(obj)
    assert terms == ["psexec"]


def test_terms_for_object_without_type_is_empty():
    class _NoType:
        pass
    obj = _NoType()
    terms = _evidence_terms(obj)
    assert terms == []


# --- _split_sentences ---

def test_split_sentences_basic():
    text = "A one. B two!\n\nC three?"
    parts = _split_sentences(text)
    assert len(parts) == 3
    assert all(p.strip() for p in parts)


def test_split_sentences_empty_and_non_string():
    assert _split_sentences("") == []
    assert _split_sentences(None) == []


# --- _build_sentence_index ---

def test_index_maps_object_to_its_sentences():
    sentences = ["ROOTSAW ran.", "It hit evil.com.", "Nothing here."]
    malware = _Obj("malware", 1, name="ROOTSAW")
    domain = _Obj("domain-name", 1, name="evil.com")
    index = _build_sentence_index([malware, domain], sentences)
    assert index[malware.id] == {0}
    assert index[domain.id] == {1}


def test_index_omits_objects_with_no_terms():
    sentences = ["Some text here."]
    ap = _Obj("attack-pattern", 1, name="Phishing")
    index = _build_sentence_index([ap], sentences)
    assert ap.id not in index


def test_index_is_case_insensitive():
    sentences = ["ROOTSAW ran."]
    malware = _Obj("malware", 1, name="rootsaw")
    index = _build_sentence_index([malware], sentences)
    assert malware.id in index
    assert 0 in index[malware.id]


# --- _pair_is_grounded ---

def test_grounded_cosentence():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("domain-name", 1, name="evil.com")
    index = {src.id: {1}, tgt.id: {1}}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is True
    assert reason == "cosentence"


def test_grounded_within_window():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("domain-name", 1, name="evil.com")
    index = {src.id: {0}, tgt.id: {2}}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is True
    assert reason == "window:2"


def test_not_grounded_beyond_window():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("domain-name", 1, name="evil.com")
    index = {src.id: {0}, tgt.id: {9}}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is False
    assert reason == ""


def test_unanchorable_type_fails_open():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("attack-pattern", 1, name="Phishing")
    index = {src.id: {0}, tgt.id: {999}}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is True
    assert reason == "unanchorable"


def test_object_absent_from_index_fails_open():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("domain-name", 1, name="evil.com")
    index = {src.id: {0}}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is True
    assert reason == "unanchorable"


def test_empty_index_fails_open():
    src = _Obj("malware", 1, name="ROOTSAW")
    tgt = _Obj("domain-name", 1, name="evil.com")
    index = {}
    ok, reason = _pair_is_grounded(src, tgt, index, window=3)
    assert ok is True
    assert reason == "unanchorable"


# --- _materialise_pinned_edges ---

def test_cartesian_mode_emits_every_pair():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    m2 = _Obj("malware", 2, name="TRICKBOT")
    d1 = _Obj("domain-name", 1, name="evil.com")
    d2 = _Obj("domain-name", 2, name="far.example")
    stix_objects = [m1, m2, d1, d2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cartesian"},
        "rules": [
            {"src": "malware", "verb": "communicates-with", "tgt": "domain-name", "mode": "pin", "enabled": True}
        ],
    }
    report_text = "Some unrelated text."
    stats = _materialise_pinned_edges(stix_objects, policy, set(), report_text)
    rule = next(r for r in stats.rules if r.rule == "malware communicates-with domain-name")
    assert rule.candidates == 4
    assert rule.blocked == 0


def test_no_report_text_disables_the_gate():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    m2 = _Obj("malware", 2, name="TRICKBOT")
    d1 = _Obj("domain-name", 1, name="evil.com")
    d2 = _Obj("domain-name", 2, name="far.example")
    stix_objects = [m1, m2, d1, d2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cooccurrence"},
        "rules": [
            {"src": "malware", "verb": "communicates-with", "tgt": "domain-name", "mode": "pin", "enabled": True}
        ],
    }
    stats = _materialise_pinned_edges(stix_objects, policy, set(), "")
    rule = next(r for r in stats.rules if r.rule == "malware communicates-with domain-name")
    assert rule.candidates == 4
    assert rule.blocked == 0


def test_cooccurrence_blocks_unlinked_pairs():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    d1 = _Obj("domain-name", 1, name="evil.com")
    d2 = _Obj("domain-name", 2, name="far.example")
    stix_objects = [m1, d1, d2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cooccurrence"},
        "rules": [
            {"src": "malware", "verb": "communicates-with", "tgt": "domain-name", "mode": "pin", "enabled": True}
        ],
    }
    report_text = "ROOTSAW contacted evil.com today. " + ("Filler sentence here. " * 10) + "Then far.example appeared."
    stats = _materialise_pinned_edges(stix_objects, policy, set(), report_text)
    rule = next(r for r in stats.rules if r.rule == "malware communicates-with domain-name")
    assert rule.candidates == 1
    assert rule.blocked == 1
    assert stats.total_blocked == 1


def test_attack_pattern_rule_is_not_gated():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    m2 = _Obj("malware", 2, name="TRICKBOT")
    ap1 = _Obj("attack-pattern", 1, name="T1566")
    ap2 = _Obj("attack-pattern", 2, name="T1059")
    stix_objects = [m1, m2, ap1, ap2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cooccurrence"},
        "rules": [
            {"src": "malware", "verb": "uses", "tgt": "attack-pattern", "mode": "pin", "enabled": True}
        ],
    }
    report_text = "Some text that does not mention these patterns."
    stats = _materialise_pinned_edges(stix_objects, policy, set(), report_text)
    rule = next(r for r in stats.rules if r.rule == "malware uses attack-pattern")
    assert rule.candidates == 4
    assert rule.blocked == 0


def test_blocked_is_reported_separately_from_truncated():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    d1 = _Obj("domain-name", 1, name="evil.com")
    d2 = _Obj("domain-name", 2, name="far.example")
    stix_objects = [m1, d1, d2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cooccurrence"},
        "rules": [
            {"src": "malware", "verb": "communicates-with", "tgt": "domain-name", "mode": "pin", "enabled": True}
        ],
    }
    report_text = "ROOTSAW contacted evil.com today. " + ("Filler sentence here. " * 10) + "Then far.example appeared."
    stats = _materialise_pinned_edges(stix_objects, policy, set(), report_text)
    rule = next(r for r in stats.rules if r.rule == "malware communicates-with domain-name")
    assert rule.truncated == 0
    assert rule.blocked == 1


def test_emitted_edges_carry_x_pin_evidence():
    m1 = _Obj("malware", 1, name="ROOTSAW")
    d1 = _Obj("domain-name", 1, name="evil.com")
    d2 = _Obj("domain-name", 2, name="far.example")
    stix_objects = [m1, d1, d2]
    policy = {
        "max_pinned_edges": 100,
        "pin_evidence": {"mode": "cooccurrence"},
        "rules": [
            {"src": "malware", "verb": "communicates-with", "tgt": "domain-name", "mode": "pin", "enabled": True}
        ],
    }
    report_text = "ROOTSAW contacted evil.com today. " + ("Filler sentence here. " * 10) + "Then far.example appeared."
    stats = _materialise_pinned_edges(stix_objects, policy, set(), report_text)
    assert stats.total_emitted >= 1
    found = False
    for obj in stix_objects:
        if hasattr(obj, "get"):
            val = obj.get("x_pin_evidence")
            if val is not None:
                found = True
                break
    assert found


def test_to_dict_reports_blocked():
    rule_stat = PinRuleStat(rule="a", candidates=0, emitted=0, truncated=0, blocked=5)
    stats = PinStats(budget=100, mode="cooccurrence", rules=[rule_stat])
    d = stats.to_dict()
    # A rule blocked in full must stay visible in the report, not vanish
    # because its candidate count reached zero.
    assert [r["rule"] for r in d["rules"]] == ["a"]
    assert d["rules"][0]["blocked"] == 5
    assert d["total_blocked"] == 5
