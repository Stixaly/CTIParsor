"""ADR-0063 — relationship dates keep what the source said.

Contract tests (the ADR's "A" cases): code only, a fixed model answer and a
fixed anchor.  The model's behaviour (the "B" cases) is measured on the
in-house set, not asserted here.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from pipeline.temporal import (
    Anchor,
    DocumentTime,
    TemporalAssertion,
    analyst_assertion,
    check_assertions,
    choose_anchor,
    export_mode,
    export_plan,
    header_candidates,
    legacy_assertions,
    locate,
    mark_conflicts,
    merge_times,
    normalize,
    publication_candidates,
    times_from_json,
    times_to_json,
    window,
)

PUBLISHED = Anchor(value="2024-06-15", source="publication_meta")
PRINTED = Anchor(value="2026-09-01", source="file_metadata")


def _llm(role, text, value=None, **kw):
    return TemporalAssertion(role=role, time_text=text, model_value=value, **kw)


def _verified(role, value, precision, **kw):
    return TemporalAssertion(role=role, value=value, precision=precision, status="verified", **kw)


def _check(chunk, *times, anchor=None, evidence=None):
    doc = DocumentTime.build(chunk, anchor)
    return check_assertions(list(times), chunk, document=doc, evidence_text=evidence)


# ── reading one expression ───────────────────────────────────────────────────

@pytest.mark.parametrize("text,value,precision,qualifier", [
    ("in 2021", "2021", "year", "none"),
    ("since March 2023", "2023-03", "month", "none"),
    ("on 12 March 2023", "2023-03-12", "day", "none"),
    ("March 12, 2023", "2023-03-12", "day", "none"),
    ("Monday, 25 April 2022", "2022-04-25", "day", "none"),
    ("2023-03", "2023-03", "month", "none"),
    ("mid-2025", "2025", "year", "mid"),
    ("early 2023", "2023", "year", "early"),
    ("late March 2023", "2023-03", "month", "late"),
    ("around March 2023", "2023-03", "month", "approx"),
    ("Q3 2023", "2023-35", "quarter", "none"),
    ("the first half of 2023", "2023-40", "half", "none"),
    ("17/04/2023", "2023-04-17", "day", "none"),
    ("depuis mars 2023", "2023-03", "month", "none"),
    ("le 1er mars 2023", "2023-03-01", "day", "none"),
])
def test_an_expression_keeps_the_precision_the_source_gives(text, value, precision, qualifier):
    r = normalize(text)
    assert (r.value, r.precision, r.qualifier, r.status) == (value, precision, qualifier, "verified")


def test_nothing_is_padded():
    assert normalize("2021").value == "2021"
    assert normalize("March 2023").value == "2023-03"


def test_an_instant_keeps_its_offset():
    r = normalize("2023-06-20T14:32:00+02:00")
    assert (r.value, r.precision) == ("2023-06-20T14:32:00+02:00", "instant")


@pytest.mark.parametrize("role,value", [("start", "2026-01"), ("end", "2026-04"),
                                        ("within", "2026-01/2026-04")])
def test_a_range_gives_each_role_its_end(role, value):
    assert normalize("between January and April 2026", role=role).value == value


def test_a_day_range_borrows_month_and_year():
    assert normalize("du 3 au 5 mars 2023", role="start").value == "2023-03-03"


@pytest.mark.parametrize("text,reason", [
    ("31 February 2023", "invalid_date"),
    ("on 12 March", "year_from_context"),
    ("in March", "year_from_context"),
    ("sometime last spring", "unparsed"),
    ("in 1850", "implausible_year"),
])
def test_what_cannot_be_read_is_unresolved_never_guessed(text, reason):
    r = normalize(text)
    assert (r.value, r.status, r.reason) == (None, "unresolved", reason)


def test_a8_numeric_order_unknown_is_ambiguous():
    r = normalize("03/04/2023")
    assert (r.value, r.status, r.reason) == (None, "ambiguous", "numeric_order")
    assert sorted(r.alternatives) == ["2023-03-04", "2023-04-03"]


# ── relative expressions and the anchor ──────────────────────────────────────

@pytest.mark.parametrize("text,value", [
    ("last month", "2024-05"), ("this year", "2024"), ("last year", "2023"),
    ("three days ago", "2024-06-12"), ("a year ago", "2023"), ("last July", "2023-07"),
    ("over the past six months", "2023-12/2024-06"), ("le mois dernier", "2024-05"),
    ("since last month", "2024-05"),
])
def test_a14_a_publication_date_resolves_relative_expressions(text, value):
    r = normalize(text, anchor=PUBLISHED)
    assert (r.value, r.status, r.anchored) == (value, "verified", True)


def test_a15_a_file_timestamp_never_resolves_last_month():
    r = normalize("last month", anchor=PRINTED)
    assert (r.value, r.status, r.reason, r.alternatives) == (
        None, "unresolved", "weak_anchor", ["2026-08"])


def test_a16_no_anchor_is_unresolved_never_today():
    r = normalize("last month")
    assert (r.value, r.status, r.reason) == (None, "unresolved", "no_anchor")


# ── locating the quote ───────────────────────────────────────────────────────

def test_a5_a_year_inside_an_identifier_is_not_found():
    assert locate("2021", "It exploited CVE-2021-44228 last year.") == ([], "boundary")
    assert locate("2021", "Build v1.2021 shipped.") == ([], "boundary")


def test_a7_typography_folds_digits_never_do():
    spans, _ = locate("March 2023", "Active since March 2023.")
    assert spans == [(13, 23)]
    assert locate("2023", "copied from OCR: 2O23.") == ([], "not_found")


def test_a_letter_quote_after_a_hyphen_is_found():
    """"mid-March 2023" quoted as "March 2023" is still that date."""
    spans, reason = locate("March 2023", "Seen in mid-March 2023 by us.")
    assert spans and reason is None


# ── the check: status computed, never taken ──────────────────────────────────

def test_a2_a_month_is_verified_at_month_precision():
    (a,) = _check("The actor used Foo since March 2023.", _llm("start", "since March 2023"))
    assert (a.value, a.precision, a.status, a.anchor) == ("2023-03", "month", "verified", "explicit")


def test_a6_the_models_reading_contradicting_the_quote_is_a_conflict():
    (a,) = _check("Active since March 2023.", _llm("start", "since March 2023", "2023-04"))
    assert (a.status, a.reason) == ("conflict", "value_mismatch")


def test_a_padded_model_reading_is_compatible():
    (a,) = _check("Active since March 2023.", _llm("start", "since March 2023", "2023-03-01"))
    assert a.status == "verified"


def test_a7_an_ocr_quote_found_but_unreadable():
    (a,) = _check("copied from OCR: 2O23.", _llm("within", "2O23"))
    assert (a.status, a.reason) == ("unresolved", "unparsed")


def test_a_quote_not_in_the_chunk_is_a_conflict():
    (a,) = _check("Nothing dated here.", _llm("start", "since 2020"))
    assert (a.status, a.reason) == ("conflict", "not_found")


def test_a8_agreement_never_lifts_an_ambiguous_reading():
    (a,) = _check("The activity started on 03/04/2023.",
                  _llm("start", "on 03/04/2023", "2023-03-04"))
    assert (a.status, a.value) == ("ambiguous", None)


def test_a9_a_homogeneous_passage_fixes_the_order():
    chunk = "Date | Event\n17/04/2023 | first beacon\n03/04/2023 | initial access"
    (a,) = _check(chunk, _llm("start", "03/04/2023"))
    assert (a.status, a.value) == ("verified", "2023-04-03")


def test_a9_a_hint_in_another_passage_does_not_carry_over():
    chunk = "Logs: 17/04/2023 shows the beacon.\n\nThe activity started on 03/04/2023."
    (a,) = _check(chunk, _llm("start", "on 03/04/2023"))
    assert a.status == "ambiguous"


def test_a9_contradictory_hints_leave_it_ambiguous():
    chunk = "17/04/2023 and 04/17/2023 both appear; it started on 03/04/2023."
    (a,) = _check(chunk, _llm("start", "on 03/04/2023"))
    assert a.status == "ambiguous"


def test_a19_a_status_supplied_by_the_model_is_recomputed():
    (a,) = _check("Active since March 2023.",
                  _llm("start", "since March 2023", status="conflict", reason="made up"))
    assert (a.status, a.reason) == ("verified", None)


def test_the_occurrence_nearest_the_evidence_is_the_one_placed():
    chunk = "In 2021 we saw nothing.\n\nAPT29 used Foo in 2021 against banks."
    (a,) = _check(chunk, _llm("within", "in 2021"),
                  evidence="APT29 used Foo in 2021 against banks.")
    assert a.doc_offset == DocumentTime.build(chunk, None).folded_text.find("in 2021 against")


def test_analyst_and_legacy_assertions_pass_through_the_check():
    mine = analyst_assertion("start", "2023-03")
    (a,) = check_assertions([mine], "unrelated text")
    assert a == mine


# ── consistency ──────────────────────────────────────────────────────────────

def test_a1_equal_coarse_bounds_are_compatible():
    out = mark_conflicts([_verified("start", "2021", "year"), _verified("end", "2021", "year")])
    assert [a.status for a in out] == ["verified", "verified"]


def test_a10_an_end_before_the_start_marks_both():
    out = mark_conflicts([_verified("start", "2023-06", "month"), _verified("end", "2023-03", "month")])
    assert [(a.status, a.reason) for a in out] == [("conflict", "contradicts")] * 2


def test_two_incompatible_starts_contradict_each_other():
    out = mark_conflicts([_verified("start", "2021", "year"), _verified("start", "2024", "year")])
    assert {a.status for a in out} == {"conflict"}


def test_an_analyst_bound_supersedes_the_models_in_the_consistency_check():
    out = mark_conflicts([_verified("start", "2021", "year"),
                          analyst_assertion("start", "2024")])
    assert [a.status for a in out] == ["verified", "verified"]


# ── merge ────────────────────────────────────────────────────────────────────

def test_a11_two_different_years_stay_two_assertions():
    doc_a = _check("Foo was used in 2021.", _llm("within", "in 2021"))
    doc_b = _check("Foo was used in 2024.", _llm("within", "in 2024"))
    merged = merge_times(doc_a, doc_b)
    assert sorted(a.value for a in merged) == ["2021", "2024"]


def test_a12_one_occurrence_seen_through_two_overlapping_chunks_is_one_assertion():
    document = "Intro paragraph.\n\nThe actor used Foo since March 2023.\n\nMore text follows here."
    doc = DocumentTime.build(document, None)
    first = check_assertions([_llm("start", "since March 2023")],
                             "Intro paragraph.\n\nThe actor used Foo since March 2023.", document=doc)
    second = check_assertions([_llm("start", "since March 2023")],
                              "The actor used Foo since March 2023.\n\nMore text follows here.",
                              document=doc)
    assert first[0].doc_offset == second[0].doc_offset is not None
    assert len(merge_times(first, second)) == 1


def test_the_same_quote_twice_in_the_document_is_two_occurrences():
    document = "Foo ran since March 2023 in Asia.\n\nFoo ran since March 2023 in Europe."
    doc = DocumentTime.build(document, None)
    a = check_assertions([_llm("start", "since March 2023")], document.split("\n\n")[0],
                         document=doc, evidence_text="Foo ran since March 2023 in Asia.")
    b = check_assertions([_llm("start", "since March 2023")], document.split("\n\n")[1],
                         document=doc, evidence_text="Foo ran since March 2023 in Europe.")
    assert a[0].doc_offset != b[0].doc_offset
    assert len(merge_times(a, b)) == 2


def test_merging_never_builds_a_span():
    merged = merge_times([_verified("within", "2021", "year")], [_verified("within", "2024", "year")])
    assert all("/" not in (a.value or "") for a in merged)


# ── export ───────────────────────────────────────────────────────────────────

def _decision(plan, role):
    return next(d for d in plan.decisions if d["role"] == role)


def test_a2_faithful_withholds_a_month():
    plan = export_plan([_verified("start", "2023-03", "month")])
    assert plan.start_time is None
    assert (_decision(plan, "start")["outcome"], _decision(plan, "start")["reason"]) == (
        "withheld", "precision_below_policy")


@pytest.mark.parametrize("mode,expected", [
    ("faithful", None),
    ("day", datetime(2023, 3, 12, tzinfo=timezone.utc)),
])
def test_a3_a_day_is_projected_only_on_request(mode, expected):
    plan = export_plan([_verified("start", "2023-03-12", "day")], mode)
    assert plan.start_time == expected


def test_a4_a_day_end_covers_the_whole_day():
    plan = export_plan([_verified("end", "2023-06-20", "day")], "day")
    assert plan.stop_time == datetime(2023, 6, 20, 23, 59, 59, 999000, tzinfo=timezone.utc)
    assert _decision(plan, "end")["outcome"] == "projected"
    assert plan.assertions[0]["projection"] == "day"


def test_a17_an_instant_ships_in_utc_under_faithful():
    plan = export_plan([_verified("start", "2023-06-20T14:32:00+02:00", "instant")])
    assert plan.start_time == datetime(2023, 6, 20, 12, 32, tzinfo=timezone.utc)
    assert plan.assertions[0]["native"] == "start_time"


def test_an_instant_without_an_offset_is_withheld():
    plan = export_plan([_verified("start", "2023-06-20T14:32:00", "instant")])
    assert (plan.start_time, _decision(plan, "start")["reason"]) == (None, "no_offset")


def test_a18_equal_instants_give_no_native_pair():
    t = "2023-06-20T14:32:00+00:00"
    plan = export_plan([_verified("start", t, "instant"), _verified("end", t, "instant")])
    assert (plan.start_time, plan.stop_time) == (None, None)
    assert {d["reason"] for d in plan.decisions} == {"equal_bounds"}


def test_a10_a_conflict_blocks_both_bounds():
    times = mark_conflicts([_verified("start", "2023-06-01T00:00:00+00:00", "instant"),
                            _verified("end", "2023-03-01T00:00:00+00:00", "instant")])
    plan = export_plan(times)
    assert (plan.start_time, plan.stop_time) == (None, None)


@pytest.mark.parametrize("role", ["within", "throughout", "observed"])
def test_windows_never_fill_a_native_bound(role):
    plan = export_plan([_verified(role, "2023-06-20T14:32:00+00:00", "instant")], "day")
    assert (plan.start_time, plan.stop_time) == (None, None)
    assert plan.decisions[0]["reason"] == "window_role"


@pytest.mark.parametrize("label", ["gap", "inferred"])
def test_a_weakly_supported_date_is_withheld(label):
    plan = export_plan([_verified("start", "2023-06-20T14:32:00+00:00", "instant",
                                  evidence_label=label)])
    assert (plan.start_time, plan.decisions[0]["reason"]) == (None, "evidence_label")


def test_a_qualified_date_is_never_projected():
    plan = export_plan([_verified("start", "2023-03-12", "day", qualifier="approx")], "day")
    assert (plan.start_time, plan.decisions[0]["reason"]) == (None, "qualified")


def test_the_most_precise_compatible_bound_wins():
    plan = export_plan([_verified("start", "2023-03-12", "day"),
                        _verified("start", "2023-03-12T08:00:00+00:00", "instant")], "day")
    assert plan.start_time == datetime(2023, 3, 12, 8, tzinfo=timezone.utc)
    assert sorted(d["outcome"] for d in plan.decisions) == ["exported", "withheld"]


def test_an_analyst_bound_supersedes_the_models_at_export():
    plan = export_plan([_verified("start", "2021-05-01T00:00:00+00:00", "instant"),
                        analyst_assertion("start", "2022-01-10T00:00:00Z")])
    assert plan.start_time == datetime(2022, 1, 10, tzinfo=timezone.utc)
    reasons = {d.get("reason") for d in plan.decisions}
    assert "superseded_by_analyst" in reasons


def test_every_assertion_ships_in_the_extension_without_the_models_reading():
    plan = export_plan([_llm("start", "since March 2023", "2023-03"),
                        _verified("within", "2021", "year")])
    assert len(plan.assertions) == 2
    assert all("model_value" not in a for a in plan.assertions)


@pytest.mark.parametrize("policy,mode", [
    (None, "faithful"), ({}, "faithful"), ({"temporal_export": {}}, "faithful"),
    ({"temporal_export": {"mode": "day"}}, "day"),
    ({"temporal_export": {"mode": "envelope"}}, "faithful"),
])
def test_the_default_mode_is_faithful(policy, mode):
    assert export_mode(policy) == mode


# ── analyst entry, legacy rows, storage ──────────────────────────────────────

@pytest.mark.parametrize("raw,value,precision", [
    ("2023", "2023", "year"), ("2023-03", "2023-03", "month"),
    ("2023-03-12", "2023-03-12", "day"), ("March 2023", "2023-03", "month"),
    ("2023-06-20T14:32:00Z", "2023-06-20T14:32:00+00:00", "instant"),
])
def test_an_analyst_keeps_the_precision_they_typed(raw, value, precision):
    a = analyst_assertion("start", raw)
    assert (a.value, a.precision, a.status, a.origin) == (value, precision, "verified", "analyst")


@pytest.mark.parametrize("raw", ["03/04/2023", "last month", "whenever", ""])
def test_an_analyst_entry_that_is_not_a_date_is_refused(raw):
    with pytest.raises(ValueError):
        analyst_assertion("start", raw)


def test_a_legacy_row_is_never_reinterpreted():
    (a,) = legacy_assertions("2022-01-01T00:00:00+00:00", None)
    assert (a.value, a.precision, a.status, a.reason, a.origin) == (
        "2022-01-01T00:00:00+00:00", None, "unresolved", "legacy", "legacy")
    assert export_plan([a]).start_time is None


def test_storage_round_trip():
    times = [_verified("start", "2023-03", "month"), analyst_assertion("end", "2024")]
    assert times_from_json(times_to_json(times)) == times
    assert times_to_json([]) is None
    assert times_from_json("not json") == []
    assert times_from_json('[{"role": "nonsense"}]') == []


@pytest.mark.parametrize("value,lo,hi", [
    ("2023", datetime(2023, 1, 1), datetime(2024, 1, 1)),
    ("2023-12", datetime(2023, 12, 1), datetime(2024, 1, 1)),
    ("2023-35", datetime(2023, 7, 1), datetime(2023, 10, 1)),
    ("2023-41", datetime(2023, 7, 1), datetime(2024, 1, 1)),
    ("2023-03-12", datetime(2023, 3, 12), datetime(2023, 3, 13)),
    ("2023-01/2023-03", datetime(2023, 1, 1), datetime(2023, 4, 1)),
])
def test_windows(value, lo, hi):
    assert window(value) == (lo, hi)


# ── the document anchor ──────────────────────────────────────────────────────

def test_a_keyed_header_line_is_a_publication_candidate():
    (c,) = header_candidates("Blog\nPosted by Erik on Monday, 25 April 2022 10:35 (UTC)\nBody")
    assert (c["value"], c["source"], c["kind"]) == ("2022-04-25", "text_header", "published")


def test_a_bare_date_line_near_the_top_is_a_weaker_candidate():
    (c,) = header_candidates("Cloud Blog\nThreat Intelligence\nSeptember 1, 2026\nBody text.")
    assert (c["value"], c["kind"]) == ("2026-09-01", "date_line")


def test_date_inside_a_word_is_not_a_key():
    assert header_candidates("The candidate list, compiled 12 March 2023 by us, follows.") == []


def test_publication_candidates_from_page_metadata():
    got = publication_candidates(
        [("article:published_time", "2024-06-15T09:00:00+02:00"),
         ("article:modified_time", "2024-07-01T00:00:00Z"), ("og:title", "irrelevant")],
        ['{"@graph": [{"@type": "Article", "datePublished": "2024-06-14"}]}', "not json"],
        [("datePublished", "2024-06-15"), ("", "2019-01-01")],
    )
    assert sorted((c["value"], c["kind"]) for c in got) == [
        ("2024-06-14", "published"), ("2024-06-15", "published"),
        ("2024-06-15", "published"), ("2024-07-01", "updated")]


def test_the_anchor_prefers_page_metadata_then_header_then_file():
    cands = [{"value": "2026-09-01", "source": "file_metadata", "kind": "created"},
             {"value": "2024-06-20", "source": "text_header", "kind": "date_line"},
             {"value": "2024-06-15", "source": "text_header", "kind": "published"},
             {"value": "2024-07-01", "source": "publication_meta", "kind": "updated"},
             {"value": "2024-06-14", "source": "publication_meta", "kind": "published"}]
    anchor = choose_anchor(cands)
    assert (anchor.value, anchor.source) == ("2024-06-14", "publication_meta")
    assert len(anchor.candidates) == 5
    assert choose_anchor(cands[:1]).publication_grade is False
    assert choose_anchor([]) is None
