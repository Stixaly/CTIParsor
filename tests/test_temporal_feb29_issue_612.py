"""#612 -- _year_candidate gives up too early on a Feb 29 without year.

When the anchor year is not a leap year, "February 29" does not parse in the
anchor year, and the previous year (a leap year) must still be tried.
"""
from __future__ import annotations

from pipeline.temporal import Anchor, normalize

A_LEAP = Anchor(value="2024-06-17", source="publication_meta", publication_grade="high")
A_NONLEAP = Anchor(value="2025-03-01", source="publication_meta", publication_grade="high")


def test_feb29_leap_anchor_proposes_same_year():
    r = normalize("february 29", anchor=A_LEAP)
    assert r.alternatives == ["2024-02-29"]


def test_feb29_nonleap_anchor_falls_back_to_previous_leap_year():
    r = normalize("february 29", anchor=A_NONLEAP)
    assert r.status == "unresolved"
    assert r.reason == "year_from_context"
    assert r.alternatives == ["2024-02-29"]


def test_march5_nonleap_anchor_unchanged():
    # 2025-03-05 is after the 2025-03-01 anchor, so the previous year is used.
    r = normalize("march 5", anchor=A_NONLEAP)
    assert r.status == "unresolved"
    assert r.reason == "year_from_context"
    assert r.alternatives == ["2024-03-05"]


def test_normal_case_current_year_still_preferred():
    # Date in the anchor year is not after publication: no fallback needed.
    r = normalize("june 14", anchor=A_LEAP)
    assert r.alternatives == ["2024-06-14"]
