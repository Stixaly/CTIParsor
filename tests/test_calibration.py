"""Calibrated NER cutoffs (ADR-0051) — the fit, the selection rule, the store.

The isotonic fit and the proposal rule are exercised on synthetic samples whose
answer is known by construction; the database half runs on the isolated
`temp_db` fixture (SQLite, or PostgreSQL with CTIPARSOR_TEST_DATABASE_URL).
"""
from __future__ import annotations

from uuid import uuid4

import pipeline.thresholds as thresholds
from pipeline import calibration as cal

# ── Synthetic samples ────────────────────────────────────────────────────────


def _band(lo: int, hi: int, accepted_per_score: int, rejected_per_score: int) -> list[tuple[float, bool]]:
    """(score, accepted) pairs for every score in [lo, hi) hundredths."""
    pts: list[tuple[float, bool]] = []
    for s in range(lo, hi):
        pts += [(s / 100, True)] * accepted_per_score + [(s / 100, False)] * rejected_per_score
    return pts


# 0.40–0.59: half rejected.  0.60–0.89: 95 % accepted.  640 decisions.
_SPLIT_AT_060 = _band(40, 60, 1, 1) + _band(60, 90, 19, 1)


# ── Isotonic fit ─────────────────────────────────────────────────────────────


def test_isotonic_blocks_are_non_decreasing_and_pool_violators():
    # A dip at 0.6 (0 % accepted) between 0.5 (100 %) and 0.7 (100 %) must be
    # pooled with its neighbour(s) so the fit never decreases.
    pts = [(0.4, False), (0.5, True), (0.6, False), (0.7, True), (0.8, True)]
    blocks = cal.isotonic_blocks(pts)
    rates = [b.rate for b in blocks]
    assert rates == sorted(rates)
    assert sum(b.n for b in blocks) == len(pts)
    assert blocks[0].lo == 0.4 and blocks[-1].hi == 0.8


def test_isotonic_blocks_keep_an_already_monotone_sample_apart():
    pts = [(0.4, False), (0.5, True), (0.6, True)]
    blocks = cal.isotonic_blocks(pts)
    assert [(b.lo, b.rate) for b in blocks] == [(0.4, 0.0), (0.5, 1.0), (0.6, 1.0)]


def test_isotonic_blocks_of_nothing_is_nothing():
    assert cal.isotonic_blocks([]) == []
    assert cal.calibrated_rate([], 0.5) is None


def test_calibrated_rate_reads_the_block_a_score_falls_in():
    blocks = cal.isotonic_blocks(_SPLIT_AT_060)
    assert cal.calibrated_rate(blocks, 0.45) == 0.5
    assert cal.calibrated_rate(blocks, 0.75) == 0.95
    assert cal.calibrated_rate(blocks, 0.99) == 0.95     # past the last block


# ── Proposal rule ────────────────────────────────────────────────────────────


def test_proposes_the_lowest_band_that_reaches_the_target():
    p = cal.propose("gliner", "malware", 0.40, _SPLIT_AT_060, target_precision=0.9, min_samples=100)
    assert p.status == "ok"
    assert p.proposed == 0.60
    assert p.unclamped == 0.60
    assert p.sample_size == 640 and p.accepted == 590 and p.rejected == 50
    assert p.precision_at_proposed == 0.95
    assert round(p.recall_at_proposed, 4) == round(570 / 590, 4)
    # The report also says what the cutoff in force delivers today.
    assert round(p.precision_at_current, 4) == round(590 / 640, 4)
    assert p.recall_at_current == 1.0
    assert p.min_score == 0.40 and p.max_score == 0.89


def test_unchanged_when_the_current_cutoff_is_already_the_answer():
    p = cal.propose("gliner", "malware", 0.60, _SPLIT_AT_060, target_precision=0.9, min_samples=100)
    assert p.status == "unchanged"
    assert p.proposed == 0.60


def test_too_few_decisions_propose_nothing_but_still_report():
    p = cal.propose("gliner", "campaign", 0.40, _SPLIT_AT_060[:50], min_samples=200)
    assert p.status == "insufficient_samples"
    assert p.proposed is None
    assert p.sample_size == 50
    assert p.curve, "the fit is still reported so the UI can show the shape"


def test_no_band_reaching_the_target_is_reported_not_forced():
    flat = _band(40, 90, 1, 1)                      # 50 % everywhere
    p = cal.propose("cyner", "malware", 0.70, flat, target_precision=0.9, min_samples=10)
    assert p.status == "target_unreachable"
    assert p.proposed is None and p.unclamped is None


def test_a_cutoff_resting_on_auto_accepted_rows_is_not_proposed():
    # Only the >= 0.90 band — the tier the review UI accepts on its own — is
    # clean.  That is the model's verdict, not the analysts', so keep the
    # number visible but do not apply it.
    pts = _band(40, 90, 1, 1) + _band(90, 100, 20, 0)
    p = cal.propose("cyner", "threat_actor", 0.70, pts, target_precision=0.9, min_samples=10)
    assert p.status == "above_auto_accept"
    assert p.proposed is None
    assert p.unclamped == 0.90


def test_a_lower_auto_accept_level_lets_the_same_cutoff_through():
    pts = _band(40, 90, 1, 1) + _band(90, 100, 20, 0)
    p = cal.propose("cyner", "threat_actor", 0.70, pts, target_precision=0.9, min_samples=10,
                    auto_accept_level=0.95)
    assert p.status == "ok" and p.proposed == 0.90


def test_a_proposal_never_goes_below_a_score_analysts_have_seen():
    # Everything observed is clean, so the target is met from the very first
    # score: the answer is the lowest OBSERVED score, never anything below it.
    clean = _band(55, 90, 5, 0)
    p = cal.propose("gliner", "location", 0.40, clean, target_precision=0.9, min_samples=10)
    assert p.status == "ok"
    assert p.proposed == 0.55 == p.min_score


def test_a_cutoff_is_not_anchored_on_a_handful_of_high_scores():
    # Mostly noise (20 % accepted, 40-79) plus a sparse high tail (three
    # accepted decisions at 0.85 and nothing above -- below AUTO_ACCEPT_LEVEL
    # so that branch doesn't shadow this one). The tail alone clears
    # target_precision and the aggregate sample_size clears min_samples, but
    # only 3 decisions exist AT OR ABOVE 0.85 -- too few to trust as the
    # region a production cutoff now rests its precision on.
    pts = _band(40, 80, 1, 4) + [(0.85, True)] * 3
    p = cal.propose("cyner", "tool", 0.70, pts, target_precision=0.9, min_samples=50)
    assert p.sample_size >= 50           # the aggregate gate alone would have allowed this
    assert p.status == "target_unreachable"
    assert p.proposed is None

    # The same tail, now with enough decisions to back it, is proposed.
    pts_supported = _band(40, 80, 1, 4) + [(0.85, True)] * 25
    p2 = cal.propose("cyner", "tool", 0.70, pts_supported, target_precision=0.9, min_samples=50)
    assert p2.status == "ok"
    assert p2.proposed == 0.85


def test_empty_sample_is_insufficient_and_metric_free():
    p = cal.propose("gliner", "identity", 0.40, [])
    assert p.status == "insufficient_samples"
    assert p.precision_at_current is None and p.curve == []


def test_as_dict_is_json_shaped():
    d = cal.propose("gliner", "malware", 0.40, _SPLIT_AT_060, min_samples=100).as_dict()
    assert d["source"] == "gliner" and d["proposed"] == 0.60
    assert isinstance(d["curve"], list) and {"lo", "hi", "n", "rate"} <= set(d["curve"][0])


# ── Database side ────────────────────────────────────────────────────────────


def _seed(db, job_id: str, rows: list[tuple[str, str, float, int | None]]) -> None:
    conn = db.get_conn()
    now = db.now_iso()
    conn.execute(
        "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) VALUES (?,?,?,?,?)",
        (job_id, f"{job_id}.pdf", "for_review", now, now),
    )
    conn.executemany(
        "INSERT INTO entities (id, job_id, value, entity_type, context, confidence, accepted, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        [(str(uuid4()), job_id, f"e{i}", etype, "", conf, acc, source)
         for i, (source, etype, conf, acc) in enumerate(rows)],
    )
    conn.commit()


def test_calibrate_reads_only_decided_rows_of_calibrated_sources(temp_db):
    rows: list[tuple[str, str, float, int | None]] = []
    rows += [("gliner", "malware", s, int(ok)) for s, ok in _SPLIT_AT_060]
    rows += [("gliner", "malware", 0.45, None)] * 30          # undecided — ignored
    rows += [("gazetteer", "malware", 0.92, 1)] * 30          # not a calibrated source
    rows += [("cyner", "threat_actor", 0.75, 0)] * 5          # decided, but too few
    _seed(temp_db, "job-a", rows)

    proposals = cal.calibrate(temp_db.get_conn(), target_precision=0.9, min_samples=100)
    by_key = {(p.source, p.entity_type): p for p in proposals}
    assert set(by_key) == {("gliner", "malware"), ("cyner", "threat_actor")}
    assert by_key[("gliner", "malware")].sample_size == 640
    assert by_key[("gliner", "malware")].status == "ok"
    assert by_key[("gliner", "malware")].current == 0.40          # the stage default
    assert by_key[("cyner", "threat_actor")].status == "insufficient_samples"


def test_apply_writes_only_proposals_with_a_cutoff_and_the_stage_reads_it_back(temp_db):
    rows = [("gliner", "malware", s, int(ok)) for s, ok in _SPLIT_AT_060]
    rows += [("cyner", "threat_actor", 0.75, 0)] * 5
    _seed(temp_db, "job-b", rows)
    conn = temp_db.get_conn()

    proposals = cal.calibrate(conn, target_precision=0.9, min_samples=100)
    assert cal.apply_proposals(conn, proposals, temp_db.now_iso()) == 1

    stored = cal.list_overrides(conn)
    assert len(stored) == 1
    row = stored[0]
    assert (row["source"], row["entity_type"], row["threshold"]) == ("gliner", "malware", 0.60)
    assert row["sample_size"] == 640 and row["origin"] == "calibrated"
    assert row["precision_at"] == 0.95

    thresholds.reload()
    try:
        assert thresholds.get_threshold("gliner", "malware", 0.40) == 0.60
        assert thresholds.get_threshold("gliner", "campaign", 0.40) == 0.40
        assert thresholds.overrides_for("gliner") == {"malware": 0.60}
    finally:
        thresholds.reload()


def test_recalibrating_reports_against_the_stored_cutoff(temp_db):
    _seed(temp_db, "job-c", [("gliner", "malware", s, int(ok)) for s, ok in _SPLIT_AT_060])
    conn = temp_db.get_conn()
    cal.apply_proposals(conn, cal.calibrate(conn, min_samples=100), temp_db.now_iso())

    again = cal.calibrate(conn, min_samples=100)[0]
    assert again.current == 0.60 and again.status == "unchanged"


def test_manual_override_round_trip(temp_db):
    conn = temp_db.get_conn()
    cal.set_override(conn, "cyner", "malware", 0.85, temp_db.now_iso())
    row = cal.list_overrides(conn)[0]
    assert (row["source"], row["entity_type"], row["threshold"], row["origin"]) == ("cyner", "malware", 0.85, "manual")

    # A second write replaces, never duplicates (the PK is the pair).
    cal.set_override(conn, "cyner", "malware", 0.80, temp_db.now_iso())
    assert [r["threshold"] for r in cal.list_overrides(conn)] == [0.80]

    assert cal.clear_override(conn, "cyner", "malware") is True
    assert cal.clear_override(conn, "cyner", "malware") is False
    assert cal.list_overrides(conn) == []


def test_stage_default_matches_the_stage_constants():
    from pipeline.stage2d_cyner import _MEDIUM_THRESH
    from pipeline.stage2e_gliner import _GLINER_THRESHOLD
    assert cal.stage_default("cyner") == _MEDIUM_THRESH
    assert cal.stage_default("gliner") == _GLINER_THRESHOLD
