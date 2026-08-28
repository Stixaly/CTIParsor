"""Figure ordinals must follow reading order, not read-completion order."""
from __future__ import annotations

import hashlib

from pipeline.stage1f_figures import (
    CLOSE,
    OPEN,
    FigureCandidate,
    inject_append,
    read_figures,
)
from pipeline.vlm import FigureRead


def _read(kind: str = "network-diagram", *lines: str) -> FigureRead:
    """A FigureRead carrying the given transcribed lines."""
    return FigureRead(
        kind=kind,
        verbatim_text=list(lines),
        edges=[],
        iocs=[],
        provider="fake",
        model="fake-1",
        elapsed_s=0.0,
    )


class _Backend:
    """A vision backend that answers with the line it is told to."""

    name = "fake"
    model = "fake-1"
    max_concurrency = 4

    def __init__(self, answers: dict[bytes, FigureRead]) -> None:
        self.answers = answers

    def read_figure(self, png: bytes) -> FigureRead:
        return self.answers[png]


class _Cache:
    """A read cache pre-loaded with answers for chosen crops."""

    def __init__(self, hits: dict[str, FigureRead]) -> None:
        self.hits = hits

    def get(self, sha256, model, prompt_version):
        return self.hits.get(sha256)

    def put(self, sha256, model, prompt_version, read):
        pass


def test_cached_figure_does_not_jump_ahead_of_an_earlier_one(monkeypatch):
    """A cached figure must not jump ahead of an earlier one on the same page."""
    # BUG: read_figures builds results in two passes — cache hits first, then
    # parallel reads in thread-arrival order — and sorts only by `page`.
    # Python's stable sort preserves that construction order for same-page items,
    # so a cached figure (added first) ends up before a higher-positioned one.
    # The cache makes this deterministic: no sleeps, no thread races.
    c_top = FigureCandidate(page=1, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)
    c_bottom = FigureCandidate(page=1, bbox=(50.0, 500.0, 400.0, 700.0), area_ratio=0.2)

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [c_top, c_bottom])

    def fake_render(pdf_path, cand, dpi=150):
        return b"TOP" if cand.bbox[1] < 300.0 else b"BOTTOM"

    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    bottom_sha = hashlib.sha256(b"BOTTOM").hexdigest()
    cache = _Cache({bottom_sha: _read("network-diagram", "bottom figure")})
    backend = _Backend({b"TOP": _read("network-diagram", "top figure")})

    reads = read_figures("x.pdf", backend, cache=cache)

    assert [c for c, _, _ in reads] == [c_top, c_bottom]
    assert reads[0][1].verbatim_text[0] == "top figure"


def test_ordinals_follow_reading_order_on_one_page(monkeypatch):
    """Ordinal 1 must be the figure highest on the page."""
    c_top = FigureCandidate(page=1, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)
    c_bottom = FigureCandidate(page=1, bbox=(50.0, 500.0, 400.0, 700.0), area_ratio=0.2)

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [c_top, c_bottom])

    def fake_render(pdf_path, cand, dpi=150):
        return b"TOP" if cand.bbox[1] < 300.0 else b"BOTTOM"

    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    bottom_sha = hashlib.sha256(b"BOTTOM").hexdigest()
    cache = _Cache({bottom_sha: _read("network-diagram", "bottom figure")})
    backend = _Backend({b"TOP": _read("network-diagram", "top figure")})

    reads = read_figures("x.pdf", backend, cache=cache)
    text, spans = inject_append("Report body.", reads)

    assert [s.ordinal for s in spans] == [1, 2]
    assert spans[0].bbox == c_top.bbox
    assert spans[1].bbox == c_bottom.bbox


def test_pages_are_ordered_before_position(monkeypatch):
    """Page number takes precedence over vertical position within a page."""
    c_p2_top = FigureCandidate(page=2, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)
    c_p1_bot = FigureCandidate(page=1, bbox=(50.0, 500.0, 400.0, 700.0), area_ratio=0.2)
    c_p1_top = FigureCandidate(page=1, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)

    monkeypatch.setattr(
        "pipeline.stage1f_figures.find_figures",
        lambda p: [c_p2_top, c_p1_bot, c_p1_top],
    )

    def fake_render(pdf_path, cand, dpi=150):
        return b"X"

    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    backend = _Backend({b"X": _read("network-diagram", "x")})
    cache = _Cache({})

    reads = read_figures("x.pdf", backend, cache=cache)
    assert [c for c, _, _ in reads] == [c_p1_top, c_p1_bot, c_p2_top]


def test_spans_delimit_their_own_block(monkeypatch):
    """Each span's char range must enclose exactly its own figure block."""
    c_top = FigureCandidate(page=1, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)
    c_bottom = FigureCandidate(page=1, bbox=(50.0, 500.0, 400.0, 700.0), area_ratio=0.2)

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [c_top, c_bottom])

    def fake_render(pdf_path, cand, dpi=150):
        return b"TOP" if cand.bbox[1] < 300.0 else b"BOTTOM"

    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    bottom_sha = hashlib.sha256(b"BOTTOM").hexdigest()
    cache = _Cache({bottom_sha: _read("network-diagram", "bottom figure")})
    backend = _Backend({b"TOP": _read("network-diagram", "top figure")})

    reads = read_figures("x.pdf", backend, cache=cache)
    text, spans = inject_append("Report body.", reads)

    # Invariant on which every offset-based search depends.
    for span in spans:
        block = text[span.char_start : span.char_end]
        assert block.startswith(OPEN)
        assert block.endswith(CLOSE)
        assert f"figure {span.ordinal} " in block


def test_span_offsets_do_not_overlap(monkeypatch):
    """Consecutive spans must not overlap in character space."""
    c_top = FigureCandidate(page=1, bbox=(50.0, 100.0, 400.0, 300.0), area_ratio=0.2)
    c_bottom = FigureCandidate(page=1, bbox=(50.0, 500.0, 400.0, 700.0), area_ratio=0.2)

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [c_top, c_bottom])

    def fake_render(pdf_path, cand, dpi=150):
        return b"TOP" if cand.bbox[1] < 300.0 else b"BOTTOM"

    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    bottom_sha = hashlib.sha256(b"BOTTOM").hexdigest()
    cache = _Cache({bottom_sha: _read("network-diagram", "bottom figure")})
    backend = _Backend({b"TOP": _read("network-diagram", "top figure")})

    reads = read_figures("x.pdf", backend, cache=cache)
    _, spans = inject_append("Report body.", reads)

    ordered = sorted(spans, key=lambda s: s.char_start)
    for a, b in zip(ordered, ordered[1:]):
        assert a.char_end <= b.char_start
