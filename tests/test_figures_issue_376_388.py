"""Issues #376 and #388: off-page figure boxes, and the separator and names of injected figures."""
from __future__ import annotations

import types

from pipeline.stage1f_figures import (
    CLOSE,
    OPEN,
    FigureCandidate,
    find_figures,
    inject_append,
    render_block,
    render_edges,
)
from pipeline.vlm import FigureEdge, FigureRead


class _Page:
    """A pdfplumber page: only width, height and images are read."""

    def __init__(self, width: float, height: float, images: list[dict]) -> None:
        self.width = width
        self.height = height
        self.images = images


class _PDF:
    def __init__(self, pages: list[_Page]) -> None:
        self.pages = pages

    def __enter__(self) -> _PDF:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


def _fake_pdfplumber(pages: list[_Page]):
    return types.SimpleNamespace(open=lambda path: _PDF(pages))


def _read(kind: str = "screenshot", text: list[str] | None = None,
          edges: list[FigureEdge] | None = None) -> FigureRead:
    return FigureRead(
        kind=kind,
        verbatim_text=["line one"] if text is None else text,
        edges=edges or [],
        iocs=[],
        provider="x",
        model="m",
        elapsed_s=0.0,
        error=None,
    )


def _cand(page: int = 1) -> FigureCandidate:
    return FigureCandidate(page=page, bbox=(0, 0, 100, 100), area_ratio=0.1)


# --- #376: an image off the page is not a figure candidate -------------------

def test_image_wholly_right_of_the_page_is_not_a_candidate_issue_376(monkeypatch):
    """x0 beyond the right edge clamps to an inverted box, which must be dropped."""
    page = _Page(800, 1000, [{"x0": 850, "x1": 1000, "top": 100, "bottom": 400}])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_image_wholly_left_of_the_page_is_not_a_candidate_issue_376(monkeypatch):
    """x1 left of the page clamps to a box with negative x; it must be dropped too."""
    page = _Page(800, 1000, [{"x0": -200, "x1": -50, "top": 100, "bottom": 400}])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_image_wholly_below_the_page_is_not_a_candidate_issue_376(monkeypatch):
    """The same rule holds vertically."""
    page = _Page(800, 1000, [{"x0": 100, "x1": 300, "top": 1100, "bottom": 1400}])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    assert find_figures("x.pdf") == []


def test_image_partly_off_the_page_keeps_its_clamped_box_issue_376(monkeypatch):
    """Control: an image that only overhangs the edge is still a figure, clipped to the page."""
    page = _Page(800, 1000, [{"x0": 700, "x1": 900, "top": 100, "bottom": 300}])
    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber", _fake_pdfplumber([page]))
    cands = find_figures("x.pdf")
    assert [(c.page, c.bbox) for c in cands] == [(1, (700.0, 100.0, 800, 300.0))]


# --- #388: the separator before an injected figure ----------------------------

def test_inject_append_adds_one_blank_line_to_text_without_a_trailing_newline_issue_388():
    text, spans = inject_append("alpha", [(_cand(), _read(), "sha1")])
    assert text.startswith("alpha\n\n" + OPEN)
    assert spans[0].char_start == len("alpha\n\n")


def test_inject_append_adds_one_newline_to_text_ending_in_a_newline_issue_388():
    """A text ending in one newline gets one more, not two: a single blank line."""
    text, spans = inject_append("alpha\n", [(_cand(), _read(), "sha1")])
    assert text.startswith("alpha\n\n" + OPEN)
    assert not text.startswith("alpha\n\n\n")
    assert spans[0].char_start == len("alpha\n\n")


def test_inject_append_adds_nothing_to_text_ending_in_a_blank_line_issue_388():
    text, spans = inject_append("alpha\n\n", [(_cand(), _read(), "sha1")])
    assert text.startswith("alpha\n\n" + OPEN)
    assert not text.startswith("alpha\n\n\n")
    assert spans[0].char_start == len("alpha\n\n")


def test_inject_append_spans_point_at_the_sentinels_for_every_base_issue_388():
    """Offsets must stay exact whatever the separator added, for each figure."""
    reads = [
        (_cand(page=1), _read(text=["first"]), "sha1"),
        (_cand(page=2), _read(kind="table", text=["second"]), "sha2"),
    ]
    for base in ["alpha", "alpha\n", "alpha\n\n"]:
        text, spans = inject_append(base, reads)
        assert text.startswith(base)
        for span, (_, read, _) in zip(spans, reads, strict=True):
            assert text[span.char_start] == OPEN
            assert text[span.char_end - 1] == CLOSE
            assert text[span.char_start:span.char_end] == render_block(span.ordinal, read)


def test_inject_append_separates_two_blocks_by_one_blank_line_issue_388():
    reads = [
        (_cand(page=1), _read(text=["first"]), "sha1"),
        (_cand(page=2), _read(text=["second"]), "sha2"),
    ]
    text, spans = inject_append("alpha\n", reads)
    assert text[spans[0].char_end:spans[1].char_start] == "\n\n"


def test_inject_append_on_empty_text_puts_no_separator_issue_388():
    text, spans = inject_append("", [(_cand(), _read(), "sha1")])
    assert spans[0].char_start == 0
    assert text.startswith(OPEN)


# --- #388: a name wrapped across lines stays on its arrow's line ------------

def test_render_edges_turns_a_newline_inside_a_name_into_a_space_issue_388():
    read = _read(kind="attack-chain", edges=[FigureEdge("Stage\nA", "B", "x")])
    assert render_edges(read) == ["Stage A -> B (x)"]


def test_render_edges_collapses_a_wrapped_name_in_either_end_issue_388():
    read = _read(kind="network-diagram",
                 edges=[FigureEdge("  C2\n\n server ", "dropper\r\nhost", "")])
    assert render_edges(read) == ["C2 server -> dropper host"]


def test_render_block_keeps_a_wrapped_name_on_one_arrow_line_issue_388():
    read = _read(kind="attack-chain", edges=[FigureEdge("Stage\nA", "B", "")])
    lines = render_block(1, read).split("\n")
    assert "Stage A -> B" in lines
