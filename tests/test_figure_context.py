"""Surrounding document text may reach the prompt — and must never leave it.

MM-AttacKG's ablation (arXiv:2506.16968, Table 3) measures the gain: removing
both context sources drops entity F1 from 0.7716 to 0.7022. The risk it creates
is that the model transcribes the context as though it had read it off the
image, which is what `test_context_block_forbids_copying_into_verbatim_text`
guards.
"""
from __future__ import annotations

from pipeline.figure_store import _cache_key
from pipeline.stage1f_figures import FigureCandidate, _context_bands
from pipeline.vlm import PROMPT, PROMPT_VERSION, prompt_with_context


def test_no_context_returns_the_bare_prompt():
    """A caller that passes nothing must get exactly today's prompt."""
    assert prompt_with_context() == PROMPT


def test_whitespace_is_not_context():
    assert prompt_with_context("   ", "  \n ") == PROMPT


def test_page_text_is_appended_after_the_prompt():
    out = prompt_with_context(page_text="ACME report body")
    assert out.startswith(PROMPT)
    assert "ACME report body" in out


def test_global_context_is_appended_after_the_prompt():
    out = prompt_with_context(global_context="Operation Silk Parasite")
    assert out.startswith(PROMPT)
    assert "Operation Silk Parasite" in out


def test_context_block_forbids_copying_into_verbatim_text():
    """The load-bearing test.

    Handing the model page text invites it to transcribe that text as if it had
    been read off the image, which would inject report prose into `report_text`
    a second time inside a figure block. The prohibition must be explicit.
    """
    out = prompt_with_context(page_text="some surrounding prose")
    assert "verbatim_text" in out
    assert "NEVER" in out


def test_page_text_is_truncated():
    long_text = "a" * 5000
    out = prompt_with_context(page_text=long_text)
    # The prompt carries a bounded slice, not the whole page.
    assert "a" * 1200 in out
    assert "a" * 1201 not in out
    assert "[…]" in out


def test_global_context_is_truncated():
    out = prompt_with_context(global_context="b" * 5000)
    assert "b" * 600 in out
    assert "b" * 601 not in out


def test_cache_key_without_context_is_the_crop_hash():
    """The empty default has to reproduce the old key exactly."""
    assert _cache_key("abc123", "") == "abc123"


def test_cache_key_separates_two_contexts():
    """Two pages' context around one crop are two different answers."""
    base = _cache_key("abc123", "")
    one = _cache_key("abc123", "ctx-one")
    two = _cache_key("abc123", "ctx-two")
    assert one != base
    assert two != base
    assert one != two


def test_prompt_version_was_bumped_for_the_new_contract():
    """Reads cached against the context-free prompt answered another question."""
    assert PROMPT_VERSION == 2


def test_two_figures_on_one_page_get_different_context(monkeypatch):
    """The band is per figure, not per page.

    The first implementation read the whole page. On a stored web capture that
    is 18 371 characters holding 18 figures, so every figure was handed the same
    site navigation menu and none got the prose that introduces it.
    """
    class _Page:
        width, height = 600.0, 3000.0

        def __init__(self):
            self.cropped: list[tuple] = []

        def crop(self, bbox):
            self.cropped.append(bbox)
            page = self

            class _C:
                def extract_text(self_inner):
                    return f"text near y={page.cropped[-1][1]:.0f}"
            return _C()

    class _Pdf:
        def __init__(self):
            self.pages = [_Page()]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber.open", lambda p: _Pdf())

    top = FigureCandidate(page=1, bbox=(0.0, 400.0, 500.0, 600.0), area_ratio=0.1)
    bottom = FigureCandidate(page=1, bbox=(0.0, 2000.0, 500.0, 2200.0), area_ratio=0.1)
    bands = _context_bands("x.pdf", [top, bottom])

    assert len(bands) == 2
    assert bands[0] != bands[1], "two figures on one page must not share a context"


def test_context_band_is_clamped_to_the_page(monkeypatch):
    """A figure at the very top must not ask for negative coordinates."""
    seen: list[tuple] = []

    class _Page:
        width, height = 600.0, 800.0

        def crop(self, bbox):
            seen.append(bbox)

            class _C:
                def extract_text(self_inner):
                    return ""
            return _C()

    class _Pdf:
        pages = [_Page()]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("pipeline.stage1f_figures.pdfplumber.open", lambda p: _Pdf())
    _context_bands("x.pdf", [FigureCandidate(page=1, bbox=(0.0, 10.0, 500.0, 780.0), area_ratio=0.9)])

    assert seen, "the band was never requested"
    x0, top, x1, bottom = seen[0]
    assert top >= 0.0
    assert bottom <= 800.0
