"""Issue #982 point 6: a figure answer whose figure_kind is outside the contract is
not a reading.  It stays unread, is never cached, is retried on the next run and
is counted apart from the figures read."""
from __future__ import annotations

import hashlib
import logging

import pytest

from pipeline.stage1f_figures import (
    FigureCandidate,
    count_unexpected_kind,
    read_figures,
)
from pipeline.vlm import PROMPT, PROMPT_VERSION, FigureRead, _to_read


def _data(kind) -> dict:
    """A model answer; `kind` is the figure_kind it gives (None = key absent)."""
    data = {"verbatim_text": ["line one"], "edges": [], "iocs": []}
    if kind is not None:
        data["figure_kind"] = kind
    return data


def _read(kind: str = "screenshot", unexpected_kind: bool = False) -> FigureRead:
    return FigureRead(
        kind=kind,
        verbatim_text=["line one"],
        edges=[],
        iocs=[],
        provider="x",
        model="m",
        elapsed_s=0.0,
        unexpected_kind=unexpected_kind,
    )


class _Backend:
    name = "fake"
    model = "m"
    max_concurrency = 1

    def __init__(self, reads: list[FigureRead]):
        self.reads = list(reads)
        self.calls = 0

    def available(self) -> bool:
        return True

    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead:
        self.calls += 1
        return self.reads.pop(0)


class _Cache:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str, int], FigureRead] = {}
        self.puts: list[tuple[str, str, int, FigureRead]] = []

    def get(self, sha: str, model: str, pv: int, context_sha: str = "") -> FigureRead | None:
        return self.store.get((sha, model, pv))

    def put(self, sha: str, model: str, pv: int, read: FigureRead,
            context_sha: str = "") -> None:
        self.puts.append((sha, model, pv, read))
        self.store[(sha, model, pv)] = read


def _one_figure(monkeypatch: pytest.MonkeyPatch, png: bytes) -> FigureCandidate:
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [cand])
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", lambda p, c, dpi=150: png)
    return cand


def test_an_unknown_kind_comes_back_unread_and_flagged() -> None:
    r = _to_read(_data("diagram-of-doom"), "p", "m", 0.0, None, None)
    assert r.kind == "unread"
    assert r.unexpected_kind is True
    assert r.verbatim_text == []
    assert r.error == "unexpected figure_kind 'diagram-of-doom'"


def test_a_missing_kind_is_unexpected_too() -> None:
    r = _to_read(_data(None), "p", "m", 0.0, None, None)
    assert r.kind == "unread"
    assert r.unexpected_kind is True


def test_a_kind_that_is_not_a_string_is_unexpected() -> None:
    r = _to_read(_data(["chart"]), "p", "m", 0.0, None, None)
    assert r.kind == "unread"
    assert r.unexpected_kind is True


def test_the_unexpected_kind_is_logged_truncated_to_40_characters(
    caplog: pytest.LogCaptureFixture,
) -> None:
    long_kind = "x" * 100
    with caplog.at_level(logging.WARNING, logger="pipeline.vlm"):
        _to_read(_data(long_kind), "p", "m", 0.0, None, None)
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(messages) == 1
    assert repr(long_kind)[:40] in messages[0]
    assert long_kind not in messages[0]


def test_a_valid_kind_is_still_a_reading() -> None:
    r = _to_read(_data("chart"), "p", "m", 0.0, None, None)
    assert r.kind == "chart"
    assert r.unexpected_kind is False
    assert r.verbatim_text == ["line one"]


def test_an_unexpected_read_is_not_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    png = b"png-1"
    _one_figure(monkeypatch, png)
    cache = _Cache()
    backend = _Backend([_to_read(_data("diagram-of-doom"), "p", "m", 0.0, None, None)])

    results = read_figures("fake.pdf", backend, cache=cache)

    assert cache.puts == []
    assert len(results) == 1
    assert results[0][1].kind == "unread"
    assert results[0][2] == hashlib.sha256(png).hexdigest()


def test_an_unexpected_figure_is_asked_again_on_the_next_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    png = b"png-1"
    _one_figure(monkeypatch, png)
    cache = _Cache()
    bad = _to_read(_data("diagram-of-doom"), "p", "m", 0.0, None, None)
    good = _read(kind="chart")
    backend = _Backend([bad, good])

    first = read_figures("fake.pdf", backend, cache=cache)
    second = read_figures("fake.pdf", backend, cache=cache)

    assert first[0][1].kind == "unread"
    assert backend.calls == 2
    assert second[0][1].kind == "chart"
    assert len(cache.puts) == 1


def test_a_valid_read_is_cached_as_before(monkeypatch: pytest.MonkeyPatch) -> None:
    png = b"png-1"
    sha = hashlib.sha256(png).hexdigest()
    _one_figure(monkeypatch, png)
    cache = _Cache()
    backend = _Backend([_read(kind="chart")])

    results = read_figures("fake.pdf", backend, cache=cache)

    assert len(cache.puts) == 1
    key_sha, model, pv, stored = cache.puts[0]
    assert (key_sha, model, pv) == (sha, "m", PROMPT_VERSION)
    assert stored.kind == "chart"
    assert results[0][1].kind == "chart"


def test_only_the_unexpected_reads_are_counted_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    cands = [
        FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=1, bbox=(0, 200, 100, 300), area_ratio=0.1),
        FigureCandidate(page=1, bbox=(0, 400, 100, 500), area_ratio=0.1),
    ]
    pngs = iter([b"png-a", b"png-b", b"png-c"])
    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: cands)
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop",
                        lambda p, c, dpi=150: next(pngs))
    # One backend call per figure, in order: a valid read, an unexpected one, a logo.
    backend = _Backend([
        _read(kind="chart"),
        _to_read(_data("diagram-of-doom"), "p", "m", 0.0, None, None),
        _read(kind="logo"),
    ])

    results = read_figures("fake.pdf", backend, cache=None)

    reads = [r for _, r, _ in results]
    assert count_unexpected_kind(results) == 1
    assert sum(1 for r in reads if r.kind != "unread") == 2
