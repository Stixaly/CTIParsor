from __future__ import annotations

import hashlib

import pytest

from pipeline.stage1f_figures import (
    CLOSE,
    MAX_EDGES_PER_FIGURE,
    OPEN,
    FigureCandidate,
    inject,
    inject_append,
    map_verbatim,
    read_figures,
    render_block,
    render_edges,
)
from pipeline.vlm import PROMPT, PROMPT_VERSION, FigureEdge, FigureRead


def _read(kind: str = "screenshot", text: list[str] | None = None,
          provider: str = "x", model: str = "m",
          error: str | None = None) -> FigureRead:
    """Construct a FigureRead for testing."""
    if text is None:
        text = ["line one", "line two"]
    return FigureRead(
        kind=kind,
        verbatim_text=text,
        edges=[],
        iocs=[],
        provider=provider,
        model=model,
        elapsed_s=0.0,
        error=error
    )


class _Backend:
    name = "fake"
    model = "m"
    max_concurrency = 2

    def __init__(self, reads: list[FigureRead]):
        self.reads = list(reads)
        self.calls = 0
        self.prompts: list[str] = []

    def available(self) -> bool:
        return True

    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead:
        # Mirrors the real signature exactly.  The first version defaulted to
        # None, so read_figures passing None looked fine here and sent a null
        # prompt to the API in production.
        self.calls += 1
        assert isinstance(prompt, str) and prompt, 'prompt must be a non-empty str'
        self.prompts.append(prompt)
        return self.reads.pop(0)


class _Cache:
    def __init__(self, seed: dict[tuple[str, str, int], FigureRead] | None = None):
        self.store = dict(seed or {})
        self.puts: list[tuple[str, str, int, FigureRead]] = []

    # `context_sha` defaults to "" so these fixtures keep keying on the crop
    # alone, which is what they are about; the real cache folds it in.
    def get(self, sha: str, model: str, pv: int, context_sha: str = "") -> FigureRead | None:
        return self.store.get((sha, model, pv))

    def put(self, sha: str, model: str, pv: int, read: FigureRead,
            context_sha: str = "") -> None:
        self.puts.append((sha, model, pv, read))


def test_render_block_wraps_verbatim_text_between_sentinels() -> None:
    read = _read(kind="screenshot", text=["line one", "line two"])
    block = render_block(1, read)
    assert block.startswith(OPEN)
    assert block.endswith(CLOSE)
    assert "line one" in block
    assert "line two" in block


def test_render_block_is_empty_for_a_logo() -> None:
    read = _read(kind="logo")
    block = render_block(1, read)
    # Extract body between first CLOSE and last OPEN
    first_close = block.index(CLOSE)
    last_open = block.rindex(OPEN)
    body = block[first_close + 1:last_open]
    assert body == "\n"


def test_render_block_is_empty_for_an_unread_figure() -> None:
    read = _read(kind="unread")
    block = render_block(1, read)
    first_close = block.index(CLOSE)
    last_open = block.rindex(OPEN)
    body = block[first_close + 1:last_open]
    assert body == "\n"
    assert "unread" in block


def test_render_block_neutralises_sentinels_inside_the_body() -> None:
    read = _read(kind="screenshot", text=[f"{OPEN}bad{CLOSE}", "normal"])
    block = render_block(1, read)
    assert block.count(OPEN) == 2
    assert block.count(CLOSE) == 2
    assert "[" in block
    assert "]" in block


def test_inject_places_a_figure_after_its_own_page() -> None:
    page_texts = ["page one text", "page two text"]
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    read = _read(kind="screenshot")
    reads = [(cand, read, "sha1")]
    text, spans = inject(page_texts, reads)
    page1_idx = text.index("page one text")
    page2_idx = text.index("page two text")
    fig_idx = text.index(OPEN)
    assert page1_idx < fig_idx < page2_idx


def test_inject_spans_point_at_the_sentinels() -> None:
    page_texts = ["text"]
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    read = _read(kind="screenshot")
    reads = [(cand, read, "sha1")]
    text, spans = inject(page_texts, reads)
    for span in spans:
        assert text[span.char_start] == OPEN
        assert text[span.char_end - 1] == CLOSE


def test_inject_numbers_ordinals_from_one_across_pages() -> None:
    page_texts = ["p1", "p2"]
    cand1 = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    cand2 = FigureCandidate(page=2, bbox=(0, 0, 100, 100), area_ratio=0.1)
    cand3 = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    reads = [
        (cand1, _read(kind="screenshot"), "sha1"),
        (cand2, _read(kind="screenshot"), "sha2"),
        (cand3, _read(kind="screenshot"), "sha3"),
    ]
    text, spans = inject(page_texts, reads)
    ordinals = [s.ordinal for s in spans]
    assert ordinals == [1, 2, 3]


def test_inject_never_emits_three_consecutive_newlines() -> None:
    page_texts = ["", "text"]
    cand = FigureCandidate(page=2, bbox=(0, 0, 100, 100), area_ratio=0.1)
    read = _read(kind="screenshot")
    reads = [(cand, read, "sha1")]
    text, _ = inject(page_texts, reads)
    assert "\n\n\n" not in text


def test_inject_appends_a_figure_whose_page_is_out_of_range() -> None:
    page_texts = ["text"]
    cand = FigureCandidate(page=9, bbox=(0, 0, 100, 100), area_ratio=0.1)
    read = _read(kind="screenshot")
    reads = [(cand, read, "sha1")]
    text, spans = inject(page_texts, reads)
    assert OPEN in text
    assert len(spans) == 1
    span = spans[0]
    assert text[span.char_start] == OPEN
    assert text[span.char_end - 1] == CLOSE


def test_read_figures_serves_a_cached_read_without_calling_the_backend(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    png = b"png-1"
    sha = hashlib.sha256(png).hexdigest()
    cached_read = _read(kind="screenshot")
    cache = _Cache(seed={(sha, "m", PROMPT_VERSION): cached_read})
    backend = _Backend([])

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [cand])
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", lambda p, c, dpi=150: png)

    results = read_figures("fake.pdf", backend, cache=cache)
    assert backend.calls == 0
    assert len(results) == 1
    assert results[0][1] is cached_read


def test_read_figures_does_not_cache_an_unread_result(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    png = b"png-1"
    sha = hashlib.sha256(png).hexdigest()
    unread_read = _read(kind="unread")
    cache = _Cache()
    backend = _Backend([unread_read])

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [cand])
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", lambda p, c, dpi=150: png)

    results = read_figures("fake.pdf", backend, cache=cache)
    assert len(cache.puts) == 0
    # Use the values rather than dropping them: the figure must survive as an
    # unread row carrying its real sha, so a later run can retry the same crop.
    assert len(results) == 1
    assert results[0][1].kind == "unread"
    assert results[0][2] == sha


def test_read_figures_preserves_candidate_order(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    cands = [
        FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=2, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=3, bbox=(0, 0, 100, 100), area_ratio=0.1),
    ]
    reads = [_read(kind="screenshot") for _ in range(3)]
    backend = _Backend(reads)

    def fake_render(p: str, c: FigureCandidate, dpi: int = 150) -> bytes:
        return f"png-{c.page}".encode()

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: cands)
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    results = read_figures("fake.pdf", backend)
    shas = [r[2] for r in results]
    expected_shas = [hashlib.sha256(f"png-{c.page}".encode()).hexdigest() for c in cands]
    assert shas == expected_shas


def test_read_figures_keeps_a_figure_whose_crop_failed(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    cands = [
        FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=2, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=3, bbox=(0, 0, 100, 100), area_ratio=0.1),
    ]
    reads = [_read(kind="screenshot") for _ in range(2)]
    backend = _Backend(reads)

    def fake_render(p: str, c: FigureCandidate, dpi: int = 150) -> bytes:
        if c.page == 2:
            raise RuntimeError("crop failed")
        return f"png-{c.page}".encode()

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: cands)
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    results = read_figures("fake.pdf", backend)
    assert len(results) == 3
    assert results[1][1].kind == "unread"
    assert results[1][2] == ""
    assert "render" in results[1][1].error


def test_read_figures_truncates_to_max_figures(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    cands = [
        FigureCandidate(page=i, bbox=(0, 0, 100, 100), area_ratio=0.1)
        for i in range(1, 6)
    ]
    reads = [_read(kind="screenshot") for _ in range(5)]
    backend = _Backend(reads)

    def fake_render(p: str, c: FigureCandidate, dpi: int = 150) -> bytes:
        return f"png-{c.page}".encode()

    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: cands)
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", fake_render)

    results = read_figures("fake.pdf", backend, max_figures=2)
    assert len(results) == 2
    assert backend.calls == 2


def test_inject_separates_consecutive_pages() -> None:
    """Two pages with no figure between them must not be glued together.

    The first implementation appended page texts with no separator at all, so
    the last token of one page ran into the first of the next.  The existing
    placement test passed anyway — it only checked ordering — which is why this
    one asserts the separator itself.
    """
    text, spans = inject(["alpha", "beta", "gamma"], [])
    assert text == "alpha\nbeta\ngamma"
    assert spans == []


def test_inject_append_keeps_the_document_text_intact() -> None:
    """The default placement must not touch a single character of the source.

    Locked because the alternative — weaving figures into per-page pdfplumber
    text — costs 18.2% of characters on this corpus, and on one report the five
    observables that vanished were all SHA-256 hashes broken by a wrapped table
    column.
    """
    base = "prose line one\nprose line two"
    cand = FigureCandidate(page=7, bbox=(0, 0, 100, 100), area_ratio=0.1)
    text, spans = inject_append(base, [(cand, _read(kind="screenshot"), "sha1")])
    assert text.startswith(base)
    assert len(spans) == 1
    assert spans[0].page == 7
    assert text[spans[0].char_start] == OPEN
    assert text[spans[0].char_end - 1] == CLOSE


def test_inject_append_orders_blocks_by_reads_not_by_page() -> None:
    cands = [
        FigureCandidate(page=9, bbox=(0, 0, 100, 100), area_ratio=0.1),
        FigureCandidate(page=2, bbox=(0, 0, 100, 100), area_ratio=0.1),
    ]
    reads = [(c, _read(kind="screenshot"), f"sha{i}") for i, c in enumerate(cands)]
    text, spans = inject_append("prose", reads)
    assert [s.ordinal for s in spans] == [1, 2]
    assert [s.page for s in spans] == [9, 2]
    assert spans[0].char_start < spans[1].char_start


def test_inject_append_handles_empty_document_text() -> None:
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    text, spans = inject_append("", [(cand, _read(kind="screenshot"), "sha1")])
    assert text.startswith(OPEN)
    assert spans[0].char_start == 0


def test_read_figures_sends_the_real_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backend must receive a string prompt, not None.

    read_figures submitted `backend.read_figure, png, None` to the executor.
    The API rejected every call with
    `messages.0.content.1.text.text: Input should be a valid string`, and the
    unit tests passed throughout because the fake backend's own default was None.
    """
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    backend = _Backend([_read(kind="screenshot")])
    monkeypatch.setattr("pipeline.stage1f_figures.find_figures", lambda p: [cand])
    monkeypatch.setattr("pipeline.stage1f_figures.render_crop", lambda p, c, dpi=150: b"png")

    read_figures("fake.pdf", backend)
    assert backend.prompts == [PROMPT]


def test_map_verbatim_rewrites_every_line() -> None:
    """Figure text must be refangable before the block is rendered.

    Order is load-bearing: refang turns "[.]" into "." and so shortens the text,
    so a span computed before it runs would point at the wrong characters.
    """
    cand = FigureCandidate(page=1, bbox=(0, 0, 100, 100), area_ratio=0.1)
    reads = [(cand, _read(text=["evil[.]com", "safe"]), "sha1")]
    mapped = map_verbatim(reads, lambda s: s.replace("[.]", "."))
    assert mapped[0][1].verbatim_text == ["evil.com", "safe"]
    # The originals are frozen dataclasses and must not have been mutated.
    assert reads[0][1].verbatim_text == ["evil[.]com", "safe"]
    assert mapped[0][0] is cand and mapped[0][2] == "sha1"


def test_map_verbatim_keeps_every_other_field() -> None:
    cand = FigureCandidate(page=3, bbox=(0, 0, 100, 100), area_ratio=0.1)
    original = _read(kind="code-listing", text=["x"])
    mapped = map_verbatim([(cand, original, "s")], str.upper)[0][1]
    assert mapped.kind == original.kind
    assert mapped.model == original.model
    assert mapped.provider == original.provider


def _edge_read(kind: str = "attack-chain", edges=None, text=None) -> FigureRead:
    return FigureRead(
        kind=kind,
        verbatim_text=text if text is not None else ["Figure 5. Sideloading"],
        edges=edges or [],
        iocs=[],
        provider="x",
        model="m",
        elapsed_s=0.0,
    )


def test_render_edges_emits_one_line_per_arrow() -> None:
    read = _edge_read(edges=[
        FigureEdge("MpDefenderCoreService.exe", "mpclient.dll", "1"),
        FigureEdge("mpclient.dll", "DriveSilkRAT", "2"),
    ])
    assert render_edges(read) == [
        "MpDefenderCoreService.exe -> mpclient.dll",
        "mpclient.dll -> DriveSilkRAT",
    ]


def test_render_edges_drops_numeric_step_labels() -> None:
    """Diagram numbering is step order, not a relationship verb."""
    read = _edge_read(edges=[FigureEdge("a", "b", "3")])
    assert render_edges(read) == ["a -> b"]


def test_render_edges_keeps_a_meaningful_label() -> None:
    read = _edge_read(edges=[FigureEdge("implant", "1.2.3.4", "exfiltrates to")])
    assert render_edges(read) == ["implant -> 1.2.3.4 (exfiltrates to)"]


def test_render_edges_is_silent_on_non_diagram_kinds() -> None:
    """The one measured invention was a screenshot montage read as a flow."""
    read = _edge_read(kind="screenshot", edges=[FigureEdge("chat", "window", "")])
    assert render_edges(read) == []


def test_render_edges_dedupes_and_drops_self_loops() -> None:
    read = _edge_read(edges=[
        FigureEdge("a", "b", ""),
        FigureEdge("a", "b", ""),
        FigureEdge("c", "c", ""),
        FigureEdge("", "d", ""),
    ])
    assert render_edges(read) == ["a -> b"]


def test_render_edges_caps_a_runaway_topology() -> None:
    read = _edge_read(edges=[FigureEdge(f"n{i}", f"n{i+1}", "") for i in range(100)])
    assert len(render_edges(read)) == MAX_EDGES_PER_FIGURE


def test_render_block_carries_the_arrows_into_the_text() -> None:
    read = _edge_read(edges=[FigureEdge("ebook-edit.exe", "calibre-launcher.dll", "1")])
    block = render_block(5, read)
    assert "ebook-edit.exe -> calibre-launcher.dll" in block
    assert block.startswith(OPEN)
    assert block.endswith(CLOSE)


def test_render_block_arrow_survives_refang_and_normalisation() -> None:
    """The rendered arrow must reach report_text byte for byte.

    Stage 3 quotes it and evidence_span.resolve_span has to find that quote, so
    neither refang nor the offset-preserving normaliser may touch it.
    """
    from pipeline.evidence_span import locate
    from pipeline.stage2_extraction import refang

    read = _edge_read(edges=[FigureEdge("node.exe", "update.js", "2")])
    block = render_block(11, read)
    text = "prose before\n\n" + refang(block) + "\n\nprose after"
    quote = "node.exe -> update.js"
    assert quote in text
    span = locate(quote, text)
    assert span is not None
    assert text[span.start:span.end] == quote
