# tests/test_figure_store.py
from __future__ import annotations

import pytest

from pipeline.figure_store import (
    SqliteReadCache,
    figure_at_offset,
    load_spans,
    read_from_json,
    read_to_json,
    save_spans,
)
from pipeline.stage1f_figures import FigureSpan
from pipeline.vlm import FigureEdge, FigureRead


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point api.db at a throwaway database, for real, for this test only.

    `get_conn()` caches its connection in thread-local storage, so patching
    DB_PATH alone does nothing once anything has already connected: the first
    version of this fixture ran every test against the project's real
    `cti_stix.db`, which is why `jobs.id` collided on the second insert.  The
    cached handle has to be dropped on the way in AND on the way out.
    """
    import api.db as db

    def _drop_cached_conn() -> None:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            del db._local.conn

    _drop_cached_conn()
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    yield
    _drop_cached_conn()


def _read(
    kind: str = "screenshot",
    text: list[str] | None = None,
    edges: list[FigureEdge] | None = None,
    iocs: list[str] | None = None,
    error: str | None = None,
) -> FigureRead:
    return FigureRead(
        kind=kind,
        verbatim_text=text or [],
        edges=edges or [],
        iocs=iocs or [],
        provider="test",
        model="test-model",
        elapsed_s=1.23,
        input_tokens=100,
        output_tokens=200,
        error=error,
    )


def test_read_round_trips_through_json():
    edges = [FigureEdge(src="A", dst="B", label="calls")]
    iocs = ["ioc1", "ioc2"]
    original = _read(text=["line1", "line2"], edges=edges, iocs=iocs)
    raw = read_to_json(original)
    restored = read_from_json(raw)
    assert restored is not None
    assert restored.kind == original.kind
    assert restored.verbatim_text == original.verbatim_text
    assert restored.edges == original.edges
    assert restored.iocs == original.iocs
    assert restored.provider == original.provider
    assert restored.model == original.model
    assert restored.elapsed_s == original.elapsed_s
    assert restored.input_tokens == original.input_tokens
    assert restored.output_tokens == original.output_tokens
    assert restored.error == original.error


def test_read_from_json_preserves_non_ascii():
    original = _read(text=["Привіт"])
    raw = read_to_json(original)
    restored = read_from_json(raw)
    assert restored is not None
    assert restored.verbatim_text == ["Привіт"]


def test_read_from_json_returns_none_on_garbage():
    assert read_from_json("not json") is None


def test_read_from_json_repairs_wrong_types():
    raw = '{"kind": "screenshot", "verbatim_text": "string", "edges": ["string"]}'
    restored = read_from_json(raw)
    assert restored is not None
    assert restored.verbatim_text == []
    assert restored.edges == []


def test_cache_put_then_get_returns_the_read():
    cache = SqliteReadCache()
    original = _read(text=["hello"])
    cache.put("sha1", "model1", 1, original)
    restored = cache.get("sha1", "model1", 1)
    assert restored is not None
    assert restored.kind == original.kind
    assert restored.verbatim_text == original.verbatim_text


def test_cache_get_misses_on_a_different_prompt_version():
    cache = SqliteReadCache()
    original = _read(text=["hello"])
    cache.put("sha1", "model1", 1, original)
    assert cache.get("sha1", "model1", 2) is None


def test_cache_never_stores_an_unread():
    cache = SqliteReadCache()
    unread = _read(kind="unread")
    cache.put("sha1", "model1", 1, unread)
    assert cache.get("sha1", "model1", 1) is None


def test_cache_ignores_an_empty_sha():
    cache = SqliteReadCache()
    original = _read(text=["hello"])
    cache.put("", "model1", 1, original)
    assert cache.get("", "model1", 1) is None


def test_save_spans_then_load_spans_round_trips():
    from api.db import get_conn, now_iso

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, "
            "updated_at) VALUES ('j1', 'x.pdf', 'uploaded', ?, ?)",
            (now_iso(), now_iso()),
        )

    spans = [
        FigureSpan(
            ordinal=1,
            page=1,
            bbox=(1.0,
            2.0,
            3.0,
            4.0),
            kind="chart",
            char_start=0,
            char_end=100,
            model="m",
            sha256="s1",
        ),
        FigureSpan(
            ordinal=2,
            page=2,
            bbox=(5.0,
            6.0,
            7.0,
            8.0),
            kind="table",
            char_start=200,
            char_end=300,
            model="m",
            sha256="s2",
        ),
    ]
    count = save_spans("j1", spans, "provider1")
    assert count == 2

    loaded = load_spans("j1")
    assert len(loaded) == 2
    assert loaded[0].ordinal == 1
    assert loaded[0].page == 1
    assert loaded[0].kind == "chart"
    assert loaded[0].char_start == 0
    assert loaded[0].char_end == 100
    assert all(abs(a - b) < 0.01 for a, b in zip(loaded[0].bbox, (1.0, 2.0, 3.0, 4.0)))

    assert loaded[1].ordinal == 2
    assert loaded[1].page == 2
    assert loaded[1].kind == "table"
    assert loaded[1].char_start == 200
    assert loaded[1].char_end == 300
    assert all(abs(a - b) < 0.01 for a, b in zip(loaded[1].bbox, (5.0, 6.0, 7.0, 8.0)))


def test_save_spans_replaces_a_previous_run():
    from api.db import get_conn, now_iso

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, "
            "updated_at) VALUES ('j1', 'x.pdf', 'uploaded', ?, ?)",
            (now_iso(), now_iso()),
        )

    spans1 = [
        FigureSpan(
            ordinal=1,
            page=1,
            bbox=(1.0,
            2.0,
            3.0,
            4.0),
            kind="chart",
            char_start=0,
            char_end=100,
            model="m",
            sha256="s1",
        ),
        FigureSpan(
            ordinal=2,
            page=2,
            bbox=(5.0,
            6.0,
            7.0,
            8.0),
            kind="table",
            char_start=200,
            char_end=300,
            model="m",
            sha256="s2",
        ),
        FigureSpan(
            ordinal=3,
            page=3,
            bbox=(9.0,
            10.0,
            11.0,
            12.0),
            kind="image",
            char_start=400,
            char_end=500,
            model="m",
            sha256="s3",
        ),
    ]
    save_spans("j1", spans1, "provider1")

    spans2 = [
        FigureSpan(
            ordinal=1,
            page=1,
            bbox=(1.0,
            2.0,
            3.0,
            4.0),
            kind="chart",
            char_start=0,
            char_end=100,
            model="m",
            sha256="s1",
        ),
    ]
    save_spans("j1", spans2, "provider1")

    loaded = load_spans("j1")
    assert len(loaded) == 1
    assert loaded[0].ordinal == 1


def test_figure_at_offset_finds_the_containing_span():
    from api.db import get_conn, now_iso

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, "
            "updated_at) VALUES ('j1', 'x.pdf', 'uploaded', ?, ?)",
            (now_iso(), now_iso()),
        )

    spans = [
        FigureSpan(
            ordinal=1,
            page=1,
            bbox=(1.0,
            2.0,
            3.0,
            4.0),
            kind="chart",
            char_start=10,
            char_end=20,
            model="m",
            sha256="s1",
        ),
    ]
    save_spans("j1", spans, "provider1")

    found_10 = figure_at_offset("j1", 10)
    assert found_10 is not None
    assert found_10.ordinal == 1

    found_19 = figure_at_offset("j1", 19)
    assert found_19 is not None
    assert found_19.ordinal == 1


def test_figure_at_offset_returns_none_outside_any_span():
    from api.db import get_conn, now_iso

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, "
            "updated_at) VALUES ('j1', 'x.pdf', 'uploaded', ?, ?)",
            (now_iso(), now_iso()),
        )

    spans = [
        FigureSpan(
            ordinal=1,
            page=1,
            bbox=(1.0,
            2.0,
            3.0,
            4.0),
            kind="chart",
            char_start=10,
            char_end=20,
            model="m",
            sha256="s1",
        ),
    ]
    save_spans("j1", spans, "provider1")

    assert figure_at_offset("j1", 20) is None
    assert figure_at_offset("j1", 5) is None
