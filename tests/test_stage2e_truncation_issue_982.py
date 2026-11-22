"""Stage 2e — chunks GLiNER cut to its token limit are counted, not hidden (issue #982, point 7).

GLiNER warns "Sentence of length N has been truncated to 384" for each chunk it
cuts.  The stage used to hide that warning for the whole process with a global
filter; now each model call counts the warnings it raised, and the run and the
stage note say how many chunks were cut.  The model is stubbed, as in
test_stage2e_gliner.py: SKIP_HEAVY_MODELS loads no GLiNER.
"""
from __future__ import annotations

import warnings

import pytest

from pipeline import stage2e_gliner
from tests.test_stage2e_gliner import _FakeGLiNER, _pred, _two_chunks

_THREE_CHUNKS = ("Emotet spread through the mail again. Qakbot followed it a week later. "
                 "Lazarus came after that too.")


@pytest.fixture(autouse=True)
def _every_entity_type(monkeypatch):
    """The six labels, whatever GLINER_ENTITY_TYPES says in the environment."""
    monkeypatch.setattr(stage2e_gliner, "_GLINER_LABELS", list(stage2e_gliner._LABEL_MAP))


def _truncation_warning(chunks: int) -> None:
    warnings.warn(f"Sentence of length {chunks} has been truncated to 384", UserWarning, stacklevel=2)


class _TruncatingGLiNER(_FakeGLiNER):
    """Answers a batch as _FakeGLiNER does, and warns once for each chunk at a position in *over*,
    as GLiNER does when it cuts a chunk to its token limit."""

    def __init__(self, predictions: list[dict], over: set[int]):
        super().__init__(predictions)
        self.over = over

    def inference(self, texts, labels, threshold=0.5, **kw):
        for index in range(len(texts)):
            if index in self.over:
                _truncation_warning(500)
        return super().inference(texts, labels, threshold=threshold, **kw)


class _WarnThenRefuseGLiNER(_FakeGLiNER):
    """Warns for every chunk of a batch and then refuses the batch; each chunk alone warns once and is answered."""

    def inference(self, texts, labels, threshold=0.5, **kw):
        for _ in texts:
            _truncation_warning(500)
        raise RuntimeError("batch refused after the truncation warnings")

    def predict_entities(self, text, labels, threshold=0.5, **kw):
        _truncation_warning(500)
        return super().predict_entities(text, labels, threshold, **kw)


def test_the_chunks_cut_to_the_limit_are_counted_once_and_the_note_says_so(monkeypatch):
    fake = _TruncatingGLiNER([_pred("malware family", 0.9, "Emotet")], over={0, 2})
    _two_chunks(monkeypatch, fake)
    infos: list[str] = []
    monkeypatch.setattr(stage2e_gliner.logger, "info", infos.append)

    run = stage2e_gliner.run_gliner(_THREE_CHUNKS)

    assert (run.chunks, run.answered, run.truncated_chunks) == (3, 3, 2)
    assert run.note() == "2 chunks truncated at 384 tokens"
    assert run.failure() == ""
    assert [r.value for r in run.entities] == ["Emotet"]
    assert len(infos) == 1 and "2 of 3 chunks truncated" in infos[0]     # one line per document


def test_no_chunk_over_the_limit_counts_nothing_and_the_note_is_unchanged(monkeypatch):
    fake = _FakeGLiNER([_pred("malware family", 0.9, "Emotet")])
    _two_chunks(monkeypatch, fake)
    infos: list[str] = []
    monkeypatch.setattr(stage2e_gliner.logger, "info", infos.append)

    run = stage2e_gliner.run_gliner(_THREE_CHUNKS)

    assert (run.chunks, run.answered, run.truncated_chunks) == (3, 3, 0)
    assert run.note() == ""
    assert infos == []


def test_a_refused_batch_does_not_count_its_warnings_twice(monkeypatch):
    """The batch raised after its warnings; each chunk is then asked alone and counted once."""
    fake = _WarnThenRefuseGLiNER([_pred("malware family", 0.9, "Emotet")])
    _two_chunks(monkeypatch, fake)

    run = stage2e_gliner.run_gliner(_THREE_CHUNKS)

    assert (run.chunks, run.answered, run.retried_batches, run.truncated_chunks) == (3, 3, 1, 3)
    assert run.note() == "1 batch answers refused, asked again chunk by chunk; 3 chunks truncated at 384 tokens"


def test_the_global_truncation_filter_is_gone():
    """The module used to hide the warning for the whole process with an 'ignore' filter."""
    hidden = [f for f in warnings.filters if f[0] == "ignore" and f[1] is not None and "truncated" in f[1].pattern]
    assert hidden == []
