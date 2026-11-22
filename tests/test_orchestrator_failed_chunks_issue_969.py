"""pipeline/orchestrator.py — a chunk whose model answer was not read is a failed
chunk, not an empty result (issue #969).

The LLM is the `mock_llm` fixture (conftest): `_call_llm` answers with the
scripted strings, so `enrich_chunk` really reads each answer and sets its own
"answered" flag.  With llm_parallelism=1 the calls run in chunk order.
"""
import json

import pytest

from pipeline.orchestrator import Document, FileCheckpoint, Hooks, RunOptions, run_document


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


def _opts(**kw) -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    kw.setdefault("disabled", frozenset({"2f"}))   # the CVE cache needs a database
    kw.setdefault("verify_relationships", False)
    kw.setdefault("verify_ttps", False)
    return RunOptions(consensus=False, document_relations=False, llm_parallelism=1, **kw)


def _long_text(sample: str, n_chunks: int) -> str:
    """A report of about n_chunks Stage 1 chunks, each worth sending to the LLM."""
    para = (sample + " ") * 8
    return "\n\n".join(f"Section {i}. {para}" for i in range(n_chunks))


class _KeepCheckpoint(Hooks):
    """A checkpoint that survives the run, as if it had crashed, saved after every chunk."""

    def __init__(self, path):
        self.checkpoint = FileCheckpoint(path, "job")
        self.checkpoint.clear = lambda: None


def _saved_chunks(path) -> set[str]:
    """The chunk indexes the checkpoint file holds."""
    return set(json.loads(path.read_text(encoding="utf-8"))["chunks"])


def test_an_unreadable_answer_is_retried_and_recovered(mock_llm, mock_llm_response, sample_cti_text):
    # The first answer is garbage, the second try reads.
    mock_llm.side_effect = ["garbage", json.dumps(mock_llm_response)]
    result = run_document(Document(text=sample_cti_text), _opts())
    stage3 = result.outcome("3")

    assert mock_llm.call_count == 2
    assert result.llm_result.campaign_name == "SolarWinds Supply Chain"
    assert (stage3.counts["retried_chunks"], stage3.counts["recovered_chunks"],
            stage3.counts["failed_chunks"]) == (1, 1, 0)
    assert stage3.details["failed_chunks"] == []
    assert stage3.status == "ran" and "not analysed" not in stage3.reason


def test_a_chunk_unreadable_twice_stays_out_of_the_checkpoint(mock_llm, mock_llm_response, sample_cti_text,
                                                              tmp_path):
    path = tmp_path / "c.json"
    text = _long_text(sample_cti_text, 2)
    # Chunk 1 is read; chunk 2 is unreadable on its first call and on its second try.
    mock_llm.side_effect = [json.dumps(mock_llm_response), "garbage", "garbage"]
    result = run_document(Document(text=text), _opts(checkpoint_every=1), _KeepCheckpoint(path))
    stage3 = result.outcome("3")

    assert len(result.chunks) == 2
    assert _saved_chunks(path) == {"1"}                      # chunk 2 is not recorded as done
    assert stage3.status == "ran"
    assert "1 passage(s) not analysed by the model (chunks 2)" in stage3.reason
    [failed] = stage3.details["failed_chunks"]
    assert failed["chunk"] == 2 and failed["chars"] == len(result.chunks[1])
    assert failed["reason"] == "no usable answer"
    position = result.text.find(result.chunks[1][:200])       # the report text the stages read
    assert failed["start"] == (position if position >= 0 else None)
    assert (stage3.counts["failed_chunks"], stage3.counts["retried_chunks"],
            stage3.counts["recovered_chunks"]) == (1, 1, 0)


def test_a_resumed_run_replays_only_the_chunk_that_failed(mock_llm, mock_llm_response, sample_cti_text,
                                                          tmp_path):
    path = tmp_path / "c.json"
    text = _long_text(sample_cti_text, 2)
    mock_llm.side_effect = [json.dumps(mock_llm_response), "garbage", "garbage"]
    first = run_document(Document(text=text), _opts(checkpoint_every=1), _KeepCheckpoint(path))
    assert first.outcome("3").counts["failed_chunks"] == 1
    assert _saved_chunks(path) == {"1"}

    # The second run answers normally: chunk 1 comes from the checkpoint, chunk 2 is sent again.
    mock_llm.side_effect = [json.dumps(mock_llm_response)]
    calls = mock_llm.call_count
    again = run_document(Document(text=text), _opts(checkpoint_every=1), _KeepCheckpoint(path))
    stage3 = again.outcome("3")

    assert mock_llm.call_count == calls + 1
    assert stage3.counts["from_checkpoint"] == 1 and stage3.counts["llm_calls"] == 1
    assert (stage3.counts["failed_chunks"], stage3.counts["extraction_ok"]) == (0, 1)
    assert stage3.details["failed_chunks"] == [] and "not analysed" not in stage3.reason


def test_an_answer_with_nothing_in_it_is_a_read_answer(mock_llm, sample_cti_text, tmp_path):
    path = tmp_path / "c.json"
    mock_llm.side_effect = [json.dumps({"threat_actors": [], "malware_families": []})]
    result = run_document(Document(text=sample_cti_text), _opts(checkpoint_every=1), _KeepCheckpoint(path))
    stage3 = result.outcome("3")

    assert mock_llm.call_count == 1                          # no second try
    assert stage3.counts["extraction_ok"] == 1
    assert (stage3.counts["failed_chunks"], stage3.counts["retried_chunks"]) == (0, 0)
    assert _saved_chunks(path) == {"1"}                      # an empty answer is done, not failed


def test_a_provider_down_on_the_second_try_stops_the_replays(mock_llm, sample_cti_text):
    """One failed request on the second try is enough: the other failed chunks
    are listed without a one-at-a-time replay each (which, with the retries of
    #968, would run the job into its timeout)."""
    from pipeline import llm_stats

    def down(*_args, **_kwargs):
        llm_stats.record_call("connection refused")
        return ""

    mock_llm.side_effect = down
    result = run_document(Document(text=_long_text(sample_cti_text, 3)), _opts())
    stage3 = result.outcome("3")
    n = len(result.chunks)

    assert n >= 2
    assert mock_llm.call_count == n + 1                      # the first pass, then one second try
    assert stage3.counts["retried_chunks"] == 1
    assert stage3.counts["failed_chunks"] == n
    reasons = [c["reason"] for c in stage3.details["failed_chunks"]]
    assert reasons[0] == "provider request failed"
    assert set(reasons[1:]) == {"provider request failed (second try not made)"}
