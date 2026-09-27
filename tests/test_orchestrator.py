"""pipeline/orchestrator.py — one pipeline for the worker, the CLI and the
benchmark (ADR-0059).

Offline: SKIP_HEAVY_MODELS keeps CyNER/GLiNER/embeddings out, and the LLM is
the `mock_llm` fixture (conftest), so Stage 3 runs against a fixed response.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from pipeline import orchestrator as orch
from pipeline.orchestrator import (
    Document,
    FileCheckpoint,
    Hooks,
    RunAborted,
    RunOptions,
    StageRequired,
    run_document,
)

REPO = Path(__file__).resolve().parents[1]


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


# ── The stage report ─────────────────────────────────────────────────────────

def test_a_run_reports_every_stage_and_builds_a_valid_bundle(mock_llm, sample_cti_text, tmp_path):
    out = tmp_path / "bundle.json"
    result = run_document(
        Document(text=sample_cti_text, original_filename="r.txt", output_path=str(out)), _opts(),
    )

    # 1f is decided before Stage 1 finishes chunking (figures change the text).
    assert [o.stage for o in result.stages] == [
        "1f", "1", "2", "2b", "2c", "2d", "2e", "2g", "3", "3d", "3f", "3e", "3doc",
        "2f", "4", "4b", "4c", "5"]
    assert result.outcome("3f").reason == "disabled"      # _opts turns 3d / 3f off
    assert result.outcome("4c").reason == "not enabled by the relationship policy"
    assert {o.stage for o in result.stages} == set(orch.STAGES)
    assert result.ran("1") and result.ran("2") and result.ran("3") and result.ran("4")
    assert result.outcome("3").counts["llm_calls"] == 1
    assert result.outcome("2d").status == "skipped" and "unavailable" in result.outcome("2d").reason
    assert result.outcome("2f").reason == "disabled"
    # Only the LLM names the campaign (APT29 itself is the gazetteer's, so the merge drops it).
    assert result.llm_result.campaign_name == "SolarWinds Supply Chain"
    assert "update.solarwinds.com" in result.text          # refanged
    assert result.valid is True and out.exists()
    assert json.loads(out.read_text())["type"] == "bundle"


def test_a_disabled_stage_is_skipped_and_never_called(mock_llm, sample_cti_text):
    result = run_document(Document(text=sample_cti_text), _opts(disabled={"2f", "3", "5"}))

    assert mock_llm.call_count == 0
    assert result.outcome("3").reason == "disabled"
    assert result.outcome("3e").reason == result.outcome("3doc").reason == "Stage 3 did not run"
    # Stage 3c still runs: Stage 4 gets a result either way.
    assert result.llm_result is not None and result.bundle is not None


def test_a_required_stage_that_cannot_run_stops_the_run(sample_cti_text, monkeypatch):
    monkeypatch.setattr("pipeline.stage3_llm._provider_ready", lambda provider=None: False)

    with pytest.raises(StageRequired) as err:
        run_document(Document(text=sample_cti_text), _opts(required={"3"}))

    assert err.value.outcome.stage == "3"
    assert "not ready" in err.value.outcome.reason


def test_a_stage3_whose_every_call_fails_is_failed_not_empty(sample_cti_text, monkeypatch):
    """A wrong model name 404s on every request; each call is caught and
    returns "", so the run used to look like one where the model found nothing."""
    import pipeline.stage3_llm as s3

    def not_found(system, user):
        raise RuntimeError("Error code: 404 - The model `Qwen` does not exist.")

    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_call_anthropic_impl", not_found)

    result = run_document(Document(text=sample_cti_text), _opts())
    stage3 = result.outcome("3")
    assert stage3.status == "failed" and "404" in stage3.reason
    assert stage3.counts["provider_failures"] == stage3.counts["provider_calls"] > 0

    with pytest.raises(StageRequired):
        run_document(Document(text=sample_cti_text), _opts(required={"3"}))


def test_unknown_stage_ids_are_refused():
    with pytest.raises(ValueError, match="unknown stage"):
        RunOptions(disabled=frozenset({"2x"}))
    with pytest.raises(ValueError, match="unknown stage"):
        RunOptions(required=frozenset({"llm"}))


def test_the_environment_can_turn_stages_off(monkeypatch):
    monkeypatch.setenv("PIPELINE_DISABLED_STAGES", " 2d, 2e ,")
    opts = RunOptions.from_env(disabled={"1f"})
    assert opts.disabled == {"1f", "2d", "2e"}


# ── Hooks ────────────────────────────────────────────────────────────────────

class _Recorder(Hooks):
    def __init__(self):
        self.calls: list[tuple] = []

    def progress(self, event, data):
        self.calls.append(("progress", event, data.get("stage")))

    def text_ready(self, text, figure_spans, figure_provider):
        self.calls.append(("text_ready", text))

    def extraction_ready(self, entities, llm_result, text):
        self.calls.append(("extraction_ready", len(entities)))

    def policy(self):
        self.calls.append(("policy",))
        return {"completion": {}}

    def policy_used(self, policy):
        self.calls.append(("policy_used", policy))


def test_hooks_are_called_in_pipeline_order(mock_llm, sample_cti_text):
    hooks = _Recorder()
    result = run_document(Document(text=sample_cti_text), _opts(), hooks)

    names = [c[0] for c in hooks.calls]
    assert names.index("text_ready") < names.index("extraction_ready") < names.index("policy")
    assert ("policy_used", {"completion": {}}) in hooks.calls
    assert result.policy == {"completion": {}}
    stages = [c[2] for c in hooks.calls if c[:2] == ("progress", "stage")]
    assert stages == [1, 2, 3, 4]      # no Stage 5 event: no output path, Stage 5 skipped
    assert ("progress", "partial_graph", None) in hooks.calls


def test_a_hook_can_abort_before_anything_is_mapped(mock_llm, sample_cti_text):
    class Abort(Hooks):
        def extraction_ready(self, entities, llm_result, text):
            raise RunAborted

        def policy(self):
            raise AssertionError("Stage 4 must not start")

    with pytest.raises(RunAborted):
        run_document(Document(text=sample_cti_text), _opts(), Abort())


# ── Stage 3 checkpoint ───────────────────────────────────────────────────────

def test_checkpoint_resumes_only_its_own_run(tmp_path):
    from pipeline.stage3_llm import LLMEnrichmentResult

    ckpt = FileCheckpoint(tmp_path / "c.json", "job-1")
    ckpt.save("fp-a", 3, {1: LLMEnrichmentResult(threat_actors=["APT29"])})

    loaded, saved_at = ckpt.load("fp-a", 3)
    assert loaded[1].threat_actors == ["APT29"] and saved_at
    assert ckpt.load("fp-b", 3) == ({}, "")      # another document, model or prompt
    assert ckpt.load("fp-a", 4) == ({}, "")      # another chunking
    ckpt.clear()
    assert ckpt.load("fp-a", 3) == ({}, "")


def _fp(chunks=("one", "two"), ctx="ctx", consensus=False, verify_rels=False, verify_ttps=False):
    from pipeline.stage3_llm import stage3_settings
    settings = stage3_settings(consensus=consensus, verify_rels=verify_rels, verify_ttps=verify_ttps)
    return orch.stage3_fingerprint(settings, {"chunks": list(chunks), "doc_context": ctx})


def test_the_fingerprint_moves_with_every_stage3_setting(monkeypatch):
    """A checkpoint must not resume across any change that alters Stage 3's
    output — including switching 3d/3f verification on after a crash, and the
    consensus pass's own model."""
    import pipeline.stage3_llm as s3

    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_MODEL", "model-a")
    monkeypatch.setenv("CONSENSUS_PROVIDER", "mistral")
    monkeypatch.setenv("MISTRAL_MODEL", "small")
    base = _fp()

    assert _fp() == base
    assert _fp(chunks=("one", "TWO")) != base
    assert _fp(ctx="other") != base
    assert _fp(verify_ttps=True) != base            # ENABLE_TTP_VERIFICATION turned on
    assert _fp(verify_rels=True) != base            # ENABLE_STIX_VERIFICATION turned on
    with_consensus = _fp(consensus=True)
    assert with_consensus != base
    monkeypatch.setenv("MISTRAL_MODEL", "large")    # same provider, another model
    assert _fp(consensus=True) != with_consensus
    monkeypatch.setenv("ANTHROPIC_MODEL", "model-b")
    assert _fp() != base


def test_a_crashed_stage3_resumes_but_never_on_a_different_document(mock_llm, sample_cti_text, tmp_path):
    class Keep(Hooks):
        """A checkpoint that survives the run, as if it had crashed."""
        def __init__(self):
            self.checkpoint = FileCheckpoint(tmp_path / "c.json", "job")
            self.checkpoint.clear = lambda: None

    text = _long_text(sample_cti_text, 3)
    first = run_document(Document(text=text), _opts(checkpoint_every=1), Keep())
    calls = mock_llm.call_count
    assert first.outcome("3").counts["llm_calls"] == len(first.chunks) > 1

    again = run_document(Document(text=text), _opts(checkpoint_every=1), Keep())
    assert mock_llm.call_count == calls                     # nothing re-sent
    assert again.outcome("3").counts["from_checkpoint"] == len(again.chunks)

    edited = text.replace("SolarWinds", "SolarWindz")        # same chunk count
    other = run_document(Document(text=edited), _opts(checkpoint_every=1), Keep())
    assert len(other.chunks) == len(first.chunks)
    assert mock_llm.call_count > calls                       # not resumed
    assert other.outcome("3").counts["from_checkpoint"] == 0


# ── One pipeline: the worker and the CLI build the same bundle ───────────────

# Fields that differ between two builds of the same content.
_VOLATILE = {"id", "created", "modified", "valid_from", "published", "first_observed", "last_observed"}


def _normalise(bundle: dict) -> dict[str, dict]:
    """The bundle as {stable key: object}, every id replaced by the stable key
    of the object it names, timestamps dropped — so relationship endpoints,
    evidence, labels and confidences are compared, not only names."""
    objs = bundle["objects"]

    def label(o):
        for k in ("name", "value", "pattern", "hashes", "payload_bin"):
            if o.get(k):
                return json.dumps(o[k], sort_keys=True)
        return None

    keys = {o["id"]: f"{o['type']}|{label(o)}" for o in objs if label(o) is not None}
    for o in objs:                                     # relationships: by their endpoints
        if o["type"] == "relationship":
            keys[o["id"]] = (f"relationship|{keys.get(o['source_ref'])}|{o['relationship_type']}"
                             f"|{keys.get(o['target_ref'])}")

    def sub(v):
        if isinstance(v, str):
            return keys.get(v, v)
        if isinstance(v, list):
            out = [sub(x) for x in v]
            return sorted(out, key=lambda x: json.dumps(x, sort_keys=True))
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items() if k not in _VOLATILE}
        return v

    out: dict[str, dict] = {}
    for o in objs:
        key = keys.get(o["id"]) or f"{o['type']}|{json.dumps(sub(o), sort_keys=True)}"
        assert key not in out, f"two objects share the key {key}"
        out[key] = sub(o)
    return out


def test_worker_and_cli_run_the_same_pipeline(temp_db, mock_llm, sample_cti_text, tmp_path,
                                              monkeypatch):
    """Same file, same saved relationship policy: the worker and the CLI must
    build the same bundle, object for object and edge for edge."""
    from api import worker

    monkeypatch.setattr(worker, "_ROOT", tmp_path)
    monkeypatch.setenv("CVE_ENRICHMENT", "false")     # never reach CIRCL from a test
    for var in ("ENABLE_CONSENSUS", "ENABLE_DOCUMENT_LEVEL_RELATIONS", "PIPELINE_DISABLED_STAGES"):
        monkeypatch.delenv(var, raising=False)
    report = tmp_path / "report.txt"
    report.write_text(sample_cti_text, encoding="utf-8")

    # A saved, non-default policy: both paths must apply it.
    policy = {"global": "enforce", "rules": [], "completion": {"transitive": False, "reference": False}}
    with temp_db.get_conn() as conn:
        conn.execute("INSERT INTO relationship_policy (id, policy_json) VALUES (1, ?)",
                     (json.dumps(policy),))
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, created_at, updated_at) "
            "VALUES (?,?,?,?,?)",
            ("job-eq", "report.txt", "queued", temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()
    worker._run_pipeline("job-eq", str(report), "report.txt")
    row = temp_db.get_conn().execute(
        "SELECT status, bundle_json, run_config_json FROM jobs WHERE id=?", ("job-eq",)).fetchone()
    assert row["status"] == "for_review", row
    worker_bundle = json.loads(row["bundle_json"])

    spec = importlib.util.spec_from_file_location("cti_main", REPO / "main.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    cli_out = tmp_path / "cli.json"
    assert cli.run_pipeline(str(report), str(cli_out)) is True     # --policy db (the default)
    cli_bundle = json.loads(cli_out.read_text(encoding="utf-8"))

    w, c = _normalise(worker_bundle), _normalise(cli_bundle)
    assert set(w) == set(c), (sorted(set(w) - set(c)), sorted(set(c) - set(w)))
    for key in w:
        assert w[key] == c[key], key
    assert any(k.startswith("campaign|") for k in w)                 # Stage 3 ran
    assert any(k.startswith("relationship|") for k in w)             # edges compared by endpoints
    assert json.loads(row["run_config_json"])["policy"] == policy    # the saved policy was used

    stages = {s["stage"]: s["status"] for s in json.loads(row["run_config_json"])["stage_report"]}
    assert stages["3"] == "ran" and stages["4"] == "ran" and stages["5"] == "ran"
    manifest = json.loads(row["run_config_json"])["manifest"]
    assert manifest["llm"]["prompt_fingerprint"] and manifest["data"]["mitre_index.json"]
    assert manifest["packages"]["stix2"]
    assert temp_db.get_conn().execute(
        "SELECT COUNT(*) AS n FROM entities WHERE job_id='job-eq'").fetchone()["n"] > 0


def test_the_bundle_comparison_sees_a_reversed_edge():
    """The normalisation must not hide what the old name-only comparison did."""
    base = {"objects": [
        {"type": "threat-actor", "id": "t--1", "name": "APT29"},
        {"type": "malware", "id": "m--1", "name": "WellMess"},
        {"type": "relationship", "id": "r--1", "relationship_type": "uses",
         "source_ref": "t--1", "target_ref": "m--1", "confidence": 90},
    ]}
    flipped = json.loads(json.dumps(base))
    flipped["objects"][2].update(source_ref="m--1", target_ref="t--1")
    less_sure = json.loads(json.dumps(base))
    less_sure["objects"][2]["confidence"] = 50
    assert _normalise(base) != _normalise(flipped)
    assert _normalise(base) != _normalise(less_sure)


def test_sampling_is_the_providers_unless_set(monkeypatch):
    from pipeline.stage3_llm import sampling_options

    monkeypatch.delenv("LLM_TEMPERATURE", raising=False)
    monkeypatch.delenv("LLM_SEED", raising=False)
    assert sampling_options() == {}
    monkeypatch.setenv("LLM_TEMPERATURE", "0")
    monkeypatch.setenv("LLM_SEED", "13")
    assert sampling_options() == {"temperature": 0.0, "seed": 13}
    assert sampling_options(seed_ok=False) == {"temperature": 0.0}   # Anthropic, Mistral, Gemini
    # A different sampling is a different Stage 3: the checkpoint must not resume.
    t0 = _fp()
    monkeypatch.setenv("LLM_TEMPERATURE", "0.7")
    assert _fp() != t0


@pytest.mark.parametrize(("answer", "kind"), [("", "empty"), ("this is not JSON at all", "unparseable")])
def test_an_empty_or_unparseable_answer_is_not_nothing_found(sample_cti_text, monkeypatch, answer, kind):
    """The request succeeds, but nothing usable comes back: that is a failed
    Stage 3, not a model that found nothing (review of 2026-09-27, point 2)."""
    import pipeline.stage3_llm as s3

    monkeypatch.setattr(s3, "_PROVIDER", "anthropic")
    monkeypatch.setattr(s3, "_call_anthropic_impl", lambda system, user: answer)

    stage3 = run_document(Document(text=sample_cti_text), _opts()).outcome("3")
    assert stage3.status == "failed" and f"1 {kind}" in stage3.reason
    assert stage3.counts["provider_failures"] == 0 and stage3.counts["extraction_ok"] == 0
    with pytest.raises(StageRequired):
        run_document(Document(text=sample_cti_text), _opts(required={"3"}))


def test_a_partly_unusable_stage3_runs_and_says_how_much(mock_llm, mock_llm_response, sample_cti_text):
    mock_llm.side_effect = [json.dumps(mock_llm_response), "garbage"]
    text = _long_text(sample_cti_text, 2)
    result = run_document(Document(text=text), _opts())
    stage3 = result.outcome("3")
    assert len(result.chunks) == 2
    assert stage3.status == "ran" and "1 of 2 extraction calls unusable" in stage3.reason
    assert (stage3.counts["extraction_ok"], stage3.counts["extraction_invalid"]) == (1, 1)


def test_verification_and_completion_stages_can_be_turned_off(mock_llm, sample_cti_text, monkeypatch):
    # The environment says off (as in CI); the run options say on — the options win.
    monkeypatch.setattr("pipeline.stage3d_verify._VERIFY_ENABLED", False)
    monkeypatch.setattr("pipeline.stage3f_ttp_verify._VERIFY_ENABLED", False)
    result = run_document(
        Document(text=sample_cti_text),
        _opts(disabled={"2f", "4b", "4c"}, verify_relationships=True, verify_ttps=True),
    )
    assert result.outcome("4b").reason == "disabled" and result.outcome("4c").reason == "disabled"
    assert "graph completion disabled for this run" in result.synthesis["completion"]["notes"]
    # 3d / 3f were on; the mocked verifier answers extraction JSON, which it cannot parse.
    assert result.outcome("3d").status == result.outcome("3f").status == "failed"
    off = run_document(Document(text=sample_cti_text), _opts(disabled={"2f", "3d", "3f"}))
    assert off.outcome("3d").reason == off.outcome("3f").reason == "disabled"


def test_cli_policy_source(tmp_path, capsys):
    spec = importlib.util.spec_from_file_location("cti_main", REPO / "main.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    assert cli._ConsoleHooks("none").policy() is None
    f = tmp_path / "policy.json"
    f.write_text(json.dumps({"global": "enforce", "rules": []}), encoding="utf-8")
    assert cli._ConsoleHooks(str(f)).policy() == {"global": "enforce", "rules": []}
