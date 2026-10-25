"""pipeline/orchestrator.py and pipeline/stage5_validation.py with a baseline (ADR-0090 lot 4).

Offline, like test_orchestrator_baseline.py: SKIP_HEAVY_MODELS keeps the models
out and the LLM is the `mock_llm` fixture.  The baseline's own functions
(reconcile, serialize_bundle, validation_json) are replaced here: their bodies
are tested in their own modules, and what is checked here is what the run and
Stage 5 hand them.
"""
import json

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline import orchestrator as orch
from pipeline import stage5_validation
from pipeline.baseline_stix import BaselineBuild, BaselineIndex, Reconciliation
from pipeline.orchestrator import Document, Hooks, RunOptions, run_document
from pipeline.stage5_validation import ValidationResult, validate_and_export


@pytest.fixture(autouse=True)
def _no_heavy_models(monkeypatch):
    """Same as test_orchestrator.py: the models are not what these tests are about."""
    for module in ("pipeline.stage2c_ttp_semantic", "pipeline.stage2d_cyner", "pipeline.stage2e_gliner"):
        monkeypatch.setattr(f"{module}._SKIP_HEAVY", True)


@pytest.fixture()
def contract(monkeypatch):
    """The two baseline functions Stage 5 calls, as their contract states them:
    serialize_bundle writes the verbatim objects as given, by id; validation_json
    leaves the trusted objects out."""
    def serialize(bundle, verbatim=None):
        text = bundle.serialize(pretty=True)
        if not verbatim:
            return text
        doc = json.loads(text)
        doc["objects"] = [verbatim.get(o["id"], o) for o in doc["objects"]]
        return json.dumps(doc, indent=4)

    def without_trusted(bundle_json, trusted):
        if not trusted:
            return bundle_json
        doc = json.loads(bundle_json)
        doc["objects"] = [o for o in doc["objects"] if o["id"] not in trusted]
        return json.dumps(doc)

    monkeypatch.setattr("pipeline.baseline_stix.serialize_bundle", serialize)
    monkeypatch.setattr("pipeline.baseline_stix.validation_json", without_trusted)


def _opts() -> RunOptions:
    """Fixed options: nothing read from the developer's .env."""
    return RunOptions(disabled=frozenset({"2f"}), consensus=False, document_relations=False,
                      verify_relationships=False, verify_ttps=False, llm_parallelism=1)


def _two_identities():
    """A bundle of two objects: the first stands for a baseline object, the second for a new one."""
    kept = stix2.Identity(name="Analyst's", identity_class="organization")
    new = stix2.Identity(name="CTIParsor's", identity_class="organization")
    return stix2.Bundle(kept, new), kept.id, new.id


def _capture_validation(monkeypatch) -> list[str]:
    """validate_bundle replaced: records the JSON it was given, and judges it valid."""
    seen: list[str] = []

    def fake(bundle_json):
        seen.append(bundle_json)
        return ValidationResult("validated")

    monkeypatch.setattr(stage5_validation, "validate_bundle", fake)
    return seen


# ── Full mode ────────────────────────────────────────────────────────────────

def test_full_mode_builds_without_a_baseline_and_writes_the_bundle_as_stix2_serializes_it(
        mock_llm, sample_cti_text, tmp_path, monkeypatch, contract):
    calls: list[dict] = []
    real_build_bundle = orch.build_bundle

    def spy(*args, **kwargs):
        calls.append(kwargs)
        return real_build_bundle(*args, **kwargs)

    monkeypatch.setattr(orch, "build_bundle", spy)
    out = tmp_path / "bundle.json"
    result = run_document(Document(text=sample_cti_text, output_path=str(out)), _opts())

    assert len(calls) == 1 and calls[0]["baseline"] is None
    assert result.baseline_build is None and result.reconciliation is None
    assert result.valid is True
    assert out.read_text(encoding="utf-8") == result.bundle.serialize(pretty=True)


# ── Enrich mode ──────────────────────────────────────────────────────────────

def test_enrich_mode_gives_stage_4_the_baseline_and_the_in_text_rows(mock_llm, sample_cti_text, monkeypatch):
    index = object()
    objects = {"identity--1": {"type": "identity", "id": "identity--1"}}
    in_text = RawEntity(value="update.solarwinds.com", entity_type=EntityType.DOMAIN, source="baseline_stix")
    rec = Reconciliation(stats={})
    monkeypatch.setattr(rec, "in_text_entities", lambda: [in_text])
    monkeypatch.setattr("pipeline.baseline_stix.reconcile", lambda *args: rec)

    calls: list[tuple] = []

    def fake_build_bundle(*args, **kwargs):
        calls.append((args, kwargs))
        return stix2.Bundle(stix2.Identity(name="x", identity_class="organization"))

    monkeypatch.setattr(orch, "build_bundle", fake_build_bundle)
    result = run_document(Document(text=sample_cti_text, baseline=index, baseline_objects=objects), _opts())

    assert len(calls) == 1
    args, kwargs = calls[0]
    entities = args[0]
    assert entities == [*result.entities, in_text]
    assert in_text not in result.entities                  # r.entities itself is unchanged
    build = kwargs["baseline"]
    assert isinstance(build, BaselineBuild)
    assert build.index is index and build.objects is objects
    assert build.excluded == frozenset()
    assert result.baseline_build is build
    assert result.reconciliation is rec


# ── Stage 5 ──────────────────────────────────────────────────────────────────

def test_validate_and_export_defaults_write_and_check_the_bundle_as_it_is(tmp_path, monkeypatch, contract):
    bundle, _, _ = _two_identities()
    seen = _capture_validation(monkeypatch)
    out = tmp_path / "bundle.json"
    result = validate_and_export(bundle, str(out))

    assert seen == [bundle.serialize(pretty=True)]
    assert out.read_text(encoding="utf-8") == bundle.serialize(pretty=True)
    assert result.status == "validated"


def test_trusted_objects_are_not_checked_again_but_are_exported_as_received(tmp_path, monkeypatch, contract):
    bundle, kept_id, new_id = _two_identities()
    received = {"type": "identity", "spec_version": "2.1", "id": kept_id, "name": "as received"}
    seen = _capture_validation(monkeypatch)
    out = tmp_path / "bundle.json"
    validate_and_export(bundle, str(out), verbatim={kept_id: received}, trusted=frozenset({kept_id}))

    checked = json.loads(seen[0])["objects"]
    assert [o["id"] for o in checked] == [new_id]          # what CTIParsor built is checked
    exported = json.loads(out.read_text(encoding="utf-8"))["objects"]
    assert exported[0] == received                          # the file keeps the object as received
    assert [o["id"] for o in exported] == [kept_id, new_id]


def test_verbatim_objects_that_are_not_trusted_are_checked_as_written(tmp_path, monkeypatch, contract):
    bundle, kept_id, _ = _two_identities()
    received = {"type": "identity", "spec_version": "2.1", "id": kept_id, "name": "as received"}
    seen = _capture_validation(monkeypatch)
    validate_and_export(bundle, str(tmp_path / "bundle.json"), verbatim={kept_id: received})

    checked = json.loads(seen[0])["objects"]
    assert checked[0] == received                           # the Report re-issued is checked


# ── _Run.validate ────────────────────────────────────────────────────────────

def _run_validate(monkeypatch, tmp_path, build) -> list[dict]:
    """Runs only Stage 5 of a run whose bundle is set; returns the keyword arguments it got."""
    seen: list[dict] = []

    def fake(bundle, output_path, **kwargs):
        seen.append(kwargs)
        return ValidationResult("validated")

    monkeypatch.setattr(stage5_validation, "validate_and_export", fake)
    run = orch._Run(Document(output_path=str(tmp_path / "bundle.json")), _opts(), Hooks())
    run.r.bundle = object()
    run.r.baseline_build = build
    run.validate()
    return seen


def test_validate_passes_the_baseline_builds_verbatim_and_trusted(tmp_path, monkeypatch):
    verbatim = {"identity--1": {"type": "identity", "id": "identity--1"}}
    index = BaselineIndex(version=1, sha256="0" * 64, bundle_id="bundle--0", entries=[], relations=[],
                          imported_ids=frozenset(), passthrough_ids=frozenset(), report_ids=())
    build = BaselineBuild(index=index, objects={}, verbatim=verbatim, trusted=frozenset({"identity--1"}))

    assert _run_validate(monkeypatch, tmp_path, build) == [{"verbatim": verbatim,
                                                            "trusted": frozenset({"identity--1"})}]


def test_validate_in_full_mode_passes_no_baseline_argument(tmp_path, monkeypatch):
    assert _run_validate(monkeypatch, tmp_path, None) == [{}]
