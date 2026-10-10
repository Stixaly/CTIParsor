"""
Tests for Stage 5 (STIX validation and export).

Covers:
  - validate_and_export writes a file to disk
  - The written file is valid JSON
  - The written JSON contains the expected STIX type
  - Invalid path → parent directories are created automatically
  - print_bundle_summary does not raise
  - the vendored JSON schemas, their install, and full validation without network
"""
from __future__ import annotations

import json
import shutil
import socket

import pytest
import stix2

from models.schemas import EntityType, RawEntity
from pipeline import stage5_validation
from pipeline.stage3_llm import LLMEnrichmentResult, RelationshipExtracted, TTPExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle
from pipeline.stage5_validation import print_bundle_summary, validate_and_export

# ── Fixtures ───────────────────────────────────────────────────────────────────

def _minimal_bundle() -> stix2.Bundle:
    """Build a trivial STIX bundle for export tests."""
    return build_stix_bundle(
        [RawEntity(value="1.2.3.4", entity_type=EntityType.IPV4)],
        LLMEnrichmentResult(
            threat_actors=["APT29"],
            malware_families=["SUNBURST"],
            ttps=[TTPExtracted(technique_name="Spearphishing", mitre_id="T1566.001")],
            relationships=[
                RelationshipExtracted(
                    source_value="APT29",
                    relationship_type="uses",
                    target_value="SUNBURST",
                )
            ],
        ),
        "test_report",
    )


def _rich_bundle() -> stix2.Bundle:
    return build_stix_bundle(
        [
            RawEntity(value="185.220.101.45", entity_type=EntityType.IPV4),
            RawEntity(value="CVE-2021-40444", entity_type=EntityType.CVE),
            RawEntity(
                value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                entity_type=EntityType.SHA256,
            ),
        ],
        LLMEnrichmentResult(
            threat_actors=["APT29"],
            targeted_sectors=["government"],
            targeted_countries=["United States"],
        ),
        "rich_report",
    )


@pytest.fixture
def no_network(monkeypatch):
    """Any connection attempt fails the test: Stage 5 must not download."""
    def refuse(*args, **kwargs):
        raise AssertionError("Stage 5 opened a network connection")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def schemas(no_network):
    """The vendored schemas in stix2-validator's package directory: installed
    by the image at build time, by install_schemas() anywhere else."""
    assert stage5_validation.install_schemas(), "the vendored schemas could not be installed"


# ── validate_and_export ────────────────────────────────────────────────────────

class TestValidateAndExport:
    def test_returns_one_of_three_statuses(self, tmp_path):
        bundle = _minimal_bundle()
        result = validate_and_export(bundle, str(tmp_path / "out.json"))
        assert result.status in ("validated", "unverified", "invalid")
        assert result.ok == (result.status != "invalid")

    def test_missing_schemas_are_unverified_not_valid(self, tmp_path, monkeypatch, no_network):
        """The schemas missing used to return True, like a bundle they accepted.
        Missing and not installable (a read-only package directory): unverified,
        and nothing downloaded."""
        monkeypatch.setattr(stage5_validation, "_schemas_installed", lambda: False)
        monkeypatch.setattr(stage5_validation, "install_schemas", lambda dest=None: False)
        for name in ("a.json", "b.json"):          # every bundle, not only the first
            out = tmp_path / name
            result = validate_and_export(_minimal_bundle(), str(out))
            assert result.status == "unverified" and result.ok and out.exists()

    def test_best_practice_warnings_are_kept(self, tmp_path, schemas):
        m = stix2.Malware(name="x", is_family=True)
        t = stix2.Tool(name="y")
        bundle = stix2.Bundle(m, t, stix2.Relationship(m, "executes", t), allow_custom=True)
        result = validate_and_export(bundle, str(tmp_path / "out.json"))
        assert result.status == "validated"
        assert any("{202}" in w for w in result.warnings)

    def test_pipeline_bundles_pass_full_validation(self, tmp_path, schemas):
        """TESTING.md gap h: with the schemas installed, Stage 4's bundles,
        their x_ provenance properties included (x_evidence_label,
        x_synthesis_stats), pass the JSON schemas, without any download."""
        for name, bundle in (("minimal", _minimal_bundle()), ("rich", _rich_bundle())):
            customs = {k for o in bundle.objects for k in o if k.startswith("x_")}
            assert "x_evidence_label" in customs
            result = validate_and_export(bundle, str(tmp_path / f"{name}.json"))
            assert result.status == "validated", (name, result.errors)

    def test_the_validator_catches_what_the_library_lets_through(self, tmp_path, schemas):
        """Full validation is on: the stix2 library builds a relationship whose
        type breaks STIX's `^[a-z0-9-]+$`, and the validator refuses it."""
        m = stix2.Malware(name="x", is_family=True)
        t = stix2.Tool(name="y")
        bundle = stix2.Bundle(m, t, stix2.Relationship(m, "Uses It", t), allow_custom=True)
        result = validate_and_export(bundle, str(tmp_path / "bad.json"))
        assert result.status == "invalid"
        assert any("relationship_type" in e for e in result.errors)
        assert (tmp_path / "bad_invalid.json").exists()

    def test_file_is_created(self, tmp_path):
        bundle = _minimal_bundle()
        out = tmp_path / "stix_output.json"
        validate_and_export(bundle, str(out))
        assert out.exists() or (tmp_path / "stix_output_invalid.json").exists()

    def test_written_file_is_valid_json(self, tmp_path):
        bundle = _minimal_bundle()
        out = tmp_path / "out.json"
        validate_and_export(bundle, str(out))
        # Accept both valid and _invalid suffix outputs
        candidates = list(tmp_path.glob("*.json"))
        assert candidates, "No JSON file written"
        content = candidates[0].read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict)

    def test_bundle_type_in_output(self, tmp_path):
        bundle = _minimal_bundle()
        out = tmp_path / "out.json"
        validate_and_export(bundle, str(out))
        candidates = list(tmp_path.glob("*.json"))
        parsed = json.loads(candidates[0].read_text(encoding="utf-8"))
        assert parsed.get("type") == "bundle"

    def test_creates_nested_output_directory(self, tmp_path):
        bundle = _minimal_bundle()
        nested = tmp_path / "a" / "b" / "c" / "out.json"
        validate_and_export(bundle, str(nested))
        assert nested.exists() or list((tmp_path / "a" / "b" / "c").glob("*.json"))

    def test_rich_bundle_written(self, tmp_path):
        bundle = _rich_bundle()
        out = tmp_path / "rich.json"
        validate_and_export(bundle, str(out))
        candidates = list(tmp_path.glob("*.json"))
        assert candidates


# ── print_bundle_summary ───────────────────────────────────────────────────────

class TestPrintBundleSummary:
    def test_does_not_raise(self):
        bundle = _minimal_bundle()
        print_bundle_summary(bundle)  # should log, not raise

    def test_empty_bundle_does_not_raise(self):
        # stix2.Bundle requires at least one object; use a single report
        actor = stix2.ThreatActor(name="Test Actor", threat_actor_types=["unknown"])
        bundle = stix2.Bundle(objects=[actor])
        print_bundle_summary(bundle)


# ── The vendored schemas and their install ─────────────────────────────────────

class TestVendoredSchemas:
    """pipeline/data/stix2_json_schemas/: schemas/ of
    oasis-open/cti-stix2-json-schemas at SCHEMA_COMMIT, with its licence."""

    def test_the_schema_tree_is_complete(self):
        root = stage5_validation.VENDORED_SCHEMAS
        files = list(root.rglob("*.json"))
        assert len(files) == 57
        assert {p.name for p in root.iterdir()} == {"common", "observables", "sdos", "sros"}
        for name in ("common/core.json", "common/cyber-observable-core.json",
                     "sdos/malware.json", "sros/relationship.json", "observables/ipv4-addr.json"):
            json.loads((root / name).read_text(encoding="utf-8"))

    def test_the_licence_and_the_commit_are_recorded(self):
        here = stage5_validation.VENDORED_SCHEMAS.parent
        assert "OASIS Open" in (here / "LICENSE").read_text(encoding="utf-8")
        assert stage5_validation.SCHEMA_COMMIT in (here / "README.md").read_text(encoding="utf-8")

    def test_no_schema_refers_to_the_network(self):
        """Every $ref is relative or local: validation never fetches a schema."""
        for path in stage5_validation.VENDORED_SCHEMAS.rglob("*.json"):
            text = path.read_text(encoding="utf-8")
            assert '"$ref": "http' not in text.replace('"$ref":"http', '"$ref": "http'), path


class TestInstallSchemas:
    def test_installs_the_vendored_tree(self, tmp_path, no_network):
        dest = tmp_path / "stix2validator" / "schemas-2.1" / "schemas"
        assert stage5_validation.install_schemas(dest) is True
        installed = sorted(p.relative_to(dest) for p in dest.rglob("*.json"))
        vendored = sorted(p.relative_to(stage5_validation.VENDORED_SCHEMAS)
                          for p in stage5_validation.VENDORED_SCHEMAS.rglob("*.json"))
        assert installed == vendored
        assert not [p for p in dest.parent.iterdir() if p.name.startswith(".schemas-")]

    def test_leaves_installed_schemas_alone(self, tmp_path):
        dest = tmp_path / "schemas"
        (dest / "common").mkdir(parents=True)
        (dest / "common" / "core.json").write_text('{"kept": true}')
        assert stage5_validation.install_schemas(dest) is True
        assert (dest / "common" / "core.json").read_text() == '{"kept": true}'

    def test_a_lost_race_keeps_the_winners_copy(self, tmp_path, monkeypatch):
        """Another worker subprocess installed them between the check and the
        rename: the rename fails, the staging copy goes, the winner's stays."""
        dest = tmp_path / "schemas"
        real_copytree = shutil.copytree
        calls = []

        def copy_then_lose(src, dst, *args, **kw):
            calls.append(dst)
            result = real_copytree(src, dst, *args, **kw)
            if dst == calls[0]:          # the top-level copy, not its recursion
                (dest / "common").mkdir(parents=True)
                (dest / "common" / "core.json").write_text('{"winner": true}')
            return result

        monkeypatch.setattr(stage5_validation.shutil, "copytree", copy_then_lose)
        assert stage5_validation.install_schemas(dest) is True
        assert (dest / "common" / "core.json").read_text() == '{"winner": true}'
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".schemas-")]

    def test_an_unwritable_destination_returns_false(self, tmp_path, monkeypatch, no_network):
        """The read-only container without the build step: False, no exception,
        nothing left behind, nothing downloaded."""
        def read_only(*args, **kwargs):
            raise PermissionError(30, "Read-only file system")
        monkeypatch.setattr(stage5_validation.shutil, "copytree", read_only)
        dest = tmp_path / "schemas"
        assert stage5_validation.install_schemas(dest) is False
        assert not dest.exists()
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".schemas-")]
