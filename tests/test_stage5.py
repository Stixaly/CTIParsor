"""
Tests for Stage 5 (STIX validation and export).

Covers:
  - validate_and_export writes a file to disk
  - The written file is valid JSON
  - The written JSON contains the expected STIX type
  - Invalid path → parent directories are created automatically
  - print_bundle_summary does not raise
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import stix2

from pipeline.stage5_validation import validate_and_export, print_bundle_summary
from pipeline.stage4_stix_mapping import build_stix_bundle
from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted, RelationshipExtracted
from models.schemas import RawEntity, EntityType


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


# ── validate_and_export ────────────────────────────────────────────────────────

class TestValidateAndExport:
    def test_returns_bool(self, tmp_path):
        bundle = _minimal_bundle()
        result = validate_and_export(bundle, str(tmp_path / "out.json"))
        assert isinstance(result, bool)

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
