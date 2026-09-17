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

import io
import json
import zipfile

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


# ── _try_restore_schemas (Zip Slip guard on the GitHub schema archive) ─────────

def _fake_schema_zip(*entries: tuple[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestTryRestoreSchemas:
    """
    `_try_restore_schemas` downloads a GitHub archive and extracts only its
    `schemas/` subtree — normal operation locked by the first test below. The
    URL is fixed and trusted, but that is exactly why the extraction itself
    must not trust archive *entry names*: `pipeline/detection/sync.py` already
    learned this lesson for corpus tarballs (`_safe_members`), and this zip
    path needs the identical containment check before any write.
    """

    def test_extracts_schema_files_under_the_prefix(self, tmp_path, monkeypatch):
        dest = tmp_path / "schemas-2.1" / "schemas"
        monkeypatch.setattr(stage5_validation, "_schema_dir", lambda: dest)
        zip_bytes = _fake_schema_zip(
            (stage5_validation._ZIP_SCHEMA_PREFIX + "common/core.json", b'{"a": 1}'),
            (stage5_validation._ZIP_SCHEMA_PREFIX + "sdos/malware.json", b'{"b": 2}'),
            ("cti-stix2-json-schemas-master/README.md", b"not a schema"),  # no prefix match
        )
        monkeypatch.setattr(
            stage5_validation.urllib.request, "urlopen",
            lambda *a, **kw: _FakeResponse(zip_bytes),
        )

        ok = stage5_validation._try_restore_schemas()

        assert ok is True
        assert (dest / "common" / "core.json").read_bytes() == b'{"a": 1}'
        assert (dest / "sdos" / "malware.json").read_bytes() == b'{"b": 2}'
        assert not (tmp_path / "README.md").exists()

    def test_rejects_an_entry_that_escapes_the_schema_directory(self, tmp_path, monkeypatch):
        """
        Locks the Zip Slip fix: an archive entry named
        `<prefix>../../../../tmp/evil.json` still starts with the prefix and
        ends in `.json`, so both filters above the containment check pass it —
        the containment check itself is what must stop it landing outside
        `dest`.
        """
        dest = tmp_path / "install" / "schemas-2.1" / "schemas"
        sentinel = tmp_path / "evil.json"
        # `dest` sits 3 levels below tmp_path (install/schemas-2.1/schemas), so
        # 3 `../` segments walk exactly back up to tmp_path, landing on `sentinel`.
        traversal = "../" * 3 + "evil.json"

        monkeypatch.setattr(stage5_validation, "_schema_dir", lambda: dest)
        zip_bytes = _fake_schema_zip(
            (stage5_validation._ZIP_SCHEMA_PREFIX + "common/core.json", b'{"legit": true}'),
            (stage5_validation._ZIP_SCHEMA_PREFIX + traversal, b"pwned"),
        )
        monkeypatch.setattr(
            stage5_validation.urllib.request, "urlopen",
            lambda *a, **kw: _FakeResponse(zip_bytes),
        )

        ok = stage5_validation._try_restore_schemas()

        assert ok is True                                       # the legit entry still lands
        assert (dest / "common" / "core.json").exists()
        assert not sentinel.exists()                             # the traversal entry does not
