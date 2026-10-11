"""A file named without a hash keeps its path in `name`, as OpenCTI identifies it (ADR-0083).

STIX 2.1 would split the path into a Directory referenced by
`parent_directory_ref` (audit B 8.1.12), but OpenCTI identifies a hashless
StixFile by `name` alone: the split would merge the `svchost.exe` an attacker
dropped in a public folder with the legitimate one.
"""
from __future__ import annotations

import json
import uuid

from models.schemas import EntityType, RawEntity
from pipeline import stage4_stix_mapping as s4
from pipeline.stage3_llm import LLMEnrichmentResult

# opencti-graphql/src/schema/general.js OASIS_NAMESPACE; identifier.js idGen.
OASIS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
DECOY = r"C:\Users\Public\svchost.exe"
SYSTEM = r"C:\Windows\System32\svchost.exe"


def _opencti_file_id(name: str) -> str:
    """OpenCTI's standard id for a StixFile with no hash: its name alone."""
    canonical = json.dumps({"name": name}, separators=(",", ":"), ensure_ascii=False)
    return f"file--{uuid.uuid5(OASIS_NAMESPACE, canonical)}"


def _files(*paths: str):
    entities = [RawEntity(value=p, entity_type=EntityType.FILE) for p in paths]
    bundle = s4.build_stix_bundle(entities, LLMEnrichmentResult(), "r",
                                  report_text=" ".join(paths))
    return bundle, {o["name"]: o for o in bundle.objects if o["type"] == "file"}


def test_a_hashless_file_keeps_the_path_as_written():
    bundle, files = _files(DECOY)
    f = files[DECOY]
    assert "parent_directory_ref" not in f
    assert not [o for o in bundle.objects if o["type"] == "directory"]
    [indicator] = [o for o in bundle.objects if o["type"] == "indicator"]
    assert indicator["pattern"] == r"[file:name = 'C:\\Users\\Public\\svchost.exe']"


def test_its_id_is_the_one_opencti_computes():
    _, files = _files(DECOY, "svchost.exe")
    for name, f in files.items():
        assert f["id"] == _opencti_file_id(name), name


def test_the_same_name_in_two_directories_stays_two_files():
    _, files = _files(DECOY, SYSTEM)
    assert files[DECOY]["id"] != files[SYSTEM]["id"]
