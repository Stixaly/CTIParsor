import pytest

from models.schemas import EntityType, RawEntity
from pipeline.stage2_extraction import _extract_registry_keys
from pipeline.stage4_stix_mapping import (
    _build_stix_pattern,
    _entity_to_sco,
    _expand_registry_hive,
)


def test_trailing_prose_is_not_swallowed():
    text = "Persistence via HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon was set."
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

def test_reg_save_does_not_swallow_the_destination_drive_letter():
    text = "reg save HKLM\\SYSTEM C:\\windows\\temp\\sys.tmp"
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKLM\\SYSTEM"

def test_reg_save_sam_and_security_are_also_trimmed():
    text = "reg save HKLM\\SAM C:\\temp\\sam.hiv\nreg save HKLM\\SECURITY C:\\temp\\sec.hiv"
    entities = _extract_registry_keys(text)
    values = {e.value for e in entities}
    assert values == {"HKLM\\SAM", "HKLM\\SECURITY"}

def test_lowercase_drive_letter_is_trimmed():
    text = "reg save HKLM\\SYSTEM c:\\temp\\x.tmp"
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKLM\\SYSTEM"

def test_internal_spaces_are_preserved():
    text = "The HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware key"
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"

def test_two_letter_tail_before_colon_is_not_trimmed():
    text = "HKLM\\SOFTWARE\\Windows NT: the key was set."
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKLM\\SOFTWARE\\Windows NT"

def test_key_at_end_of_text_is_unchanged():
    text = "Persistence key HKCU\\Software\\Run"
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKCU\\Software\\Run"

def test_trailing_sentence_punctuation_is_stripped():
    text = "Persistence key HKCU\\Software\\Run."
    entities = _extract_registry_keys(text)
    assert len(entities) == 1
    assert entities[0].value == "HKCU\\Software\\Run"

def test_duplicate_keys_are_deduplicated_after_trimming():
    text = "reg save HKLM\\SYSTEM C:\\a.tmp then reg save HKLM\\SYSTEM C:\\b.tmp"
    entities = _extract_registry_keys(text)
    assert len(entities) == 1

def test_every_entity_is_typed_registry_key():
    text = "HKCU\\Software\\Run"
    entities = _extract_registry_keys(text)
    assert all(e.entity_type == EntityType.REGISTRY_KEY for e in entities)

@pytest.mark.parametrize("raw, expected", [
    ("HKLM\\SYSTEM", "HKEY_LOCAL_MACHINE\\SYSTEM"),
    ("hklm\\System\\Foo", "HKEY_LOCAL_MACHINE\\System\\Foo"),
    ("HKCU\\Software\\Run", "HKEY_CURRENT_USER\\Software\\Run"),
    ("HKU\\S-1-5-21-x\\Env", "HKEY_USERS\\S-1-5-21-x\\Env"),
    ("HKCR\\.exe", "HKEY_CLASSES_ROOT\\.exe"),
    ("HKCC\\System", "HKEY_CURRENT_CONFIG\\System"),
    ("HKEY_LOCAL_MACHINE\\SYSTEM", "HKEY_LOCAL_MACHINE\\SYSTEM"),
    ("HKLM", "HKLM"),
    ("", ""),
])
def test_hive_expansion(raw, expected):
    assert _expand_registry_hive(raw) == expected

def test_stix_sco_and_pattern_use_the_full_hive():
    sco = _entity_to_sco(RawEntity(value="HKLM\\SYSTEM", entity_type=EntityType.REGISTRY_KEY))
    assert sco["key"] == "HKEY_LOCAL_MACHINE\\SYSTEM"
    pattern = _build_stix_pattern("HKLM\\SYSTEM", sco)
    assert "HKEY_LOCAL_MACHINE" in pattern
    assert "'HKLM" not in pattern
