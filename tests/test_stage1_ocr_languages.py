"""OCR_LANG: the default, the override, the fallback to the languages Tesseract
has installed, what a page is read with, what the run record keeps, and the
Dockerfile that installs the language packs.  Tesseract is replaced by a fake,
so the tests do not depend on the language packs of the machine."""
import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from pipeline import stage1_ingestion as s1

ROOT = Path(__file__).resolve().parent.parent
MULTI = "eng+fra+ukr+pol+rus"


class _FakeTesseract:
    """Lists `installed` languages and fails an OCR call that names another one,
    as Tesseract does for a language without data."""

    def __init__(self, installed, list_error=None):
        self.installed = set(installed)
        self.list_error = list_error
        self.read_with: list[str] = []

    def get_languages(self, config=""):
        if self.list_error is not None:
            raise self.list_error
        return sorted(self.installed)

    def image_to_string(self, img, lang):
        self.read_with.append(lang)
        absent = set(lang.split("+")) - self.installed
        if absent:
            raise RuntimeError(f"Failed loading language '{sorted(absent)[0]}'")
        return f"text [{lang}]"


@pytest.fixture()
def tesseract(monkeypatch):
    """Fresh resolution cache, so one test's setting does not leak into another."""
    monkeypatch.setattr(s1, "_ocr_langs_in_use", {})
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", True)

    def install(installed, list_error=None):
        fake = _FakeTesseract(installed, list_error)
        monkeypatch.setattr(s1, "pytesseract", fake, raising=False)
        return fake

    return install


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


# ── Default and override ─────────────────────────────────────────────────────

def test_the_default_is_english(monkeypatch, tesseract):
    tesseract(["eng", "fra", "ukr", "pol", "rus", "osd"])
    monkeypatch.delenv("OCR_LANG", raising=False)
    assert s1.OCR_LANG_DEFAULT == "eng"
    assert s1.ocr_lang() == "eng"


@pytest.mark.parametrize("value", ["", "   "])
def test_a_blank_setting_is_the_default(monkeypatch, tesseract, value):
    tesseract(["eng"])
    monkeypatch.setenv("OCR_LANG", value)
    assert s1.ocr_lang() == "eng"


def test_the_setting_overrides_the_default_when_installed(monkeypatch, tesseract):
    tesseract(["eng", "fra", "ukr", "pol", "rus"])
    monkeypatch.setenv("OCR_LANG", f" {MULTI} ")
    assert s1.ocr_lang() == MULTI


def test_a_single_language_is_kept_as_written(monkeypatch, tesseract):
    tesseract(["eng", "deu"])
    monkeypatch.setenv("OCR_LANG", " deu ")
    assert s1.ocr_lang() == "deu"


# ── Fallback to the installed languages ──────────────────────────────────────

def test_a_language_without_data_is_left_out_with_one_warning(monkeypatch, tesseract, caplog):
    tesseract(["eng", "fra", "osd"])
    monkeypatch.setenv("OCR_LANG", MULTI)
    with caplog.at_level(logging.WARNING):
        assert s1.ocr_lang() == "eng+fra"
        assert s1.ocr_lang() == "eng+fra"          # the second call is not a second warning
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "ukr, pol, rus" in warnings[0] and "eng+fra" in warnings[0]


def test_no_installed_language_keeps_the_setting_and_warns(monkeypatch, tesseract, caplog):
    tesseract(["osd"])
    monkeypatch.setenv("OCR_LANG", "ukr+pol")
    with caplog.at_level(logging.WARNING):
        assert s1.ocr_lang() == "ukr+pol"
    assert any("no data for any" in w for w in _warnings(caplog))


def test_an_unreadable_language_list_keeps_the_setting(monkeypatch, tesseract, caplog):
    tesseract([], list_error=OSError("tesseract not found"))
    monkeypatch.setenv("OCR_LANG", MULTI)
    with caplog.at_level(logging.WARNING):
        assert s1.ocr_lang() == MULTI
    assert any("could not list the Tesseract languages" in w for w in _warnings(caplog))


def test_without_pytesseract_the_setting_is_returned_unchanged(monkeypatch):
    monkeypatch.setattr(s1, "_ocr_langs_in_use", {})
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", False)
    monkeypatch.setenv("OCR_LANG", MULTI)
    assert s1.ocr_lang() == MULTI


def test_a_page_is_read_only_with_the_languages_that_are_installed(monkeypatch, tesseract, tmp_path):
    fake = tesseract(["eng", "fra"])
    monkeypatch.setenv("OCR_LANG", MULTI)
    monkeypatch.setattr(s1, "convert_from_path",
                        lambda path, dpi, first_page, last_page: [SimpleNamespace(close=lambda: None)],
                        raising=False)

    assert s1._ocr_page(tmp_path / "scan.pdf", 1) == "text [eng+fra]"
    assert fake.read_with == ["eng+fra"]           # no page fails on a missing pack


# ── The run record keeps the effective languages ─────────────────────────────

def test_the_run_record_keeps_the_languages_read_with(monkeypatch, tesseract):
    from api.run_config import captured_env

    tesseract(["eng", "fra"])
    monkeypatch.setenv("OCR_LANG", MULTI)
    assert captured_env()["OCR_LANG"] == "eng+fra"


def test_the_run_record_names_the_default_when_unset(monkeypatch, tesseract):
    from api.run_config import captured_env

    tesseract(["eng"])
    monkeypatch.delenv("OCR_LANG", raising=False)
    assert captured_env()["OCR_LANG"] == "eng"


# ── The image installs the language packs ────────────────────────────────────

def _runtime_apt_install() -> str:
    """The apt-get install line of the runtime stage (the one with tesseract)."""
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    blocks = [m.group(1) for m in re.finditer(
        r"apt-get install -y --no-install-recommends(.*?)&&", text, re.S)
        if "tesseract-ocr" in m.group(1)]
    assert len(blocks) == 1, "one runtime apt-get install must install tesseract"
    return blocks[0]


def test_the_image_installs_a_tesseract_pack_for_each_documented_language():
    installed = _runtime_apt_install().split()
    assert "tesseract-ocr" in installed          # English
    for lang in MULTI.split("+")[1:]:
        assert f"tesseract-ocr-{lang}" in installed
