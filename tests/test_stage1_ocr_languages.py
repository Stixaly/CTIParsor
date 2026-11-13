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

    def __init__(self, installed, list_error=None, osd=None):
        self.installed = set(installed)
        self.list_error = list_error
        self.osd = osd              # the OSD text, or an exception that OSD raises
        self.osd_calls = 0
        self.read_with: list[str] = []

    def get_languages(self, config=""):
        if self.list_error is not None:
            raise self.list_error
        return sorted(self.installed)

    def image_to_osd(self, img, config=""):
        self.osd_calls += 1
        if isinstance(self.osd, Exception):
            raise self.osd
        return self.osd or ""

    def image_to_string(self, img, lang):
        self.read_with.append(lang)
        absent = set(lang.split("+")) - self.installed
        if absent:
            raise RuntimeError(f"Failed loading language '{sorted(absent)[0]}'")
        return f"text [{lang}]"


def osd_text(script, confidence):
    """The text Tesseract's OSD prints for a page (the lines Stage 1 reads)."""
    return (f"Page number: 0\nOrientation in degrees: 0\nRotate: 0\n"
            f"Orientation confidence: 15.3\nScript: {script}\n"
            f"Script confidence: {confidence}\n")


@pytest.fixture()
def tesseract(monkeypatch):
    """Fresh resolution and installed-language caches, so one test's setting does
    not leak into another."""
    monkeypatch.setattr(s1, "_ocr_langs_in_use", {})
    monkeypatch.setattr(s1, "_installed_cache", {})
    monkeypatch.setattr(s1, "_OCR_AVAILABLE", True)

    def install(installed, list_error=None, osd=None):
        fake = _FakeTesseract(installed, list_error, osd)
        monkeypatch.setattr(s1, "pytesseract", fake, raising=False)
        return fake

    return install


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]


# ── Default and override ─────────────────────────────────────────────────────

def test_the_default_is_auto(monkeypatch, tesseract):
    tesseract(["eng", "fra", "ukr", "pol", "rus", "osd"])
    monkeypatch.delenv("OCR_LANG", raising=False)
    assert s1.OCR_LANG_DEFAULT == "auto"
    assert s1.ocr_lang() == "auto"


@pytest.mark.parametrize("value", ["", "   "])
def test_a_blank_setting_is_the_default(monkeypatch, tesseract, value):
    tesseract(["eng"])
    monkeypatch.setenv("OCR_LANG", value)
    assert s1.ocr_lang() == "auto"


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
    assert captured_env()["OCR_LANG"] == "auto"


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


# Every Tesseract language that OCR_LANG=auto can name, Latin set included.
_PACK_LANGS = sorted({lang for langs in s1._OCR_SCRIPT_LANGS.values() for lang in langs.split("+")}
                     | set(MULTI.split("+")))


def test_the_image_installs_a_pack_for_every_language_auto_can_name():
    installed = _runtime_apt_install().split()
    for lang in _PACK_LANGS:
        if lang == "eng":
            pack = "tesseract-ocr"                          # English comes with the base package
        else:
            pack = "tesseract-ocr-" + lang.replace("_", "-")   # chi_sim -> tesseract-ocr-chi-sim
        assert pack in installed, f"{pack} is missing from the runtime apt-get install"


# ── OCR_LANG=auto: script detection and the language set of each script ──────

def test_each_script_reads_with_its_own_languages():
    assert s1._languages_for_script("Cyrillic", 12.0) == ("Cyrillic", "rus+ukr")
    assert s1._languages_for_script("Han", 12.0) == ("Han", "chi_sim+chi_tra")
    assert s1._languages_for_script("Japanese", 12.0) == ("Japanese", "jpn")
    assert s1._languages_for_script("Hangul", 12.0) == ("Hangul", "kor")
    assert s1._languages_for_script("Arabic", 12.0) == ("Arabic", "ara+fas+urd")
    assert s1._languages_for_script("Devanagari", 12.0) == ("Devanagari", "hin")
    assert s1._languages_for_script("Bengali", 12.0) == ("Bengali", "ben")
    assert s1._languages_for_script("Hebrew", 12.0) == ("Hebrew", "heb")
    assert s1._languages_for_script("Thai", 12.0) == ("Thai", "tha")


def test_latin_is_the_latin_set():
    assert s1._languages_for_script("Latin", 12.0) == ("Latin", s1._OCR_LATIN_LANGS)
    assert s1._OCR_LATIN_LANGS == "eng+fra+spa+por+deu+ita+pol+tur+vie+ind"


@pytest.mark.parametrize("script, confidence", [
    ("", 0.0),                                # OSD gave no script
    ("Cyrillic", s1._OSD_MIN_SCRIPT_CONFIDENCE - 0.01),   # low confidence
    ("Greek", 12.0),                          # a script with no set of its own
])
def test_an_unusable_script_reads_in_the_latin_set(script, confidence):
    reported, langs = s1._languages_for_script(script, confidence)
    assert langs == s1._OCR_LATIN_LANGS
    assert reported == ("unknown" if not script or confidence < s1._OSD_MIN_SCRIPT_CONFIDENCE
                        else "Greek")


def test_the_osd_lines_are_read_into_script_and_confidence(tesseract):
    tesseract(["osd"], osd=osd_text("Cyrillic", "9.25"))
    assert s1._page_script(object()) == ("Cyrillic", 9.25)


def test_an_osd_failure_is_no_script(tesseract):
    tesseract(["osd"], osd=RuntimeError("Too few characters. Skipping this page"))
    assert s1._page_script(object()) == ("", 0.0)


def test_osd_output_without_a_script_line_is_no_script(tesseract):
    tesseract(["osd"], osd="Page number: 0\nRotate: 0\n")
    assert s1._page_script(object()) == ("", 0.0)


def test_a_cyrillic_page_is_read_with_rus_and_ukr(monkeypatch, tesseract):
    fake = tesseract(["eng", "fra", "rus", "ukr"], osd=osd_text("Cyrillic", "9.0"))
    monkeypatch.setenv("OCR_LANG", "auto")
    assert s1.ocr_page_lang(object()) == "rus+ukr"
    assert fake.osd_calls == 1


def test_a_page_whose_osd_fails_is_read_with_the_latin_set(monkeypatch, tesseract):
    tesseract(["eng", "fra", "spa"], osd=RuntimeError("Too few characters"))
    monkeypatch.setenv("OCR_LANG", "auto")
    assert s1.ocr_page_lang(object()) == "eng+fra+spa"


def test_a_low_confidence_page_is_read_with_the_latin_set(monkeypatch, tesseract):
    tesseract(["eng", "rus", "ukr"], osd=osd_text("Cyrillic", "0.2"))
    monkeypatch.setenv("OCR_LANG", "auto")
    assert s1.ocr_page_lang(object()) == "eng"


def test_a_script_with_no_installed_language_reads_in_the_latin_set(monkeypatch, tesseract, caplog):
    tesseract(["eng", "fra"], osd=osd_text("Arabic", "9.0"))
    monkeypatch.setenv("OCR_LANG", "auto")
    with caplog.at_level(logging.WARNING):
        assert s1.ocr_page_lang(object()) == "eng+fra"
        assert s1.ocr_page_lang(object()) == "eng+fra"
    warnings = [w for w in _warnings(caplog) if "Arabic pages" in w]
    assert len(warnings) == 1                      # once per script, not per page


def test_a_script_is_filtered_by_the_installed_languages(monkeypatch, tesseract, caplog):
    tesseract(["eng", "fra", "spa", "osd"], osd=osd_text("Latin", "14.0"))
    monkeypatch.setenv("OCR_LANG", "auto")
    with caplog.at_level(logging.WARNING):
        assert s1.ocr_page_lang(object()) == "eng+fra+spa"
    assert any("no data for" in w and "por" in w for w in _warnings(caplog))


def test_auto_is_reported_as_the_setting_in_the_run_record(monkeypatch, tesseract):
    from api.run_config import captured_env

    tesseract(["eng"])
    monkeypatch.setenv("OCR_LANG", "auto")
    assert captured_env()["OCR_LANG"] == "auto"


# ── Explicit values do not run OSD ───────────────────────────────────────────

def test_an_explicit_value_does_not_run_osd(monkeypatch, tesseract):
    fake = tesseract(["eng", "fra"], osd=osd_text("Cyrillic", "9.0"))
    monkeypatch.setenv("OCR_LANG", "eng+fra")
    assert s1.ocr_page_lang(object()) == "eng+fra"
    assert fake.osd_calls == 0


# ── The stage report: pages, languages and scripts per document ──────────────

def test_the_summary_counts_pages_languages_and_scripts(monkeypatch, tesseract):
    tesseract(["eng", "fra", "spa", "osd", "rus", "ukr"], osd=osd_text("Latin", "14.0"))
    monkeypatch.setenv("OCR_LANG", "auto")
    with s1.ocr_summary() as summary:
        s1.ocr_page_lang(object())
        s1.ocr_page_lang(object())
    assert summary == {"pages": 2,
                       "languages": {"eng+fra+spa": 2},
                       "scripts": {"Latin": 2}}


def test_the_summary_of_an_explicit_value_has_no_scripts(monkeypatch, tesseract):
    tesseract(["eng"])
    monkeypatch.setenv("OCR_LANG", "eng")
    with s1.ocr_summary() as summary:
        s1.ocr_page_lang(object())
    assert summary == {"pages": 1, "languages": {"eng": 1}}


def test_the_summary_stays_empty_without_an_ocr_page(monkeypatch, tesseract):
    tesseract(["eng"])
    with s1.ocr_summary() as summary:
        pass
    assert summary == {}


def test_pages_outside_the_summary_are_not_counted(monkeypatch, tesseract):
    tesseract(["eng"])
    monkeypatch.setenv("OCR_LANG", "eng")
    s1.ocr_page_lang(object())                     # no ocr_summary() is collecting
    with s1.ocr_summary() as summary:
        pass
    assert summary == {}


def test_a_scanned_page_is_read_with_the_languages_of_its_script(monkeypatch, tesseract, tmp_path):
    fake = tesseract(["eng", "rus", "ukr", "osd"], osd=osd_text("Cyrillic", "9.0"))
    monkeypatch.setenv("OCR_LANG", "auto")
    monkeypatch.setattr(s1, "convert_from_path",
                        lambda path, dpi, first_page, last_page: [SimpleNamespace(close=lambda: None)],
                        raising=False)
    assert s1._ocr_page(tmp_path / "scan.pdf", 1) == "text [rus+ukr]"
    assert fake.read_with == ["rus+ukr"]
