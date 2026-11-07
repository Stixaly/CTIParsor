"""POST /api/upload, without libmagic: the `filetype` fallback reads text and HTML.

#489: the UTF-8 check of a text file reads the first megabyte only, so a
character cut by that boundary is not an error, and a broken one anywhere in
the file still is.  #490: an HTML page has no `filetype` kind, so the fallback
recognises it by its markup, and refuses what is not HTML.

The worker is stubbed, as in tests/test_upload_route.py."""
from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from api.paths import uploads_dir

_MIB = 1024 * 1024
_PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32
_HTML = b"<!DOCTYPE html><html><body>Texte du rapport</body></html>"


@pytest.fixture()
def client(temp_db_client):
    import api.main

    api.main.limiter.reset()                  # 10/minute is shared by every test
    with patch("api.worker.run_pipeline_async", return_value="started"):
        yield temp_db_client


@pytest.fixture()
def no_libmagic(monkeypatch):
    """python-magic missing or broken: the route falls back to `filetype`."""
    def broken(*a, **kw):
        raise RuntimeError("libmagic not found")

    monkeypatch.setattr("api.routes.upload.magic.from_buffer", broken)


@pytest.fixture()
def uploads():
    path = uploads_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _upload(client, filename: str, content: bytes):
    return client.post("/api/upload", files={"file": (filename, io.BytesIO(content), "application/octet-stream")})


# ── #489: a multibyte character cut by the first megabyte ────────────────────

def test_a_character_cut_by_the_first_megabyte_is_accepted(client, no_libmagic, uploads):
    """(#489) 1 048 575 ASCII bytes then `é` (C3 A9): the file is valid UTF-8, but
    the MIME read stops after C3.  Before the fix, the prefix's strict decode
    refused it: 400 'not valid UTF-8'."""
    content = b"a" * (_MIB - 1) + "é".encode()
    assert _upload(client, "r.txt", content).status_code == 200


def test_a_character_completed_inside_the_first_megabyte_is_accepted(client, no_libmagic):
    """(#489) The multibyte case that already passed: the whole character is read."""
    assert _upload(client, "r.txt", b"a" * (_MIB - 2) + "é".encode()).status_code == 200


def test_a_file_that_ends_inside_a_character_is_still_refused(client, no_libmagic):
    """(#489) A file shorter than the read is read whole: a cut character at its
    end is invalid, the allowance does not apply."""
    resp = _upload(client, "r.txt", b"rapport \xc3")
    assert resp.status_code == 400 and "not valid UTF-8" in resp.json()["detail"]


def test_an_invalid_byte_inside_the_first_megabyte_is_still_refused(client, no_libmagic):
    """(#489) The allowance covers only the last bytes read: a bad byte before them is refused."""
    resp = _upload(client, "r.txt", b"\xff" + b"a" * (_MIB + 10))
    assert resp.status_code == 400 and "not valid UTF-8" in resp.json()["detail"]


# ── #490: HTML through the fallback ──────────────────────────────────────────

@pytest.mark.parametrize("name", ["r.html", "r.htm"])
def test_an_html_page_is_accepted_when_libmagic_is_unavailable(client, no_libmagic, name):
    """(#490) `filetype` knows no HTML: the markup is what the fallback checks.
    Before the fix: 400 'Could not determine file type'."""
    assert _upload(client, name, _HTML).status_code == 200


def test_html_with_no_markup_is_refused_without_libmagic(client, no_libmagic):
    """(#490) Plain text under an .html name is not a page: still refused."""
    resp = _upload(client, "r.html", b"just some report text")
    assert resp.status_code == 400 and "Could not determine file type" in resp.json()["detail"]


def test_a_png_under_an_html_name_is_refused_as_an_image(client, no_libmagic):
    """(#490) A binary `filetype` recognises is judged by its kind, as before: 415."""
    resp = _upload(client, "r.html", _PNG)
    assert resp.status_code == 415 and "image/png" in resp.json()["detail"]


def test_html_that_is_not_utf8_is_refused_without_libmagic(client, no_libmagic):
    """(#490) The markup alone does not make it a page: the bytes must decode as UTF-8."""
    resp = _upload(client, "r.html", b"<html><body>\xff\xfe</body></html>")
    assert resp.status_code == 400 and "Could not determine file type" in resp.json()["detail"]
