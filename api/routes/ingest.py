"""
Alternative ingestion entry points — pasted text and captured web pages.

Both endpoints land in exactly the same place as a file upload: a file under
uploads/{job_id}{suffix} plus a `jobs` row, then run_pipeline_async().  Nothing
downstream of Stage 1 can tell the three apart, which is the point — the review
UI, the source viewer and the STIX mapping all keep working unchanged.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from api.db import _lock, get_conn, now_iso
from api.logging_config import get_logger
from api.main import limiter
from api.routes.upload import _MARKING_LEVELS, UPLOADS_DIR
from api.worker import run_pipeline_async
from pipeline import web_capture
from pipeline.stage1_ingestion import html_to_text

logger = get_logger(__name__)

router: APIRouter = APIRouter(prefix="/api/ingest", tags=["ingest"])

# A pasted report shorter than this is almost always a mis-paste (a URL, a hash,
# an empty clipboard).  The pipeline would run all five stages on it and produce
# an empty bundle, so reject it at the door instead.
_MIN_TEXT_CHARS = 20

# 2 MB of text.  The file-upload path allows 50 MB, but that budget is mostly
# PDF structure: 2 MB of plain text is roughly 350k words, far past any real
# report, and it all has to survive a JSON round-trip.
_MAX_TEXT_CHARS = 2_000_000

# Markdown signals.  A pasted report is stored as .md rather than .txt when at
# least _MARKDOWN_MIN_SIGNALS of these match, because the chunker splits on
# blank lines and headings, and a Markdown report that lands in a .txt file
# keeps its structure either way — but the source viewer renders it.
_MARKDOWN_PATTERNS = (
    r"^\#{1,6}\s+\S",              # ATX heading
    r"^\s{0,3}([-*+]|\d+\.)\s+\S",  # bullet or ordered list item
    r"^\s*```",                     # fenced code block
    r"^\s*\|.+\|\s*$",              # table row
    r"\[[^\]]+\]\([^)]+\)",         # inline link
    r"\*\*[^*\n]+\*\*",             # bold
)
_MARKDOWN_MIN_SIGNALS = 2

# Wall-clock ceiling for a capture, in seconds.  Playwright has its own
# per-navigation timeout; this one bounds the whole call so a page that keeps
# the renderer busy cannot hold an API worker thread indefinitely.
_CAPTURE_DEADLINE_S = 45.0
_CAPTURE_TIMEOUT_MS = 30_000

_MARKDOWN_RE = tuple(re.compile(p, re.MULTILINE) for p in _MARKDOWN_PATTERNS)


class TextIngestRequest(BaseModel):
    text: str
    title: str | None = None
    tlp_level: str | None = None
    pap_level: str | None = None


class UrlIngestRequest(BaseModel):
    url: str
    enable_js: bool = False
    tlp_level: str | None = None
    pap_level: str | None = None


def _clean_marking(value: str | None, field: str) -> str | None:
    """Normalise a TLP/PAP marking to upper case, rejecting unknown levels."""
    if value is None:
        return None
    v = value.strip().upper()
    if not v:
        return None
    if v not in _MARKING_LEVELS:
        raise HTTPException(400, f"Invalid {field}. Valid: {', '.join(sorted(_MARKING_LEVELS))}")
    return v


def _looks_like_markdown(text: str) -> bool:
    """True when enough Markdown signals appear to store the paste as .md."""
    count = sum(1 for rx in _MARKDOWN_RE if rx.search(text))
    return count >= _MARKDOWN_MIN_SIGNALS


# Pasted HTML.  An analyst who hits a page the URL capture cannot reach — one
# behind bot protection, say — falls back to "view source" and pastes the markup.
# Stored as .txt it reaches the extractor with its tags intact, and `<div
# class="post">` becomes content.  Detected here so it lands as .html, where
# Stage 1 already knows to strip it.
#
# A document declaring itself is decisive on its own; anything else needs two
# distinct tags, so prose that merely mentions "<script>" is not misfiled.
_HTML_STRONG_RE = re.compile(r"<!DOCTYPE\s+html|<html[\s>]", re.IGNORECASE)

_HTML_TAG_PATTERNS = (
    r"<body[\s>]",
    r"<div[\s>]",
    r"<p[\s>]",
    r"<span[\s>]",
    r"<table[\s>]",
    r"<t[rdh][\s>]",
    r"<h[1-6][\s>]",
    r"<[uo]l[\s>]",
    r"<li[\s>]",
    r"<a\s[^>]*href",
    r"<br\s*/?>",
    r"<img\s[^>]*src",
)
_HTML_MIN_SIGNALS = 2
_HTML_TAG_RE = tuple(re.compile(p, re.IGNORECASE) for p in _HTML_TAG_PATTERNS)


def _looks_like_html(text: str) -> bool:
    """True when the paste is an HTML document or fragment, not prose."""
    if _HTML_STRONG_RE.search(text):
        return True
    count = sum(1 for rx in _HTML_TAG_RE if rx.search(text))
    return count >= _HTML_MIN_SIGNALS



def _timestamp_slug() -> str:
    """UTC stamp used to name an untitled paste."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _start_job(
    job_id: str, dest: Path, filename: str, tlp: str | None, pap: str | None
) -> dict[str, object]:
    """Insert the jobs row and hand the file to the pipeline, as /upload does."""
    ts = now_iso()
    with _lock:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, original_filename, status, tlp_level, pap_level, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (job_id, filename, "uploaded", tlp, pap, ts, ts),
            )
            conn.commit()

    run_pipeline_async(job_id, str(dest), filename)

    return {"job_id": job_id, "filename": filename, "status": "processing"}


@router.post("/text")
@limiter.limit("20/minute")
async def ingest_text(request: Request, body: TextIngestRequest):
    tlp = _clean_marking(body.tlp_level, "tlp_level")
    pap = _clean_marking(body.pap_level, "pap_level")

    text = body.text
    if not isinstance(text, str):
        raise HTTPException(400, "text must be a string")
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    stripped_len = len(text.strip())
    if stripped_len < _MIN_TEXT_CHARS:
        raise HTTPException(400, f"Pasted text is too short ({stripped_len} chars, minimum {_MIN_TEXT_CHARS})")

    if len(text) > _MAX_TEXT_CHARS:
        raise HTTPException(413, f"Pasted text is too large ({len(text)} chars, maximum {_MAX_TEXT_CHARS})")

    # HTML first: a <li> or a <table> would also trip the Markdown list and
    # table patterns, and misfiling markup as Markdown keeps the tags.
    if _looks_like_html(text):
        suffix = ".html"
    elif _looks_like_markdown(text):
        suffix = ".md"
    else:
        suffix = ".txt"

    if suffix == ".html":
        extracted = html_to_text(text).strip()
        if len(extracted) < _MIN_TEXT_CHARS:
            raise HTTPException(
                400,
                f"That looks like HTML, but only {len(extracted)} characters of "
                f"text survive once the markup is stripped (minimum "
                f"{_MIN_TEXT_CHARS}). Paste the article text instead.",
            )

    slug = web_capture._slugify(body.title or "")
    if not slug:
        slug = f"pasted-{_timestamp_slug()}"
    filename = slug + suffix

    job_id = str(uuid4())
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOADS_DIR / f"{job_id}{suffix}"

    try:
        dest.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise HTTPException(500, "Could not store pasted text") from exc

    logger.info(
        "Ingested pasted text job_id=%s suffix=%s chars=%d",
        job_id, suffix, len(text),
    )

    return _start_job(job_id, dest, filename, tlp, pap)


@router.post("/url")
@limiter.limit("5/minute")
async def ingest_url(request: Request, body: UrlIngestRequest):
    tlp = _clean_marking(body.tlp_level, "tlp_level")
    pap = _clean_marking(body.pap_level, "pap_level")

    if not web_capture._PLAYWRIGHT_AVAILABLE:
        raise HTTPException(
            503,
            "Web capture is unavailable on this server — Playwright is not "
            "installed. Paste the report text instead.",
        )

    try:
        safe_url = web_capture.validate_url(body.url)
    except web_capture.CaptureError as exc:
        raise HTTPException(400, str(exc)) from exc

    job_id = str(uuid4())
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOADS_DIR / f"{job_id}.pdf"
    # Render to a staging name and promote it only on success.  asyncio cannot
    # cancel a thread: when the deadline below fires, the capture is still
    # running and will finish writing whatever it was given.  Pointing it at
    # `.part` means that straggler cannot land on the name the job will use, so
    # a timed-out capture never leaves a half-rendered PDF where the pipeline
    # would read it.
    staging = dest.with_name(f"{job_id}.pdf.part")

    try:
        result = await asyncio.wait_for(
            asyncio.to_thread(
                web_capture.capture_url_to_pdf,
                safe_url,
                staging,
                enable_js=body.enable_js,
                timeout_ms=_CAPTURE_TIMEOUT_MS,
            ),
            timeout=_CAPTURE_DEADLINE_S,
        )
    except asyncio.TimeoutError as exc:
        staging.unlink(missing_ok=True)
        raise HTTPException(
            504, f"Capturing {safe_url} timed out after {_CAPTURE_DEADLINE_S:.0f}s"
        ) from exc
    # Ordered subclass-first: CaptureUnavailable means the server cannot capture
    # at all (503), CaptureError means this page could not be captured (502).
    # `_PLAYWRIGHT_AVAILABLE` above only proves the Python package imports — the
    # browser binary is a separate install and fails here, not there.
    except web_capture.CaptureUnavailable as exc:
        staging.unlink(missing_ok=True)
        raise HTTPException(503, str(exc)) from exc
    except web_capture.CaptureError as exc:
        staging.unlink(missing_ok=True)
        raise HTTPException(502, str(exc)) from exc

    try:
        staging.replace(dest)
    except OSError as exc:
        staging.unlink(missing_ok=True)
        raise HTTPException(500, "Could not store the captured page") from exc

    # A capture produces TWO artefacts, and they have different jobs.
    #
    #   {job_id}.pdf  the archive.  Immutable, laid out as published, and what
    #                 `/jobs/{id}/source` streams into the review viewer.
    #   {job_id}.txt  the rendered DOM text, and what the pipeline reads.
    #
    # They are not interchangeable.  Measured over 6 CTI pages, ingesting the
    # PDF keeps 99.6% of the characters but only 72.2% of the observables: a
    # 64-character hash inside a narrow table column wraps into 24-character
    # fragments, which the PDF text layer then interleaves with the cells beside
    # it.  On the COLDRIVER report that is 9 of 12 SHA-256 hashes gone.  The DOM
    # has no columns to wrap in, so it keeps all 12 (ADR-0029).
    text_dest = dest.with_suffix(".txt")
    try:
        text_dest.write_text(result.dom_text, encoding="utf-8")
    except OSError as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, "Could not store the captured text") from exc

    # `original_filename` stays .pdf: it is what the source viewer keys its
    # renderer off, and the PDF is what the analyst should be looking at.
    filename = web_capture.suggest_filename(result)

    logger.info(
        "Captured URL job_id=%s final_url=%s pdf=%dB text=%d chars blocked=%d js=%s",
        job_id, result.final_url, result.bytes_written, result.rendered_chars,
        result.blocked_requests, result.js_enabled,
    )

    response = _start_job(job_id, text_dest, filename, tlp, pap)
    response["source_url"] = result.final_url
    response["blocked_requests"] = result.blocked_requests
    response["rendered_chars"] = result.rendered_chars
    return response

