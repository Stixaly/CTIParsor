from pathlib import Path

import pytest

from pipeline.stage1_ingestion import _parse_pdf_date, chunk_text, extract_reference_date, ingest

FIXTURES = Path(__file__).parent / "fixtures"


def test_ingest_txt():
    text = ingest(str(FIXTURES / "sample_report.txt"))
    assert len(text) > 100
    assert "APT29" in text


def test_ingest_unsupported_format(tmp_path):
    f = tmp_path / "test.xyz"
    f.write_text("hello")
    with pytest.raises(ValueError, match="Format non supporté"):
        ingest(str(f))


def test_ingest_missing_file():
    with pytest.raises(FileNotFoundError):
        ingest("nonexistent_file.txt")


def test_chunk_text_splits_on_double_newline():
    long_text = "\n\n".join([f"Paragraph {i}. " + "word " * 100 for i in range(20)])
    chunks = chunk_text(long_text, max_chars=500)
    assert len(chunks) > 1
    for chunk in chunks:
        assert len(chunk) <= 600  # tolérance pour le dernier paragraphe


def test_chunk_text_fallback_single_newline():
    # PDF-style text: no double newlines
    long_text = "\n".join([f"Line {i}. " + "word " * 50 for i in range(30)])
    chunks = chunk_text(long_text, max_chars=500)
    assert len(chunks) > 1


def test_chunk_text_fallback_monolithic():
    # Single block, no newlines at all — with overlap=0 each chunk must be ≤ max_chars
    long_text = "word " * 1000
    chunks = chunk_text(long_text, max_chars=500, overlap=0)
    assert len(chunks) > 1
    for chunk in chunks:
        assert len(chunk) <= 500


def test_chunk_text_overlap_prepends_tail():
    # Overlap must prepend the tail of chunk[i] to chunk[i+1]
    long_text = "word " * 1000   # 5000 chars, no newlines
    chunks_no = chunk_text(long_text, max_chars=500, overlap=0)
    chunks_ov = chunk_text(long_text, max_chars=500, overlap=100)
    # More chunks (or same) with overlap — each non-first chunk is larger
    assert len(chunks_ov) >= len(chunks_no)
    # Every chunk after the first should be larger than max_chars by up to ~100
    for chunk in chunks_ov[1:]:
        assert len(chunk) > 500   # overlap makes it bigger than max_chars
        assert len(chunk) <= 500 + 100 + 5   # small tolerance for separator


# ── extract_reference_date / _parse_pdf_date (TimeML/TIMEX3 DCT anchor) ───────────────

class TestParsePdfDate:
    def test_parses_full_timestamp_with_utc_designator(self):
        from datetime import datetime, timezone
        assert _parse_pdf_date("D:20230315120000Z00'00'") == \
            datetime(2023, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_parses_full_timestamp_with_offset(self):
        # The offset itself is ignored (see docstring) — only Y/M/D/H/M/S matter.
        from datetime import datetime, timezone
        assert _parse_pdf_date("D:20260913151556+00'00'") == \
            datetime(2026, 9, 13, 15, 15, 56, tzinfo=timezone.utc)

    def test_parses_date_only_no_time(self):
        from datetime import datetime, timezone
        assert _parse_pdf_date("D:20230315") == datetime(2023, 3, 15, tzinfo=timezone.utc)

    def test_missing_d_prefix_still_parses(self):
        """Non-compliant PDF producers sometimes omit the 'D:' prefix."""
        from datetime import datetime, timezone
        assert _parse_pdf_date("20230315120000") == \
            datetime(2023, 3, 15, 12, 0, 0, tzinfo=timezone.utc)

    def test_none_input_returns_none(self):
        assert _parse_pdf_date(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_pdf_date("") is None

    def test_garbage_string_returns_none_not_raise(self):
        assert _parse_pdf_date("not a date at all") is None

    def test_implausible_year_returns_none(self):
        assert _parse_pdf_date("D:18500101000000") is None


class TestExtractReferenceDate:
    def test_docx_uses_core_properties_created(self, tmp_path):
        from datetime import datetime, timezone

        import docx

        path = tmp_path / "report.docx"
        doc = docx.Document()
        doc.add_paragraph("APT29 used WellMess.")
        doc.core_properties.created = datetime(2023, 3, 15, tzinfo=timezone.utc)
        doc.save(str(path))

        result = extract_reference_date(str(path))
        assert result == datetime(2023, 3, 15, tzinfo=timezone.utc)

    def test_txt_has_no_metadata_returns_none(self, tmp_path):
        path = tmp_path / "report.txt"
        path.write_text("APT29 used WellMess.")
        assert extract_reference_date(str(path)) is None

    def test_html_has_no_metadata_returns_none(self, tmp_path):
        path = tmp_path / "report.html"
        path.write_text("<html><body>APT29 used WellMess.</body></html>")
        assert extract_reference_date(str(path)) is None

    def test_missing_file_returns_none_not_raise(self):
        assert extract_reference_date("/nonexistent/path/report.pdf") is None


def test_chunk_text_no_empty_chunks():
    text = "Short text."
    chunks = chunk_text(text)
    assert len(chunks) == 1
    assert chunks[0] == "Short text."
