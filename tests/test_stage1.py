from pathlib import Path

import pytest

from pipeline.stage1_ingestion import chunk_text, ingest

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


def test_chunk_text_no_empty_chunks():
    text = "Short text."
    chunks = chunk_text(text)
    assert len(chunks) == 1
    assert chunks[0] == "Short text."
