"""IoCs in a PDF table column that wraps them come back whole (audit B 8.1.5).

The fixtures are a report whose 34 IoCs (12 SHA-256, 8 domains, 8 IPv4, 6
URLs, defanged) sit in a value column of 38 % or 20 % of the table, printed
by Chromium (scripts/make_pdf_table_fixtures.py).  Before the table pass,
Stage 1 + Stage 2 found 16 of 34 at 38 % (no hash, no whole URL) and 1 of 34
at 20 %, with markitdown or without it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pipeline import stage1_ingestion as s1
from pipeline.stage2_extraction import extract_entities

FIXTURES = Path(__file__).parent / "fixtures" / "pdf_tables"
TRUTH = json.loads((FIXTURES / "truth.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("cell, expected", [
    ("6e16930f100e4505c66e0a4760912\n0d6d2c2c7d57c6e59f3f41aae35ba\n65adf7",
     ("6e16930f100e4505c66e0a47609120d6d2c2c7d57c6e59f3f41aae35ba65adf7", True)),
    ("hxxps://cloud-portal3[.]com/u\npdate/cdn3[.]php?id=74812",
     ("hxxps://cloud-portal3[.]com/update/cdn3[.]php?id=74812", True)),
    ("84[.]154[.]8[.]2\n00", ("84[.]154[.]8[.]200", True)),
    ("README-IF-YOU-SEE-THIS-\nYOUVE-BEEN-HACKED.TXT", ("README-IF-YOU-SEE-THIS-YOUVE-BEEN-HACKED.TXT", True)),
    ("Payload\ndownload", ("Payload download", False)),            # not IoC-shaped once glued
    ("Pre-configured Windows\nagent", ("Pre-configured Windows agent", False)),   # prose
    ("Loader sample", ("Loader sample", False)),
    (None, ("", False)),
])
def test_a_wrapped_cell_is_glued_only_into_an_ioc(cell, expected):
    assert s1._join_cell(cell) == expected


def _recall(pdf: Path) -> tuple[int, int, str]:
    text = s1.ingest(str(pdf))
    found = {(e.entity_type.value, e.value.lower()) for e in extract_entities(text)}
    expected = [(kind, v.lower()) for kind, values in TRUTH.items() for v in values]
    return sum(1 for e in expected if e in found), len(expected), text


@pytest.mark.parametrize("name", ["ioc_table_38pct.pdf", "ioc_table_20pct.pdf"])
def test_the_iocs_of_a_wrapped_table_column_are_found(name):
    hit, total, text = _recall(FIXTURES / name)
    assert hit / total >= 0.95, f"{hit}/{total} IoCs from {name}"
    assert "[[table rows rejoined from wrapped cells: page 1]]" in text


def test_rows_with_no_wrapped_ioc_are_not_repeated():
    rows = s1._rejoined_table_rows(FIXTURES / "ioc_table_38pct.pdf")
    lines = [line for line in rows.splitlines() if line and not line.startswith("[[table")]
    assert all(line.count(" | ") == 2 for line in lines)
    # 35 rows with the header; at 38 % the short domains and addresses fit on
    # one line, and their rows, already whole in the body, are not repeated.
    assert 0 < len(lines) < 34


def test_a_pdf_without_wrapped_cells_is_read_as_before(monkeypatch):
    monkeypatch.setattr(s1, "_rejoined_table_rows", lambda path, skip_pages=frozenset(): "")
    assert s1._with_table_rows("body text", Path("r.pdf")) == "body text"


def test_the_table_pass_stops_at_its_caps(monkeypatch, caplog):
    # The caps bound how many tables the finder walks through, checked after
    # each table: the first one, past the cap, is the last one read.
    monkeypatch.setattr(s1, "_MAX_CELLS", 10)
    rows = s1._rejoined_table_rows(FIXTURES / "ioc_table_20pct.pdf")
    assert "table pass stopped at 1 tables" in caplog.text
    assert rows.count("[[table rows rejoined") == 1


def test_an_unreadable_pdf_costs_the_table_pass_only(tmp_path, caplog):
    broken = tmp_path / "broken.pdf"
    broken.write_bytes(b"%PDF-1.7 not really")
    assert s1._rejoined_table_rows(broken) == ""
    assert "tables not read" in caplog.text
