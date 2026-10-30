"""The Report's STIX `description` and attached file (ADR-0093).

OpenCTI shows a STIX `description` as GitHub-flavoured Markdown, and imports an
`x_opencti_files` entry as a file attached to the object.  Stage 4 gives the
Report both:

* the `description`: a "Source document" block (file name, SHA-256, publication
  date, whether the original is attached), the count of each object type
  CTIParsor extracted, then the document text as it was read
  (`report_description`);
* the source file itself, base64 in `x_opencti_files` (`opencti_file`).

Standard library and `pipeline.markdown_text` only: the functions take the
values Stage 4 has and return the strings and dicts it stores.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

from pipeline.markdown_text import collapse_whitespace, escape_inline, escape_line


def text_to_markdown(text: str) -> str:
    """`text` as Markdown that displays it as it was extracted, line by line.

    A Markdown source file is made literal too: kept as Markdown, its links
    would be live in OpenCTI and its images fetched, from wherever the report's
    author pointed them, by the browser of each analyst who opens the Report.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    paragraphs: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        stripped = line.rstrip()
        if stripped:
            current.append(escape_line(stripped))
        elif current:
            # A run of blank lines is one paragraph break, and none at the ends.
            paragraphs.append(current)
            current = []
    if current:
        paragraphs.append(current)
    # Two spaces end every line but a paragraph's last: a hard line break, so a
    # DOCX or HTML export with one paragraph per line does not run them together.
    return "\n\n".join("  \n".join(paragraph) for paragraph in paragraphs)


def report_description(text: str, *, filename: str, source_hash: str | None,
                       published: Mapping[str, str] | None, counts: Mapping[str, int],
                       file_attached: bool) -> str:
    """The Report's `description`: the source, what was extracted, the text.

    Blocks are separated by a blank line.  A block with nothing to show is left
    out, and the description is "" when every block is.
    """
    blocks: list[str] = []
    source = _source_lines(filename, source_hash, published, file_attached)
    if source:
        blocks.append("## Source document\n\n" + "\n".join(source))
    table = _counts_table(counts)
    if table:
        blocks.append("## What CTIParsor extracted\n\n" + "\n".join(table))
    body = text_to_markdown(text)
    if body:
        blocks.append("## Document text\n\n" + body)
    return "\n\n".join(blocks)


def opencti_file(name: str, data: bytes, mime_type: str) -> dict[str, Any]:
    """An `x_opencti_files` entry: the source file, attached to the Report on import."""
    # CTIParsor has done the extraction already, and an import connector would
    # run it again: no_trigger_import.  No object_marking_refs: OpenCTI then gives
    # the file the markings of the object it is attached to, the Report's TLP.
    return {
        "name": name,
        "data": base64.b64encode(data).decode("ascii"),
        "mime_type": mime_type,
        "no_trigger_import": True,
    }


def _source_lines(filename: str, source_hash: str | None,
                  published: Mapping[str, str] | None, file_attached: bool) -> list[str]:
    # Collapsed: a line break in a value would end the list item.
    lines: list[str] = []
    if collapse_whitespace(filename):
        lines.append(f"- **File:** {escape_inline(collapse_whitespace(filename))}")
    if source_hash:
        lines.append(f"- **SHA-256:** `{source_hash}`")
    if published and collapse_whitespace(published.get("value") or ""):
        when = escape_inline(collapse_whitespace(published["value"]))
        if collapse_whitespace(published.get("source") or ""):
            when += f" ({escape_inline(collapse_whitespace(published['source']))})"
        lines.append(f"- **Published:** {when}")
    if file_attached:
        lines.append("- **Attached:** the original file is attached to this report.")
    return lines


def _counts_table(counts: Mapping[str, int]) -> list[str]:
    """The object types with a count, most frequent first, then by type name."""
    rows = sorted((kind, n) for kind, n in counts.items() if n > 0)
    # A stable sort on the count keeps the type order between equal counts.
    rows.sort(key=lambda row: -row[1])
    if not rows:
        return []
    return ["| Object type | Count |", "|---|---|",
            *(f"| `{kind}` | {n} |" for kind, n in rows)]
