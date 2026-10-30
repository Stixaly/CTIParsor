"""The Report's `description` and attached file, as Markdown (ADR-0093)."""
import base64

from pipeline.report_markdown import opencti_file, report_description, text_to_markdown

HASH = "9f2c4b1e7a0d3c58e6b9f14a2d7c0e83b5a16f2d9c4e7b08a3d1f6c52e9b7a04"
PUBLISHED = {"value": "2023-03-15", "source": "header"}


def test_lines_of_one_paragraph_end_with_a_hard_break():
    # a DOCX or HTML export has one paragraph per line: the breaks keep them apart
    assert text_to_markdown("one\ntwo\nthree") == "one  \ntwo  \nthree"


def test_blank_lines_collapse_to_one_paragraph_break():
    assert text_to_markdown("Para one.\n\n\n\nPara two.") == "Para one.\n\nPara two."


def test_blank_ends_go_and_a_line_of_spaces_is_blank():
    assert text_to_markdown("\n  \nfirst\n   \nsecond\n\n  ") == "first\n\nsecond"


def test_trailing_spaces_go():
    assert text_to_markdown("alpha   \nbeta\t \n") == "alpha  \nbeta"


def test_a_heading_mark_at_a_line_start_is_escaped():
    assert text_to_markdown("# Not a heading") == "\\# Not a heading"


def test_list_markers_at_a_line_start_are_escaped():
    assert text_to_markdown("- item\n+ other\n* star") == "\\- item  \n\\+ other  \n\\* star"


def test_ordered_list_numbers_are_escaped():
    assert text_to_markdown("1. first\n\n12) second") == "1\\. first\n\n12\\) second"


def test_indentation_goes():
    # four spaces would open a code block
    assert text_to_markdown("    indented line\n\t\ttabbed") == "indented line  \ntabbed"


def test_crlf_and_cr_are_read_as_line_ends():
    assert text_to_markdown("a\r\nb\r\n\r\nc\rd") == "a  \nb\n\nc  \nd"


def test_a_markdown_file_is_shown_as_text_not_as_markdown():
    # A .md source is text too: its heading and image stay as written, and its
    # link is not live in OpenCTI (ADR-0093).
    text = "# Title\n\n![x](http://e.x/a.png) [l](http://e.x)"
    shown = "\\# Title\n\n!\\[x\\](hxxp://e.x/a.png) \\[l\\](hxxp://e.x)"
    assert text_to_markdown(text) == shown
    assert report_description(text, filename="notes.md", source_hash=None, published=None,
                              counts={}, file_attached=False) == (
        "## Source document\n\n- **File:** notes.md\n\n## Document text\n\n" + shown)


def test_report_description_as_opencti_shows_it():
    description = report_description(
        "Group X targets energy firms.\nThe loader is Loader_v2.\n\n"
        "Contact: 203.0.113.7 via http://c2.example.net/run\nThe second stage is a DLL.",
        filename="apt.pdf", source_hash=HASH, published=PUBLISHED,
        counts={"malware": 2, "relationship": 5, "indicator": 0}, file_attached=True)
    assert description == (
        "## Source document\n"
        "\n"
        "- **File:** apt.pdf\n"
        f"- **SHA-256:** `{HASH}`\n"
        "- **Published:** 2023-03-15 (header)\n"
        "- **Attached:** the original file is attached to this report.\n"
        "\n"
        "## What CTIParsor extracted\n"
        "\n"
        "| Object type | Count |\n"
        "|---|---|\n"
        "| `relationship` | 5 |\n"
        "| `malware` | 2 |\n"
        "\n"
        "## Document text\n"
        "\n"
        "Group X targets energy firms.  \n"
        "The loader is Loader\\_v2.\n"
        "\n"
        "Contact: 203.0.113.7 via hxxp://c2.example.net/run  \n"
        "The second stage is a DLL."
    )


def _describe(**changes):
    options = {"filename": "apt.pdf", "source_hash": HASH, "published": PUBLISHED,
               "counts": {"malware": 2}, "file_attached": True}
    options.update(changes)
    return report_description("Text.", **options)


def test_the_file_line_needs_a_file_name():
    assert "- **File:**" in _describe()
    assert "- **File:**" not in _describe(filename="")


def test_the_hash_line_needs_a_hash():
    assert "SHA-256" in _describe()
    assert "SHA-256" not in _describe(source_hash=None)
    assert "SHA-256" not in _describe(source_hash="")


def test_the_published_line_needs_a_value():
    assert "Published" not in _describe(published=None)
    assert "Published" not in _describe(published={"source": "header"})


def test_the_source_of_the_date_is_optional():
    assert "- **Published:** 2023-03-15\n" in _describe(published={"value": "2023-03-15"})


def test_the_attached_line_needs_an_attached_file():
    assert "**Attached:**" in _describe()
    assert "**Attached:**" not in _describe(file_attached=False)


def test_the_source_section_goes_when_all_its_lines_do():
    assert _describe(filename="", source_hash=None, published=None, file_attached=False) == (
        "## What CTIParsor extracted\n"
        "\n"
        "| Object type | Count |\n"
        "|---|---|\n"
        "| `malware` | 2 |\n"
        "\n"
        "## Document text\n"
        "\n"
        "Text."
    )


def test_the_table_is_sorted_by_count_then_type_and_drops_zeros():
    description = report_description(
        "", filename="", source_hash=None, published=None,
        counts={"indicator": 0, "malware": 2, "relationship": 5, "attack-pattern": 2},
        file_attached=False)
    assert description == (
        "## What CTIParsor extracted\n"
        "\n"
        "| Object type | Count |\n"
        "|---|---|\n"
        "| `relationship` | 5 |\n"
        "| `attack-pattern` | 2 |\n"
        "| `malware` | 2 |"
    )


def test_the_table_goes_when_no_type_has_an_object():
    assert "What CTIParsor extracted" not in _describe(counts={"malware": 0, "indicator": 0})


def test_nothing_to_show_is_an_empty_description():
    assert report_description("", filename="", source_hash=None, published=None,
                              counts={}, file_attached=False) == ""
    assert report_description("  \n\n", filename="", source_hash=None, published=None,
                              counts={}, file_attached=False) == ""


def test_opencti_file_carries_the_bytes_in_base64():
    data = bytes(range(256))
    entry = opencti_file("apt.pdf", data, "application/pdf")
    assert base64.b64decode(entry["data"]) == data
    assert entry["name"] == "apt.pdf"
    assert entry["mime_type"] == "application/pdf"
    assert entry["no_trigger_import"] is True
    assert "object_marking_refs" not in entry
