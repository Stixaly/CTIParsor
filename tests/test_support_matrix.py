"""The capability table of docs/support-policy.md keeps implemented, qualified and limits apart.

Each row states what the code does (Implemented), what evidence shows it works
(Qualified), what is not covered (Limits) and the open issue.  A qualified
"yes" must cite its evidence; every link and every repository path in the
section must resolve.
"""
from __future__ import annotations

import re
from pathlib import Path

from scripts.check_doc_links import check_text, tracked_files

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "docs" / "support-policy.md"
SECTION = "## Capabilities: implemented, qualified, limits"
STATUS = re.compile(r"^\*\*(yes|partly|no)\*\*")
PATH_TOKEN = re.compile(r"^[\w./-]+$")
PATH_SUFFIXES = (".py", ".sh", ".yaml", ".yml", ".json", ".md", ".example", ".tsx")

#: Capabilities the README, the support policy and the ADRs announce. Each must
#: have a row (matched in the first cell).
REQUIRED_ROWS = [
    "Local accounts", "OIDC", "Audit trail", "TLP egress", "Metrics", "Scheduled backups",
    "Bounds", "Response models", "Figure reading", "Vision providers", "Default LLM provider",
    "vLLM", "Other LLM providers", "Named entities", "ATT&CK techniques", "IoC extraction",
    "Relationships", "Import of PDF", "Capture of a URL", "OCR", "languages", "Review and finalize",
    "Command line", "Enrichment", "STIX 2.1 export", "Import into OpenCTI", "Import into MISP",
    "Install with Docker Compose", "Upgrade from", "Backup and restore", "Air-gapped",
    "Queue, worker status", "Detection rules", "Detection coverage", "GPU",
]


def _section_rows() -> list[list[str]]:
    lines = POLICY.read_text(encoding="utf-8").splitlines()
    start = lines.index(SECTION)
    table = []
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        if line.startswith("|"):
            table.append(line)
    assert len(table) > 2, "the capability table is missing"
    rows = []
    for line in table[2:]:  # header and separator
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        rows.append(cells)
    return rows


def test_header_has_the_five_columns():
    lines = POLICY.read_text(encoding="utf-8").splitlines()
    start = lines.index(SECTION)
    header = next(line for line in lines[start:] if line.startswith("| Capability"))
    assert [c.strip() for c in header.strip("|").split("|")] == [
        "Capability", "Implemented", "Qualified", "Limits", "Open issue"]


def test_every_row_has_five_filled_cells():
    for cells in _section_rows():
        assert len(cells) == 5, f"row does not have five cells: {cells[:1]}"
        assert all(cells), f"empty cell in row {cells[0]!r}"


def test_implemented_and_qualified_start_with_a_status():
    for cells in _section_rows():
        assert STATUS.match(cells[1]), f"Implemented of {cells[0]!r} must start with yes, partly or no"
        assert STATUS.match(cells[2]), f"Qualified of {cells[0]!r} must start with yes, partly or no"


def test_implemented_yes_names_its_module():
    for cells in _section_rows():
        if cells[1].startswith("**yes"):
            assert "`" in cells[1], f"Implemented 'yes' of {cells[0]!r} names no module or file"


def test_qualified_yes_cites_evidence_and_a_date_or_ci():
    for cells in _section_rows():
        if cells[2].startswith("**yes"):
            assert "](" in cells[2], f"qualified 'yes' of {cells[0]!r} cites no link"
            assert re.search(r"\d{4}-\d{2}-\d{2}", cells[2]) or "CI" in cells[2], (
                f"qualified 'yes' of {cells[0]!r} cites neither a dated run nor a CI job")


def test_required_capabilities_have_a_row():
    first_cells = [cells[0] for cells in _section_rows()]
    missing = [name for name in REQUIRED_ROWS if not any(name in cell for cell in first_cells)]
    assert not missing, f"capabilities announced but without a row: {missing}"


def test_every_link_of_the_policy_resolves():
    tracked = tracked_files(ROOT)
    _, problems = check_text("docs/support-policy.md", POLICY.read_text(encoding="utf-8"), tracked, ROOT)
    assert not problems, f"broken links in docs/support-policy.md: {problems}"


def test_every_repository_path_in_the_table_exists():
    missing = []
    for cells in _section_rows():
        for cell in cells:
            for token in re.findall(r"`([^`]+)`", cell):
                if " " in token or "=" in token or token.startswith("-"):
                    continue
                if not PATH_TOKEN.match(token):
                    continue
                top = token.split("/")[0]
                is_repo_path = "/" in token and (ROOT / top).exists()
                is_root_file = "/" not in token and token.endswith(PATH_SUFFIXES)
                if not (is_repo_path or is_root_file):
                    continue  # a model name, a setting or a command, not a path
                if not (ROOT / token).exists():
                    missing.append(token)
    assert not missing, f"path named in the table does not exist: {sorted(set(missing))}"
