"""rule_atoms values must honour their documented normalisation contract."""
from __future__ import annotations

from pipeline.detection.atoms import _normalize, extract_atoms


def test_basename_is_stripped():
    """The basename segment must be stripped of leading/trailing whitespace."""
    # The full path keeps its internal space; only the basename is re-stripped.
    assert _normalize("image", "c:\\tmp\\ rev_shell.py") == [
        "c:/tmp/ rev_shell.py",
        "rev_shell.py",
    ]


def test_file_class_strips_the_basename_too():
    """The file class must also strip the basename segment."""
    result = _normalize("file", "/opt/app/ payload.sh")
    assert "payload.sh" in result
    assert " payload.sh" not in result


def test_every_emitted_atom_is_stripped():
    """Every value returned by _normalize must equal its own .strip()."""
    table = [
        ("image", "c:\\tmp\\ rev_shell.py"),
        ("file", "/opt/app/ payload.sh"),
        ("image", "c:\\windows\\system32\\cmd.exe"),
        ("file", "notepad.exe"),
        ("registry", "HKLM\\Software\\ Microsoft"),
        ("domain", "  Evil.COM  "),
        ("url", "  HTTP://evil.com/a  "),
        ("cmdline", "  whoami /all  "),
    ]
    for cls, raw in table:
        for v in _normalize(cls, raw):
            assert v == v.strip(), f"unstripped value {v!r} from {cls}/{raw!r}"


def test_every_emitted_atom_is_lowercase():
    """Every value returned by _normalize must be lowercase."""
    table = [
        ("image", "c:\\tmp\\ rev_shell.py"),
        ("file", "/opt/app/ payload.sh"),
        ("image", "c:\\windows\\system32\\cmd.exe"),
        ("file", "notepad.exe"),
        ("registry", "HKLM\\Software\\ Microsoft"),
        ("domain", "  Evil.COM  "),
        ("url", "  HTTP://evil.com/a  "),
        ("cmdline", "  whoami /all  "),
    ]
    for cls, raw in table:
        for v in _normalize(cls, raw):
            assert v == v.lower(), f"non-lowercase value {v!r} from {cls}/{raw!r}"


def test_basename_shorter_than_four_chars_is_dropped():
    """A basename shorter than 4 chars after stripping must be dropped."""
    result = _normalize("image", "c:\\tmp\\ ab")
    assert "ab" not in result
    # The full path exceeds 4 chars and must still be present.
    assert any(len(v) >= 4 for v in result)


def test_extract_atoms_never_emits_an_untrimmed_value():
    """extract_atoms must only yield stripped, lowercase values."""
    rule = {
        "detection": {
            "selection": {"Image": "c:\\tmp\\ rev_shell.py"},
            "condition": "selection",
        }
    }
    for cls, value in extract_atoms(rule):
        assert value == value.strip(), f"unstripped {value!r}"
        assert value == value.lower(), f"non-lowercase {value!r}"
