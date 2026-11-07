from __future__ import annotations

import pytest
from psycopg._queries import _split_query

from api.db_backend import translate_placeholders


def _placeholder_count(sql: str) -> int:
    """Number of parameters psycopg sees in a translated query (see issue #440)."""
    return len(_split_query(translate_placeholders(sql).encode())) - 1


# Issue #524: a named placeholder `%(name)s` is psycopg's own syntax for a dict
# of parameters. translate_placeholders doubled its '%', so psycopg read it as a
# literal '%' and failed with "1 parameters given but 0 used in the query".
@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        (
            "SELECT * FROM jobs WHERE status = %(status)s",
            "SELECT * FROM jobs WHERE status = %(status)s",
        ),
        (
            "SELECT * FROM jobs WHERE status = %(status)s AND id = %(job_id)s",
            "SELECT * FROM jobs WHERE status = %(status)s AND id = %(job_id)s",
        ),
        ("SELECT %(a_1)b, %(B)t", "SELECT %(a_1)b, %(B)t"),
    ],
)
def test_a_named_placeholder_is_left_intact_issue_524(sql, expected):
    assert translate_placeholders(sql) == expected
    assert _placeholder_count(sql) == len(expected.split("%(")) - 1


def test_a_named_placeholder_next_to_a_qmark_placeholder_issue_524():
    # Only the '?' is a positional placeholder here; mixing styles is the caller's
    # business, but the translation must not corrupt either one.
    assert translate_placeholders("SELECT 1 WHERE a = ? AND b = %(b)s") == \
        "SELECT 1 WHERE a = %s AND b = %(b)s"


def test_a_named_looking_text_inside_a_string_literal_is_still_escaped_issue_524():
    # Inside a string the whole literal is escaped, as before (#440): psycopg
    # turns '%%' back into '%', so the literal text reaches the database unchanged.
    assert translate_placeholders("SELECT '%(x)s' FROM t") == "SELECT '%%(x)s' FROM t"


def test_a_bare_percent_is_still_doubled_issue_524():
    assert translate_placeholders("SELECT 100 % 7 WHERE id = ?") == "SELECT 100 %% 7 WHERE id = %s"
