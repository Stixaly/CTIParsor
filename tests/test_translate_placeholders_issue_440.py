from __future__ import annotations

import pytest
from psycopg._queries import _split_query

from api.db_backend import translate_placeholders


def _placeholder_count(sql: str) -> int:
    """Number of parameters psycopg sees in a translated query.

    `_split_query` returns one part per placeholder plus a trailing part, so
    the count is `len - 1`. A `%s` left inside a comment or a dollar-quoted
    body shows up here, which is how the bug surfaces at execution time.
    """
    return len(_split_query(translate_placeholders(sql).encode())) - 1


# Issue #440: the scanner only tracked single and double quotes, so a '?' in a
# `--` or `/* */` comment became a parameter, an apostrophe in a comment flipped
# the quote state for the rest of the query, and a '?' in a $$ body was
# translated even though it is PL/pgSQL text.
@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        (
            "SELECT id FROM jobs -- filter by id?\nWHERE id=?",
            "SELECT id FROM jobs -- filter by id?\nWHERE id=%s",
        ),
        (
            "SELECT id FROM jobs -- it's the job\nWHERE id=? AND status=?",
            "SELECT id FROM jobs -- it's the job\nWHERE id=%s AND status=%s",
        ),
        ("SELECT 1 /* is it ? */ WHERE id=?", "SELECT 1 /* is it ? */ WHERE id=%s"),
        ("SELECT ? /* it's */ , ? -- '\nFROM t", "SELECT %s /* it's */ , %s -- '\nFROM t"),
        (
            "CREATE FUNCTION f() RETURNS int AS $$ SELECT ? $$ LANGUAGE sql",
            "CREATE FUNCTION f() RETURNS int AS $$ SELECT ? $$ LANGUAGE sql",
        ),
        (
            "DO $body$ BEGIN PERFORM ?; END $body$; SELECT ?",
            "DO $body$ BEGIN PERFORM ?; END $body$; SELECT %s",
        ),
        # A '$$' inside a tagged body does not close it.
        (
            "DO $f$ SELECT '$$ ?' $f$ WHERE id=?",
            "DO $f$ SELECT '$$ ?' $f$ WHERE id=%s",
        ),
        # A '--' inside a string or a quoted identifier is not a comment.
        ("SELECT '--', ? FROM t", "SELECT '--', %s FROM t"),
        ('SELECT "a--b" FROM t WHERE x=?', 'SELECT "a--b" FROM t WHERE x=%s'),
        # A '--' inside a block comment does not start a line comment.
        ("SELECT /* -- */ ? FROM t", "SELECT /* -- */ %s FROM t"),
        # '%' is still doubled everywhere, comments and dollar bodies included,
        # because psycopg's scanner ignores SQL structure.
        ("SELECT 1 -- 100% ?\n, '%' , ?", "SELECT 1 -- 100%% ?\n, '%%' , %s"),
        ("SELECT ? /* 50% */ FROM t", "SELECT %s /* 50%% */ FROM t"),
        ("DO $$ SELECT '%' $$; SELECT ?", "DO $$ SELECT '%%' $$; SELECT %s"),
        # Control: the '' escape inside a string is still honoured.
        ("a='it''s ?' AND b=? -- x", "a='it''s ?' AND b=%s -- x"),
        ("SELECT 1", "SELECT 1"),
    ],
)
def test_translate_placeholders_skips_comments_and_dollar_bodies_issue_440(sql, expected):
    assert translate_placeholders(sql) == expected


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        ("SELECT id FROM jobs -- filter by id?\nWHERE id=?", 1),
        ("SELECT id FROM jobs -- it's the job\nWHERE id=? AND status=?", 2),
        ("SELECT 1 /* is it ? */ WHERE id=?", 1),
        ("CREATE FUNCTION f() RETURNS int AS $$ SELECT ? $$ LANGUAGE sql", 0),
        ("SELECT * FROM t WHERE name LIKE '%foo%' -- ?\n AND id = ?", 1),
    ],
)
def test_translated_query_has_one_psycopg_parameter_per_real_placeholder_issue_440(sql, params):
    assert _placeholder_count(sql) == params
