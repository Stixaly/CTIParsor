# OpenCTI's Snort parser (vendored copy)

This folder holds a copy of two files from OpenCTI's Snort runtime, with a few
local patches. The package is not on PyPI, so it is copied here. Stage 4 runs the
same parser that OpenCTI runs on a Snort Indicator, so a rule that OpenCTI refuses
is not shipped. The decision is recorded in ADR-0070.

## Source

- Project: OpenCTI, `opencti-platform/opencti-graphql/src/python/runtime/snort/`
- Files: `snort_parser.py` and `snort_dicts.py`
- Version copied: OpenCTI master of 2026-10-01 (the date is in `__init__.py`)
- Copyright: 2021-2026 Filigran SAS

## Licence

Apache License 2.0. The licence text is `LICENSES/Apache-2.0.txt` at the root of
the repository. Filigran's copyright notice is in the docstring of `__init__.py`.

## Local changes

The copy is not byte-identical to OpenCTI's files. The changes below are in git
history; `git log --follow` on each file shows them.

| Commit | Issue | Change |
|---|---|---|
| 8fd44ba | ADR-0070 | The copy itself, added with the Snort gate. |
| 9401ba9 | #422 | `Parser.validate_options` resets the `opt` flag for every option. Before, a bare option kept the flag of the option before it, or raised `UnboundLocalError` when it came first. |
| 3e2b444 | #519 | `Parser.ip` sends a single bracketed address or variable (such as `[$HOME_NET]`) through the list path. |
| 3e2b444 | #520 | `Parser.port` range checks run. The old truthiness tests (`if item.lower()`, `if port or`) were always true, so no listed or single port was range-checked. A negative port is refused. |
| 3e2b444 | #521 | `Sanitizer.sanitize` matches options by name and keeps the `(name, values)` shape. `Sanitizer.depth` reads the values from that shape, and does not strip an operator from a plain number. |
| 393f58e | #624 | `Sanitizer.pcre` keeps a list's shape, adds the quotes and the slashes only when missing, and keeps the flags. `SerializeRule.serialize_options` writes a pcre string without commas between its characters. |

## Known limitations

The parser checks option names against the keyword tables in `snort_dicts.py`,
and it checks addresses and ports. It does not check the arguments or the syntax
of most keywords. The TODO comments in the two files mark the keywords and
behaviours that are not checked. They are listed here by topic.

Keyword arguments and syntax not checked (names only):

- `http_encode`: its options.
- `fast_pattern`: its options. The fast pattern matcher is always case-insensitive.
- `pcre`: Perl-compatible modifiers.
- `base64_decode`: its options and format.
- `byte_test`, `byte_jump`, `byte_extract`: their options.
- `byte_math`: its syntax and options.
- `ftpbounce`: its options and syntax.
- `cvs`: whether the rule uses encrypted sessions is not checked.
- `gtp_type`: the GTP message types are not checked, only the keyword.
- `gtp_info`: the table of GTP info values is not checked.
- `flow`, `flowbits`: their options and syntax.

Tables that are incomplete:

- The Snort default classifications are not in the general keyword table
  (`Dicts.general_options` and `Dicts.options`).
- The threshold types (`threshold: type limit`, and the others) are not listed. Only
  the keyword `threshold` is known. `Dicts.rule_thresholds` lists the same keyword,
  but `Dicts.options` does not call it.

Behaviour marked for a decision:

- `Parser.port`: a `return None` after the single-port range check is marked
  "verify this is intended behavior". As written it is not reached: an in-range port
  returns before it, and an out-of-range one raises.
- `Parser.validate_options`: a single-value content modifier is accepted without
  further checks. The code marks this as a feature still to implement.
- `SerializeRule.serialize_header_item`: returns None for a value that is neither a
  string nor a tuple. The code marks this as a decision to verify.

## Updating the copy

1. Copy `snort_parser.py` and `snort_dicts.py` again from the OpenCTI source above.
2. Re-apply the local changes in the table, one commit at a time, or compare the
   new files with the ones in git history.
3. Run `tests/test_snort_parser_*.py` and `tests/test_opencti_snort_docs.py`.
4. Update the date and the version copied in this file and in `__init__.py`.
