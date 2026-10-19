# ADR-0049 — The ReDoS guard becomes real: `google-re2`, and actually called

**Status:** Accepted (implemented 2026-09-16)
**Date:** 2026-09-16
**Relates to:** [0044](0044-container-images.md) (found the build failure),
SECURITY.md (gains a threat-surface entry for Stage 2 regex extraction —
it had none before this ADR)

## Context

Building the container image surfaced a build-time failure: the pinned
`re2>=0.2.20` package fails to compile on Python 3.12 — its Cython-generated
C++ source calls CPython internals removed in 3.12 (`PyUnicode_AS_UNICODE`,
`tstate->curexc_type`, the old five-argument-shorter `PyCode_New`). The
Dockerfile already treats this as non-fatal (`|| echo "WARNING: ..."`), so
the build was never broken — but nobody has had the guarantee since Python
3.12 became current, host installs included.

Checking why, before writing a spec, per this project's own review
discipline: **`pipeline/stage2_extraction.py::_compile_pattern` — the
function `SECURITY.md` and `setup.sh` describe as giving Stage 2 "guaranteed
linear time" — is never called.** All 19 module-level compiled patterns
(CVE, hash block, IPv4, domain, URL, email, MAC ×2, ASN, Windows/Unix path,
bare filename, registry key, defang, MITRE TTP, version, the 3-entry
`_HASH_LABEL_PATTERNS` tuple) call `re.compile()` directly. A working `re2`
install would have protected nothing; the gap was two bugs, not one.

## Decision

**Replace the dead package with `google-re2` (wheels for cp312+), and wire
`_compile_pattern` into every pattern it was meant to guard.**

`google-re2`'s `compile(pattern, options=None)` does not accept `re`'s
integer flags (`re.compile(p, re.IGNORECASE)` fails on it —
`AttributeError: 'RegexFlag' object has no attribute 'max_mem'`, verified).
RE2 syntax supports inline flags instead (`(?i)`, `(?m)`, `(?s)`,
combinable as `(?im)`), so `_compile_pattern` maps the three `re` flags this
codebase actually uses onto a prefix and compiles that:

```python
_RE2_INLINE_FLAGS = {re.IGNORECASE: "i", re.MULTILINE: "m", re.DOTALL: "s"}

def _compile_pattern(pattern, flags=0):
    if _RE2_AVAILABLE:
        unmapped = flags & ~sum(_RE2_INLINE_FLAGS)
        if not unmapped:
            letters = "".join(l for f, l in _RE2_INLINE_FLAGS.items() if flags & f)
            try:
                return _re2_module.compile(f"(?{letters})" + pattern if letters else pattern)
            except Exception:
                pass
    return re.compile(pattern, flags)
```

A flag this codebase never passes (`VERBOSE`, `ASCII`, …) falls back to
stdlib rather than being silently dropped; so does any pattern RE2 cannot
parse at all (backreferences, lookaround). The latter is not hypothetical:
7 of the 19 sub-patterns already use negative lookaround and hit this
fallback today — see Options considered and the validation record below.

**Verified empirically against every method and every real pattern this
codebase actually calls**, not assumed from the flag mapping alone: `.sub()`
with a callable replacement (`_defang_repl`, called on every ingested
document via `refang()`) returns the identical result under RE2; named
groups, `m.group(name)` and `m[0]` indexing work the same; the CVE pattern's
literal zero-width/dash Unicode character classes (embedded as real glyphs
in the source, not `\u` escapes — RE2 doesn't parse those) compile and
match correctly combined with an inline `(?i)`; the full defang alternation,
brackets and all, compiles and its callable substitution produces the exact
refanged output a live report's `hxxps://evil[.]com` / `foo[at]bar(dot)com`
should refang to.

## Options considered

- **`re2.Options()` with `case_sensitive = False` for every flag** —
  rejected in favour of inline prefixes: `Options` has no multi-line or
  dot-all equivalent as clean as RE2's own inline syntax, so two mechanisms
  would be needed instead of one. Verified both work; picked the simpler.
- **Rewrite the 7 lookaround sub-patterns to be RE2-parseable** — considered
  after discovering, empirically, that `_HASH_BLOCK_PATTERN`, `_IPV4_PATTERN`,
  `_DOMAIN_PATTERN`, `_BARE_FILENAME_PATTERN`, `_UNIX_PATH_PATTERN`, and 2 of
  the 3 `_HASH_LABEL_PATTERNS` entries (`sha1`, `md5`) use `(?<!...)`/`(?!...)`
  negative lookaround, which RE2's engine cannot parse under any flag
  combination — **this contradicts what an earlier draft of this ADR claimed
  ("none exist in this file today")**; that claim was wrong, caught only by
  printing `type()` on every compiled pattern inside the real container.
  Rejected rewriting them: RE2 has no lookaround equivalent at all (it's
  structurally incompatible with a non-backtracking engine), so the only way
  to make these RE2-parseable is a different pattern shape plus a
  post-match boundary check in Python — real work, for patterns just proven
  (see Validation record) to have no nested unbounded quantifier, i.e. no
  backtracking blowup to guard against in the first place. Revisit only if a
  future edit gives one of these 7 an unbounded nested quantifier.
- **Leave `_compile_pattern` unused and just fix the package** — rejected:
  it would have made the build warning disappear without the guarantee it
  implies becoming true. The dead-code finding is the more important half of
  this fix.
- **Drop the ReDoS guard entirely, document it as unsupported** — rejected:
  Stage 2 runs regex against attacker-influenced report text by design (now
  SECURITY.md §4, added by this ADR — it had no entry before); the ~20-line
  adapter is cheap against that.

## Consequences

- Every host install and the container image now get real linear-time
  matching on **12 of Stage 2's 19 top-level patterns** (plus 1 of 3
  `_HASH_LABEL_PATTERNS` entries) once `pip install google-re2` succeeds
  (wheels exist for the platforms this project targets; no C++ toolchain
  required, unlike the old package). The other 7 use negative
  lookahead/lookbehind — syntax no non-backtracking engine can support, RE2
  included — and stay on stdlib `re` regardless of whether re2 is installed;
  verified (see Validation record) that none of the 7 has the nested
  unbounded quantifier shape that makes backtracking actually explosive, so
  this is a real, checked gap in coverage, not an unverified one.
- What becomes harder: three RE2 syntax gaps to remember if a new pattern is
  added — no backreferences, no `\uXXXX` escapes (use the literal
  character), no lookaround. `_compile_pattern`'s fallback makes a pattern
  that hits any of them silently correct (stdlib `re`, unguarded) rather
  than a build failure, so a new unguarded pattern won't announce itself;
  worth an occasional check of `type(_SOME_PATTERN)` in review — this ADR's
  own first draft claimed no such pattern existed yet, and was wrong.
- Not done here: RE2 was not made a hard dependency — it stays optional,
  falling back to stdlib `re` exactly as before, so a host that can't
  install it (no wheel for its platform) keeps working, just without the
  guarantee.

## Validation record (2026-09-16)

| Check | Result |
|---|---|
| RE2 inline flags, real patterns, live in the container | `.sub()` with callable, named groups, `m[0]`, the literal-Unicode CVE class + `(?i)`, and the full defang alternation all verified against `google-re2` inside `ctiparsor:local`, not assumed |
| `_compile_pattern` unit tests | proves the returned object is `re2._Regexp`, not `re.Pattern`, when re2 is installed; a catastrophic-backtracking pattern finishes in guaranteed linear time |
| `extract_entities()` / `refang()` output, re2 vs stdlib fallback | identical on the same input — the guard changes *how* matching runs, never *what* it returns |
| Full suite, ruff, mypy | ruff: clean (`All checks passed!`). mypy: clean on `pipeline/stage2_extraction.py`, no output. Full suite: 1208 passed / 14 skipped (SQLite, 107.96s), 1216 passed / 6 skipped (PostgreSQL, 111.48s) — 0 failures on either engine |
| Real corpus (`cti_stix.db`) before/after | 9 real ingested jobs, 228,651 chars of `report_text`. `extract_entities()` returned 501 entities on both the re2 path and the stdlib-fallback path, 0 mismatches by `(value.lower(), entity_type)`; `refang()` output identical on all 9. Wall time: 0.344s (re2) vs. 0.325s (stdlib) for all 9 combined — re2 is not faster on this corpus size, its guarantee is the *worst case*, not the common case |
| Container rebuild, verify re2 is real | Rebuilt `ctiparsor:local` with the updated `Dockerfile` (no `libre2-dev`/`libre2-9`) and `requirements-optional.txt` (`google-re2>=1.1`). Inside it: `import re2` succeeds; `type(_compile_pattern("CVE-[0-9]{4}-[0-9]{4,}"))` is `re2._Regexp`, not `re.Pattern`; it matches and respects `re.IGNORECASE` via the `(?i)` prefix |
| Which patterns actually got RE2 | Checked `type()` on all 19 top-level patterns plus the 3 `_HASH_LABEL_PATTERNS` entries inside the container: 12 top-level + 1 hash-label are `re2._Regexp`. 7 fell back to `re.Pattern` — `_HASH_BLOCK_PATTERN`, `_IPV4_PATTERN`, `_DOMAIN_PATTERN`, `_BARE_FILENAME_PATTERN`, `_UNIX_PATH_PATTERN`, and the `sha1`/`md5` entries of `_HASH_LABEL_PATTERNS` — all because they use `(?<!...)`/`(?!...)` lookaround, which RE2 cannot parse under any flag. This ADR's own first draft claimed no such pattern existed; it was wrong, and only checking every pattern's actual compiled type caught it |
| Are the 7 fallback patterns exploitable anyway | Stress-tested each against adversarial input (5,000–8,000 repeated ambiguous units, e.g. `"/usr" + "/a"*8000`, `"a."*8000`) under plain stdlib `re`, timed: all 5 top-level patterns and both hash-label patterns completed in under 11 ms. None has a nested unbounded quantifier (`_UNIX_PATH_PATTERN`'s `(?:/[^...]+)+` looked structurally suspicious — inner class allows `/`, so segment boundaries are ambiguous — but the pattern has no end anchor, so `re.search` accepts the first greedy match and never explores the ambiguity exhaustively); none is exploitable today. Documented as a checked, not assumed, residual gap |
| `docker_smoke.sh` re2 check | Ran against the rebuilt image: step 11 now reports PASS (`re2 available — most Stage 2 regexes run in guaranteed linear time`) instead of the historical WARN. Also caught and fixed a pre-existing wording bug in the WARN branch (`scripts/docker_smoke.sh`): it said "re2 available" in the branch that runs when re2 is *not* available |

## Amendment (2026-10-11): five of Stage 2's fallbacks run on RE2, the rest are pinned

The October 2026 audit (B 8.2.5) asked for Stage 2 at 100 % RE2. By then
RE2 refused 11 patterns across the code: Stage 2's 7 above, the half-bracket
defang added in October (`_HALF_BRACKET_DOT`), and three sentence splitters
(Stage 2c, Stage 4, the retrieval passages), all for their lookaround.

**Rewritten for RE2, guards in code** (`pipeline/stage2_extraction.py`):
`_IPV4_PATTERN` (the octets; the guards filter one `finditer` pass),
`_HASH_BLOCK_PATTERN` (now `_hash_blocks`: ASCII alphanumeric runs from RE2,
grouped when all hex and separated by whitespace alone), `_HALF_BRACKET_DOT`
(the neighbours checked by the `sub` callable), and the SHA-1 and MD5 labels.
Each rewrite is exact, not approximate: a match the old guards refused hides
no valid one, and the comment beside each pattern says why. Measured: the
same entities, file paths, hashes and refanged text on AnnoCTR's 400 texts,
with google-re2 and without it. The only differences are three synthetic
cases with Arabic-Indic digits, where `re`'s Unicode `\d` used to extract
`1.2.3.4١`; RE2's octets are ASCII.

Two RE2 differences the rewrites had to respect:

- RE2's `\s` is ASCII. A rewritten class that needs Python's `\s` (the
  hash labels) uses `regex_safety.PY_WHITESPACE`, its 29 characters, checked
  by a test against `str.isspace()` under both engines.
- google-re2 encodes the whole text at every call. The first IPv4 rewrite
  restarted `search(text, pos)` after each refused match, as the backtracking
  engine does; on `test_stage2_performance`'s 5,000-IP appendix that took
  2.7 s instead of 0.5 s. Every rewrite is one `finditer` pass.

**Still on `re`, pinned and measured**: `_DOMAIN_PATTERN` and
`_BARE_FILENAME_PATTERN` (a lookahead the engine backtracks over, so a
filter after one pass would miss the shorter match), `_UNIX_PATH_PATTERN` (a
path refused for the word character before it can contain a valid one, as
in `x/tmp/a./usr/bin`), and the three splitters. `compile_pattern` records
every refusal in `regex_safety.FALLBACKS`; `tests/test_re2_fallbacks.py`
fails on a refused pattern it does not list, and runs each listed one under
`re` on 50,000 characters of 14 adversarial inputs within 1 s. The domain
pattern, the slowest, scales linearly: 42, 83, 168 and 337 ms on 25, 50,
100 and 200 thousand `a.` pairs.

## Amendment (2026-10-18): `\s` means Python's whitespace under both engines

The rewrites above respected RE2's ASCII `\s`; the patterns RE2 accepted as
written did not. The review of the NER precision filters (ADR-0088, on its own
branch) found the gap: their `[\s\-]+` tokeniser dropped "Chinese\xa0threat
actors" in a local run (no re2, `re`'s Unicode `\s`) and kept it in production
(RE2). PDF extraction and HTML pages put no-break, thin and narrow no-break
spaces between words, and nothing before Stage 2 normalises them.

Audit of every `compile_pattern` call in `pipeline/` and `api/`: 72
module-level patterns used `\s` or `\S`.

- **21 rewritten**: the class says `PY_WHITESPACE`, or the code splits with
  `str.split()` where the pattern only collapsed blanks. Stage 2's ASN, Windows
  path and spaced-defang patterns; Stage 2g's alias markers; Stage 2c's
  list-item and table-caption tests and the retrieval passages' list-item test
  and blank collapse; Stage 3f's quote check; ADR-0050's generic-vocabulary
  tokeniser, which ADR-0052's promote gate also uses; the six patterns of
  `detection/yara_atoms.py`, whose `split_rules` reads the report itself in
  Stage 4 (an `import\xa0"pe"` outside the rule was not added to it, and the
  rule failed to compile); Stage 4's Sigma title scan (a next rule opening
  with `title\xa0:` did not end the one before, and both shipped as one
  pattern); the network-traffic port; the observables' `[dot]`. Under `re`
  each rewrite matches what it matched before.
- **51 left on `\s`**, each for a reason `tests/test_unicode_whitespace.py`
  lists: the 24 date patterns read `fold()`ed text, where any
  `str.isspace()` is already a space; four lookbehind patterns always run on
  `re`; the 17 upload sniffing patterns follow HTML and CommonMark, whose
  blanks are ASCII; Stage 1's IoC-shaped cell test runs only on text without
  blanks; CyNER's three span checks read spans an NFKC tokenizer decoded, and
  a non-ASCII span is dropped anyway; Stage 4 reads a number in the STIX
  patterns it wrote; the ATT&CK link cleaner runs on ATT&CK's text at corpus
  build.

Matching more blanks exposed one Python-side gap: Stage 2g's `_clean_alias`
stripped ASCII blanks only, so `Berserk Bear\xa0and\xa0Dragonfly` gave
`Berserk Bear\xa0` and lost `Dragonfly`, under both engines. It strips every
`str.isspace()` character now.

The test runs 42 cases with three blanks; they pass with re2 and without it,
and under RE2 every one failed before the rewrites. It also imports each
module that calls `compile_pattern` and fails on a module-level pattern that
uses `\s` without being listed, and on a listed one that no longer does. A
pattern compiled inside a function is not seen by the test; the audit found
none that uses `\s`. `PY_WHITESPACE` is a class body, not a set of
characters: it writes the run U+2000 to U+200A as a range, so
`str.strip(PY_WHITESPACE)` would strip `-`.

`\w`, `\d` and `\b` are ASCII under RE2 too, and Unicode under `re`; they were
not audited here.

## Amendment (2026-10-18): `\d`, `\w` and `\b` read one way under both engines

The amendment above left these three. google-re2 reads `\d` as `[0-9]`, `\w`
as `[0-9A-Za-z_]` and `\b` against that `\w`; `re` reads them as
`str.isdecimal()`, `str.isalnum()` or `_`, and the boundary between the two.

Audit: every `compile_pattern` call made at import was recorded under RE2 (137
calls) and its pattern walked with the parser: 76 use `\w`, `\W`, `\d`, `\D`,
`\b` or `\B`. Three are lookaround fallbacks (the domain, bare-filename and
Unix-path patterns), on `re` under both engines, so Unicode under both; they
are unchanged. The two calls made inside functions compile `re.escape`d
literals. That leaves 73 patterns that RE2 compiles and that read text two
ways. Probed with real inputs, production had cut `o@evil.com` out of
`joão@evil.com`, read `ÚLTIMOS DÍAS 2024` as `AS2024`, and given Stage 2g the
anchor `Group` for `Müller Group (aka Berserk Bear)`; a dev run shipped `T١٠٥٩`,
`CVE-٢٠٢١-٤٤٢٢٨` and `８.８.８.８`, and missed `T1059` in `使用T1059技术`.

**The rule.** An IoC, an identifier and a grammar are ASCII: ATT&CK and CVE
ids, addresses, ports, ASNs, hashes, PDF dates, Sigma, YARA and Suricata
syntax, git's transport-helper names. A date is too: the words around it are
English or French, and `fold()` keeps digits as they are. Such a pattern
writes the class it means, `[0-9]` or `[A-Za-z0-9_]`. A `\b` has no class
spelling, so `compile_pattern` now maps `re.ASCII`: it needs no inline flag,
since RE2's `\w`, `\d`, `\s` and `\b` are ASCII whatever the flags, and `re`
gets the flag. Beside an identifier the ASCII `\b` is the right one, because
Chinese text glues words to it. Where the edge of a match is a run of letters
that a glued letter continues (the start of an address, its top-level domain,
the `AS` of an ASN, a path's extension, the word `port`), the caller also drops
a match glued to a letter of a script with case (Latin, Greek, Cyrillic...),
which writes spaces between its words, or to a digit
(`regex_safety.glued_to_a_word`). Chinese, Japanese, Korean and Thai write no
spaces, so an IoC glued to them stays one: `该IP属于AS4134网络` gives `AS4134`,
as RE2 gave it. An address is judged before the run of `.`, `%`, `+`, `-` or
`_` that ends where it starts, so `josé.perez@evil.com` is no `perez@evil.com`.
Names, and numbers that must not pass for names, read every script, without
`\w` or `\d`.

| Verdict | Patterns |
|---|---|
| ASCII, written `[0-9]` or `[A-Za-z0-9_]` (56) | the 30 date patterns of `temporal.py`; Stage 2's CVE and IPv4 octets (the IPv4 guards still read `str.isdecimal()`, so `8.8.8.8١` is no address); the list-item tests of Stage 2c and of the retrieval passages; Stage 2f's, 3c's and 3f's id checks; Stage 4's STIX pattern number; the network-traffic `host:port`; Stage 1's PDF date and IoC-shaped cell; Sigma's three tag patterns and condition tokens (pySigma's grammar is ASCII); the Suricata, YARA and synthetic-Sigma IPv4 checks, Suricata's ATT&CK id and the observables' CVE; YARA's meta keys, string names and imports; the upload sniffer's ordered list item; the corpus remote check, which now refuses every helper name git reads (`transport.c`: letters, digits, `+`, `-`, `.`), and `_` as RE2's `\w+` did |
| `\b` with `re.ASCII` (7) | Stage 2's ATT&CK ids, both MAC forms and registry keys; Stage 2c's table caption; Stage 4b's IoC guard; the YARA technique tag |
| `\b` with `re.ASCII`, and dropped when glued to a word (4) | Stage 2's email address, ASN and Windows path (its extension's end), the network-traffic port |
| Every script's digits, `regex_safety.PY_DIGIT` (2) | the two version filters (spaCy's spans, CyNER's); `value.isdigit()` beside the first reads them all too |
| Python's `\w`, `[A-Za-z0-9_` + `PY_NON_ASCII_WORD` + `]` (1) | a YARA rule's name: YARA refuses `rule café`, and a rule that is found is left out with `rule_does_not_compile` in the ledger (ADR-0067), where one that is not found is silently gone |
| Masked text (3) | Stage 2g's two alias patterns and its splitter |

**Generated classes.** `PY_DIGIT` and `PY_NON_ASCII_WORD` are class bodies of
literal ranges, as `PY_WHITESPACE` is, read at import from the running
Python's tables, because a list written out would lag one Python or the other:
`\w` past ASCII is 744 ranges in 3.12 and 767 in 3.14, `\d` 64 and 71. It
takes about 20 ms. A test compares both with `re`'s `\d` and `\w` on every
code point, through RE2 when it is installed, and checks that nothing past
U+3FFFF, where the reading stops, is a letter or a digit.

**Stage 2g masks.** Python's `\w` written out does not fit Stage 2g's inline
pattern, which repeats a word 40 times (`_ANCHOR` four times over, ten
anchors): its RE2 program grew from 971 instructions to 54,451, and RE2 logged
"DFA out of memory" on test sentences. The stage instead replaces every
non-ASCII word character with `z`, runs the patterns unchanged on that text,
and cuts the names from the original at the same offsets: one code point
stands for one, astral ones included. `z` is a word character to both engines,
never the capital that starts a Title-Case word, and in none of the patterns'
words: a first draft masked to `a`, and read `áka` as the marker `aka` and
`Ánd Ghost Blizzard` as a split at `and`. The mask replaces runs, not
characters: on 1.9 million characters of Chinese and English, Stage 2g took
0.38 s before the change, 2.19 s masking one character at a time and 0.54 s by
runs, under RE2. google-re2's `Match.span()` takes a group's number, not its
name.

**Measured.** On AnnoCTR's 400 texts, 44 of which hold a letter or a digit
outside ASCII, Stage 2's 12,350 entities, the alias lists, the header dates and
the YARA rule names are identical before and after, under both engines: the
change acts only where a letter or digit of another script meets a pattern.
`tests/test_unicode_word_digit.py` runs 68 cases that pass with re2 and
without it. Before the fix 47 failed under `re` and 20 under RE2; the ones that
passed under both are the helper tests, two positive controls and the three
cases that guard the mask's letter. It also fails on a module-level
pattern compiled by `compile_pattern` that says `\w` or `\d`, or `\b` without
`re.ASCII` (read in the assignment's source), unless it is listed with a
reason; only Stage 2g's patterns are listed. It refuses `\s` in a `re.ASCII` pattern too,
since `re.ASCII`'s `\s` has `\v` and RE2's has not.

**What remains.**

- `re.ASCII` also keeps `re`'s case folding to ASCII, where RE2 folds the
  Kelvin sign into `k` and the long s into `s`: the registry pattern
  (`IGNORECASE` and `re.ASCII`) reads a hive spelled with them under RE2 only.
  The Windows path pattern lost `IGNORECASE` instead, whose letters are
  `[A-Za-z]` anyway.
- The glued rule reads Unicode categories. Arabic, Hebrew and Devanagari have
  no case either, though they write spaces: an IoC glued to one of their
  letters is kept, as RE2 kept it.
- Digits of other scripts in an IoC or a date are refused by both engines
  now. Reading them, by folding them to ASCII before Stage 2 (NFKC would also
  fold fullwidth letters), is a separate decision.
- Two other divergences are not `\w`, `\d` or `\b`. Under `IGNORECASE`, `re`
  folds the Turkish İ and ı into `[a-z]` and RE2 does not: the URL pattern
  ends `http://evil.com/kılavuz` at `http://evil.com/k` under RE2. And `$`
  matches before a final newline under `re`, not under RE2.
- google-re2 was run on Python 3.12 only (`~/.cache/ctiparsor-ci312`, as in
  CI); the 3.14 venv has no re2.
