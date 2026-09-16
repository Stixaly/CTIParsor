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
