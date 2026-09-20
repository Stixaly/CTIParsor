# ADR-0056 — Sync the domain regex's TLD-exclusion list with the bare-filename extension list

**Status:** Accepted (implemented 2026-09-20)
**Date:** 2026-09-20
**Relates to:** [pipeline/stage2_extraction.py](../../pipeline/stage2_extraction.py), ADR-0055

## Context

ADR-0055's real-corpus measurement (12 reports, entities already recorded by
the running pipeline) surfaced a pattern bigger than everything that ADR
fixed combined: **137 cases where the same literal string was typed both
`domain` and `file`**, both from `source="ioc"` — the deterministic regex
layer in `pipeline/stage2_extraction.py` disagreeing with *itself*.
`resolve_type_conflicts()` (ADR-0055) correctly refuses to arbitrate this —
both rows share the same (top) precedence, so picking one would be a guess,
not a resolution — so these 137 duplicate, contradictory rows were reaching
the review queue untouched.

Root-caused by grepping the 137 conflicting values for their trailing
extension:

| Extension | Count | Cause |
|---|---|---|
| `.com` | 126 | `_extract_bare_filenames()`'s extension allow-list (`_MALWARE_FILE_EXTS`) includes `com` (a real, if legacy, DOS executable extension) — and every one of those strings *also* matches `_DOMAIN_PATTERN`, because `.com` is (obviously) the most common TLD there is. |
| `.msi`, `.pl`, `.sys`, `.cmd`, `.app` | 11 | `_DOMAIN_PATTERN`'s TLD-exclusion list (a second, independently hand-typed set of extensions) never had these five added to it, even though they were already in `_MALWARE_FILE_EXTS`. The two lists had drifted apart. |

Manually reviewing every one of the 113 *distinct* bare `.com` values behind
the 126-count row (`cert.pl` excluded — different extension): every single
one — `hooks.slack.com`, `pastebin.com`, `cloud.google.com`,
`publicdomainregistry.com`, `trycloudflare.com`, a long list of
passkey-phishing domains, etc. — is unambiguously a domain. Zero were
actually a `.com`-extension malware filename in this corpus.

## Decision

Two changes, both in `pipeline/stage2_extraction.py`:

1. **Remove `"com"` from `_MALWARE_FILE_EXTS`.** This constant is consumed
   by exactly one pattern, `_BARE_FILENAME_PATTERN` — a *path-less* filename
   match, used specifically to avoid flooding on prose like "report.pdf".
   `_WIN_PATH_PATTERN` / `_UNIX_PATH_PATTERN` (full paths, e.g.
   `C:\Windows\Temp\update.com`) do not consult this list at all and are
   unaffected — a `.com` file mentioned with a real path is still caught,
   unambiguously, because a path has no domain-collision risk. Only the
   *bare*, path-less form is affected, and that is exactly the form where
   the ambiguity with a domain exists.
2. **Derive `_DOMAIN_PATTERN`'s TLD-exclusion list from `_MALWARE_FILE_EXTS`**
   (now without `"com"`) unioned with a small explicit list of non-malware
   document/media/data extensions (`_DOMAIN_EXTRA_NON_TLD_EXTS`: pdf, docx,
   png, json, yaml, …) that `_MALWARE_FILE_EXTS` has no reason to know
   about. Built once at import time from a `set()` union instead of two
   independently hand-typed literals, specifically so the two lists cannot
   drift apart again — that drift is what caused 11 of the 137 conflicts.
   `_MALWARE_FILE_EXTS` had to be moved earlier in the file (before
   `_DOMAIN_PATTERN`) so the derivation has something to read.

## Options considered

- **Exclude `.com` from `_DOMAIN_PATTERN` instead** (treat it like the other
  malware extensions) — rejected outright: `.com` is the single most common
  TLD in the world. This would silently stop detecting the majority of real
  C2/phishing domains in any report, trading 126 noisy duplicate rows for a
  much larger, silent recall loss on real domain IOCs.
- **Let `resolve_type_conflicts()` (ADR-0055) pick a winner between two
  equal-precedence `ioc` rows using a shape heuristic** (e.g. "has 2+ dots →
  domain") — rejected: that logic belongs at the point where the ambiguity
  is created, not bolted onto a generic cross-source reconciliation pass
  that is deliberately source-precedence-based, not content-based. Fixing
  `_extract_bare_filenames()` itself is also strictly better: it stops the
  contradictory `file` row from being generated at all, rather than
  generating it and then discarding it downstream.
- **Keep `.com` in `_MALWARE_FILE_EXTS` but require additional context**
  (e.g. a preceding word like "dropped" or "renamed to") before treating a
  bare `.com` string as a file — rejected as over-engineering for a regex
  layer whose whole design philosophy elsewhere is simple, deterministic
  rules (see `_extract_bare_filenames`'s own docstring: extension allow-list
  only, no NLP). The measured 113-domains/0-files split on real data does
  not justify the added complexity and its own new failure modes.

## Consequences

- **Easier:** the 137 domain/file contradictions measured on the source
  corpus are fully eliminated (137 → 0, re-verified by re-running
  `extract_entities()` against the same 12 reports after the fix). Nothing
  in this fix touches CyNER, GLiNER, the gazetteer, or Stage 3 — it is
  entirely inside the regex layer.
- **Harder / watch:** a bare `.com` string with no path is now *always*
  read as a domain, never a file — the one deliberate, disclosed trade-off.
  A future report where a bare `.com`-extension malware filename is the
  correct read and no path is given would be mistyped as a domain. Judged
  acceptable given 113/113 real bare `.com` strings in the source corpus
  were domains and the base rate of this specific legacy technique is low;
  revisit if it recurs.
- **Not addressed by this ADR:** the `.msi`/`.pl`/`.sys`/`.cmd`/`.app` gap
  was a *maintenance* bug (two lists able to drift), now structurally
  prevented by deriving one from the other — but the underlying question of
  "should this string ever be *both* types" for extensions not yet observed
  in a real report remains open the same way it was before; this ADR closes
  the specific cases measured, not the category in the abstract.
- **Superseded/related:** builds directly on ADR-0055's
  `resolve_type_conflicts()`, which correctly identified these 137 rows as
  *not* its job to fix (tied precedence) and pointed at this file instead.

## Validation record (2026-09-20)

| Check | Result |
|---|---|
| New unit tests | `tests/test_stage2.py::TestDomainFileTypeAmbiguity` (5 tests): the 6 real drifted-extension values are `file`-only; the 4 real bare-`.com` domains are `domain`-only; a `.com` file WITH a real path is still caught as `file`; the one genuinely ambiguous bare-`.com`-with-no-path case defaults to `domain` (documented trade-off); an end-to-end mixed-report check asserts no value is ever typed both `DOMAIN` and `FILE` |
| Full suite | 1160 passed (+5 from this ADR), 15 skipped, 239 errors — same pre-existing `CTIPARSOR_TEST_DATABASE_URL` errors as ADR-0055, zero new failures, zero regressions among the pre-existing 84 `tests/test_stage2.py` tests (including the domain-extraction and bare-filename tests already covering `isolated-domain.com`, `report.pdf`/`chart.png`/`summary.docx`, and the path-vs-bare-filename dedup case) |
| ruff | `pipeline/stage2_extraction.py`, `tests/test_stage2.py` — clean |
| mypy | `pipeline/stage2_extraction.py` — 2 pre-existing errors (`re2` / `iocextract` missing type stubs, unrelated third-party import lines this change does not touch), no new errors |
| **Real-corpus re-measurement** | Re-ran `extract_entities()` against the exact same 12 report texts that produced the original 137-conflict count: **0 domain/file conflicts remain**, across all 12 reports individually and in aggregate |
