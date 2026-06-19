# ADR-0005: IoC Extraction & Defang Robustness

**Status:** Accepted (retroactively documented — already implemented)
**Date:** documented 2026-06-19
**Deciders:** maintainer

> Records the decision referenced in code/tests as `ADR-005` (e.g.
> `tests/test_stage2.py` — "Extended defang tests"). Documents what shipped.

## Context

CTI reports never present IoCs as clean values — analysts **defang** them so they
can't be accidentally clicked or executed: `hxxps://`, `evil[.]com`, `1[.]2[.]3[.]4`,
`user[at]evil[.]com`, `http[:]//`. Defanging styles vary widely across vendors,
and the same report often mixes live and defanged forms. Missing a defang variant
means silently dropping a real indicator.

## Decision

Treat **refanging** as a first-class, exhaustively-tested step, and extract IoCs
from list/appendix layouts — not just prose.

- **Refang matrix** — cover the defang families seen in the wild:
  - protocol: `hxxp(s)`, `h__p`, `hXXp`, `fxp`, `http[:]`, `http[://]`
  - dots: `[.]`, `(.)`, `{.}`, ` . `, word-boundary and path-internal forms
  - at-sign: `[at]`, `(at)`, `[@]`, …
  - case-insensitive throughout
- **Mixed content** — live and defanged IoCs in the same text both extract.
- **Appendix / list patterns** (overlaps ADR-0004 P1-C) — comma-separated rows,
  one-per-line indicator sections, pipe tables, multiple hashes per line,
  IPv4-with-port, URLs with path+query, hyphen-linebreak rejoining.
- **Normalisation** — IoCs are stored **refanged** (clean) so STIX values are
  canonical; the Review UI re-derives defanged variants to still highlight the
  original spelling in the source text.

## Consequences

- **Easier:** high IoC recall on real-world reports regardless of defang style; canonical STIX values.
- **Harder / revisit:** the refang regex set is broad and must be guarded by a large test matrix (`tests/test_stage2.py`) so a new pattern never regresses an old one.

## Implementation
`pipeline/stage2_extraction.py` (refang + extraction), highlight re-derivation in
`frontend/src/components/review/tokens.ts::generateDefangedVariants`, tests in
`tests/test_stage2.py`.
