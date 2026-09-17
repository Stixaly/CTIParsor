# ADR-0050 — CyNER's Malware/Threat_group labels get a generic-language filter

**Status:** Accepted (implemented 2026-09-18)
**Date:** 2026-09-18
**Relates to:** [pipeline/stage2d_cyner.py](../../pipeline/stage2d_cyner.py)

## Context

A user reported that a real report (`apt44-unearthing-sandworm.pdf`) produced
far too many entities tagged `malware` or `threat_actor` to review. Pulling
the actual extracted entities for that job confirmed it: of the entities
`source=cyner` contributed, 193 were tagged `malware` and 62 `threat_actor` —
and well over a third of those were not named entities at all.

CyNER's `Malware` and `Threat_group` labels fire on any span *discussing*
malware or threat-actor activity, not only on spans that *name* one.
`extract_cyner_entities` accepted almost everything above a 0.70 confidence
score, with only a length check, a bare-version-number check, and a 7-word
organisation blocklist for `Threat_group`. The result, verbatim from the real
job:

- Pure generic language, often at high confidence: `"malware"` (0.98),
  `"ransomware family"` (0.96), `"disruptive tool"` (0.75), `"threat actor"`
  (0.85), `"cyber espionage"` (0.86), `"Russian government-backed cyber
  groups"` (0.80).
- A comma-separated list of six real malware names glued into one entity:
  `"AZORULT, FORMBOOK, REMCOS, URSNIF, SILENTNIGHT, TRICKBOT"`.
- Spans crossing a sentence boundary or mixing script: `"sponsor. CyberА"`,
  `"Народная group"`.
- Truncated possessive fragments: `"s Information Operations"`, `"s Primary"`.
- Countries mistagged as threat actors: `"Russia"`, `"Moscow"`.
- A legitimate software product mistagged as malware: `"MicroSCADA binary"`.

Confirming this wasn't just a reading of the data: in the job's own review
history, several of these — `"Russian state"`, `"campaign"`, `"backed threat
groups"`, `"influence operations"` — had confidence ≥ 0.90 (the tier the
existing design auto-accepts) yet were manually flipped to rejected by the
user. The system was already being told, one click at a time, that this
vocabulary is noise.

## Decision

**Filter each CyNER `Malware`/`Threat_group` prediction through five checks
before accepting it, all in `pipeline/stage2d_cyner.py`:**

1. **List splitting.** A raw span containing `,` or `/` is split into parts
   before anything else — each part is evaluated (and can survive)
   independently, instead of the whole list living or dying as one entity.
2. **Normalization.** Strip one leading article (`the`/`a`/`an`) and one
   trailing period.
3. **Boundary-artifact rejection.** Drop a span that still contains a period
   followed by whitespace (crossed a sentence boundary), any non-ASCII
   character (OCR or script-mixing garbage), or starts with a single
   lowercase letter and a space (a truncated possessive fragment). A bare
   interior period with nothing after it (`"BLACKENERGY.V2"`, `"Guccifer
   2.0"`) is *not* rejected — only period-then-whitespace is a real sentence
   break.
4. **Generic-vocabulary rejection.** Tokenize on whitespace/hyphens; if every
   token of length ≥ 3 is in a ~150-word enumerated stoplist of malware/actor
   category nouns, operational vocabulary, and modifiers (`_GENERIC_TOKENS`
   in the source), the span carries no identifying content and is dropped.
   A span with even one token outside that list survives — `"ARGUEPATCH
   Launcher payload"` keeps `ARGUEPATCH`, `"tunneler REGEORG"` keeps
   `REGEORG`.
5. **Type-specific denylists.** Two small, exact-observation-driven sets —
   `_KNOWN_NON_MALWARE = {"winrar", "microscada"}` and `_KNOWN_NON_ACTORS =
   {"russia", "moscow"}` — feed into the *same* generic-vocabulary check
   (step 4) rather than a separate blanket veto, so a fragment is rejected
   only when **every** token is either generic or denylisted. This matters:
   an earlier version of this fix used a standalone "any token denylisted →
   reject" rule, which correctly dropped `"MicroSCADA binary"` but also
   wrongly dropped `"XAKNET Cyber Army of Russia Reborn"` — a real
   hacktivist-front name — for containing the word "Russia". Folding the
   denylist into the same all-tokens-generic test fixes both.

The existing `_ORG_BLOCKLIST` (specific vendor/platform names, exact
whole-fragment match) is unchanged and still applies to `Threat_group` only.

## Options considered

- **Raise the confidence threshold instead of filtering content** — rejected:
  measured against this job, generic noise spans span the same confidence
  range as real names (`"malware"` at 0.98, `ARGUEPATCH` at 0.93); there is
  no threshold that separates them.
- **A denylist of exact noisy phrases** — rejected: the noise is
  compositional (`"disruptive"` + `"malware"`, `"commodity"` + `"malware"`,
  `"custom"` + `"malware"`, …), so an exact-phrase list would need to
  enumerate every combination and still miss the next report's wording. A
  token-level stoplist generalizes to unseen combinations of the same
  vocabulary.
- **Drop CyNER's `Malware`/`Threat_group` labels entirely, rely on the
  gazetteer + LLM stages** — rejected: CyNER contributed 142 malware and
  20 threat-actor entities that survived the new filter on this one report,
  most of them (the all-caps codenames: `ARGUEPATCH`, `AXETERROR`,
  `BRUSHPASS`, …) not present in the MITRE gazetteer at all. The label is
  valuable; only its unfiltered acceptance was the problem.

## Consequences

- **Measured on the real job** (`apt44-unearthing-sandworm.pdf`, replaying
  the exact CyNER output already produced for it): raw `malware` +
  `threat_actor` predictions from CyNER went from **255 to 162** (−36.5%).
  Split by type: `malware` 193 → 142 (−26.4%), `threat_actor` 62 → 20
  (−67.7%) — the threat-actor label was the more noise-prone of the two.
  Every one of the 93 removed entities was manually reviewed and is either
  generic language, a list-join artifact (its parts survive separately), or
  OCR/script garbage — none is a real name.
- **What becomes harder:** the generic-token stoplist needs upkeep. It is
  enumerated from one report's real noise, not a general-purpose English
  stopword list — a future report may surface descriptive vocabulary this
  list doesn't cover yet (residual false positives already known: `"CAD"`,
  bare `"MMG"` context aside, `"Yamux GOGETTER Tunneler"` — a real tool name
  fused with a real malware name into one span the splitter doesn't catch
  since there's no list separator).
- **A known, accepted loss:** `"Malicious Macro Generator"` (spelled out) is
  now rejected — every one of its words is in the generic stoplist — even
  though in this specific report it is the literal name Mandiant gives a
  real tool. Its acronym form, `"MMG"`, is unaffected and still extracted.
  Distinguishing a genuinely-generic-sounding proper name from an actually
  generic phrase would need acronym-echo detection (`"Malicious Macro
  Generator (MMG)"` → initials match) or similar; not built here, flagged as
  a follow-up if it recurs.
- Two regression tests lock the two real defects found during real-data
  validation, not just the designed behavior:
  `test_denylisted_word_does_not_veto_a_larger_distinct_name` and
  `test_dotted_names_are_not_mistaken_for_sentence_boundaries` in
  `tests/test_stage2d_cyner.py`.

## Validation record (2026-09-18)

| Check | Result |
|---|---|
| Targeted unit tests | `tests/test_stage2d_cyner.py`: 17/17 passed, including 8 new tests built from real production strings (not invented cases) |
| Regression-locks verified | Reverted the fix and reran the 8 new tests against the pre-fix code: all 8 failed, confirming they test the actual behavior change, not a coincidental pass |
| Full suite | 1227 passed, 15 skipped, 0 failures (`SKIP_HEAVY_MODELS=1`) |
| ruff | `pipeline/stage2d_cyner.py`, `tests/test_stage2d_cyner.py` — clean |
| mypy | `pipeline/stage2d_cyner.py` — clean, no output |
| Real data (`apt44-unearthing-sandworm.pdf`) | Replayed the job's actual captured CyNER output (255 `malware`/`threat_actor` rows) through the new filter: 162 survived (−36.5%); manually reviewed both the survived list (all genuine names) and the removed list (all generic language, list-join artifacts, or script/OCR garbage) |
