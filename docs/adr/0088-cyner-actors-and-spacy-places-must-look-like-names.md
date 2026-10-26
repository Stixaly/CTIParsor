# ADR-0088: A CyNER threat actor and a spaCy place must look like a name

**Status:** Accepted
**Date:** 2026-10-18
**Amended by:** [0089](0089-the-malware-lead-measured-once-on-test.md)
(2026-10-19). Rejected: the malware lead it registered on top of these filters,
measured once on test and not adopted; its code was removed.
**Deciders:** maintainer
**Amends:** ADR-0050 (for `Threat_group`, a second filter follows the
generic-language one; `Malware` is unchanged)
**Relates to:** ADR-0060 (the protocol this adoption followed), ADR-0051 (the
calibrated cutoffs, the other lever on the same stages), ADR-0035 and ADR-0086
(the freshness list and its scopes), ADR-0061 (a Location Stage 4 cannot build
is recorded as dropped)

## Context

The audit of 2026-10-17 named entity precision as the main quality defect of the
shipped bundle. Measured on AnnoCTR dev (16 reports, strict matching, the full
pipeline with the LLM, commit `1ef9638`):

| Type | Gold | Strict TP / FP | Precision | Recall |
|---|---:|---|---:|---:|
| threat actor | 16 | 15 / 97 | 0.134 | 0.938 |
| malware | 39 | 34 / 132 | 0.205 | 0.872 |
| location | 97 | 39 / 57 | 0.406 | 0.402 |

Most false positives come from two models. CyNER (Stage 2d) gave 87 of the 97
threat-actor false positives and 93 of the 132 malware ones. spaCy (Stage 2)
gave 23 of the malware false positives and most of the location ones. On AnnoCTR
train (70 reports, no LLM) the picture is the same: threat actors 63 TP / 413 FP
(precision 0.132), locations 143 / 182 (0.440).

Two defects explain the first and the last of these rows.

- **CyNER's `Threat_group` label fires on any span that talks about actors.**
  ADR-0050 removed the spans made only of its own category vocabulary (141
  words, `_GENERIC_TOKENS`). What it left reads like prose: "cybercriminals",
  "underground forums", "Chinese threat actors", "Iran", "United States".
- **spaCy's `GPE` label, mapped to a location, fires on products, vendors and
  protocol names**: "C&C", "XSS", "GitHub". It also returns "the United States"
  with its article, which is scored as a partial match and which Stage 4's ISO
  country table (`_COUNTRY_ISO`) does not know, so no Location is built for it.

A measurement of a filter cannot stop at the extractors. Stage 3 receives
CyNER's names in its prompt and drops its own names that CyNER already found.
Removing a CyNER row can bring back an LLM row, or change what the LLM
extracts. So the decision rests on a real run with the LLM.

## Decision

**1. One switch, on by default.** `NER_PRECISION_FILTERS`
(`pipeline/ner_precision.py::enabled`) is read at call time and defaults to
true. `false` restores the behaviour before this ADR. That was checked by
replaying recorded model outputs through the code of this change with the switch
off: the Stage 2 output is identical to the baseline's on 70 of 70 train
documents and 16 of 16 dev documents.

**2. CyNER `Threat_group`: ordinary language is dropped.** `refine_cyner`
judges each fragment, after Stage 2d has split and normalised it
(`_split_fragments`, `_normalize_candidate`, `_collapse_repeated_token`) and
before the checks of ADR-0050 and the case-insensitive dedup. A fragment is
dropped when:

| Rule | Dropped |
|---|---|
| It has no letter, is a CVE id, or is "Agent", "Crew" or "Miner" alone | `2020`, `CVE-2020-1234`, "Crew" |
| The report is written with capitals, and the fragment has no capital letter and no digit | "cybercriminals", "underground forums", "same threat actor" |
| The whole value, without a leading "the", is a country | "United States", "Hong Kong", "New Zealand" |
| Every word of 3 or more letters is a category word, a software name, a nationality or a country | "Chinese threat actors", "North Korean hackers", "Iran", "Linux operators" |

The words are, in one set:

- ADR-0050's `_GENERIC_TOKENS` (141 words) and `_MORE_GENERIC` (178 words,
  read in the AnnoCTR train false positives: criminals, underground, forum,
  botnet, keylogger, affiliates, bad, same, multiple…);
- Stage 2's list of software names `_NER_PRODUCT_BLOCKLIST` (93 entries: Linux,
  Windows, JSON…), with powershell, mac, vbs, vba, excel and office added;
- 21 nationality words (chinese, russian, iranian, north, south…);
- the countries of Stage 4's `_COUNTRY_ISO`, with korea, prc, dprk, us, usa and
  hong kong.

Words that form real names stay out of the list on purpose: agent (X-Agent),
crew (Shell Crew), circles (Circles), miner (Miner Dropper). "Agent", "Crew"
and "Miner" are dropped only when they stand alone. A name with a digit passes
the capital-letter test whatever its case: "apt29" is kept.

The capital-letter test is skipped for a text with fewer than 0.5% capital
letters, a lowercase chat log or OCR where case says nothing. The share is
counted on words made only of letters, so an appendix of hashes or URLs does not
turn a report into a lowercase text. Every AnnoCTR train and dev report is above
1.6%.

`Malware` is untouched. The same rule applied to CyNER's malware was measured
and not adopted (Options considered).

**3. spaCy `GPE` → location: the value must be able to be a place.**
`refine_spacy` runs in Stage 2's `_extract_ner_entities`, after its existing
rules for versions, `@` scopes, two characters or fewer and pure numbers, and
before the `_GPE_BLOCKLIST`.

- The value is put on one line ("Saudi\nArabia" from a wrapped line). A leading
  "the" and a trailing apostrophe are dropped ("the United States" becomes
  "United States").
- A country, or a known abbreviation (U.S., USA, UK, UAE, PRC…), is kept. Stage
  2's length rule still drops a two-letter value, and now also "the US", whose
  article is gone: the check runs again after the strip.
- Any other value is kept only if it can be a place name: letters (accented
  ones too: São Paulo, Zürich), spaces, periods, hyphens and apostrophes; a
  capital first letter; not an all-capital acronym of five letters or fewer
  (XSS, SCADA, IRGC); no camel case (GitHub, DocuSign; McLean and MacKenzie are
  allowed); not made only of category or software words (Payload, Exploit,
  Linux). "C&C", "C++", "regsvr32", "logs.txt" and "beirut" in a URL go.

Other spaCy types, PRODUCT → malware included, are unchanged.

**4. Why before the dedup.** CyNER and spaCy keep the first spelling of a name,
case-insensitively. If the dedup came first, "blackwater" read in a URL slug
would hide a later "BlackWater" and the filter would then drop the only copy. The
filter drops the lowercase copy first, so the capitalised spelling survives
whichever was reported first (`test_the_lowercase_copy_is_dropped_before_the_case_insensitive_dedup`).

**5. The stage report says it.** Stages 2 and 2d record "precision filters on
(ADR-0088)" as the reason of their report line when the filters run. The run
config captures `NER_PRECISION_FILTERS` (`_CAPTURED_ENV`) like any allow-listed
variable: it appears in `env` only when it is set, not as the default it falls
back to, which is why the stage report carries the note. `tests/conftest.py`
removes the variable for every test, so the Stage 2 tests run at the default
whatever `.env` says. A test about the filters sets it itself.

## How it was measured

The protocol is ADR-0060's. The full tables, the lost entities read in context
and the rules of the leads not adopted are in
[docs/eval/ner-precision-2026-10.md](../eval/ner-precision-2026-10.md).

- **Designed on train**, with no LLM (70 documents, Stages 1, 2, 2b, 2d, 2e,
  2g), by re-running Stage 2 on recorded CyNER and spaCy outputs.
- **Criteria fixed on 2026-10-18, before any dev figure with a filter.** Each
  lead is judged on its own, on the types it acts on: G1 strict precision +5
  points on dev with the lower bound of the 95% paired-bootstrap interval above
  0; G2 at most one gold entity of the type lost; G3 strict F1 does not go down;
  G4 no other type's precision or recall drops by more than 1 point; G5 at most
  2% of the type's true positives lost on train; G6 the retained combination,
  run for real on dev with the LLM against a baseline run of the same commit
  with the switch off, meets G1 to G4. G4 first read "moves"; it was changed to
  "drops" before any dev figure, because removing a CyNER row can let a spaCy
  location through the type-conflict resolution and raise recall.
- **Offline simulation on dev**, to choose what goes to the real run.
- **Real run (G6)** on the 16 dev documents with the full `evaluation run`
  configuration (Stages 1 to 3 with 3d and 3f, `TTP_MODE=select`,
  `LLM_TEMPERATURE=0`, `LLM_SEED=13`, `Inferact/Qwen3.8-27B-NVFP4`). 10,000
  resamples, seed 13. The test split was not read.

G6, AnnoCTR dev, strict, switch off → on:

| Type | Precision | Δ precision [95% interval] | Recall | F1 | TP / FP |
|---|---|---|---|---|---|
| threat actor | 0.134 → 0.326 | +19.2 [+11.4, +30.9] | 0.938 → 0.938 | 0.234 → 0.484 | 15 / 97 → 15 / 31 |
| location | 0.406 → 0.526 | +12.0 [+5.1, +18.9] | 0.402 → 0.412 | 0.404 → 0.462 | 39 / 57 → 40 / 36 |

- CyNER's threat-actor false positives went from 87 to 22. Nothing was lost.
- Locations gained one gold entity and lost none: "Kingdom of Saudi Arabia",
  which spaCy gave as "the Kingdom of Saudi Arabia", offline and in the real
  run. The false positives from spaCy alone went from 44 to 23.
- Malware and identity are unchanged (malware precision 0.205, identity 0.345).
  Tool precision rose by 1.1 points [0, +3.9]. Techniques, for information and
  not a gate: F1 +0.024 [−0.016, +0.080], inside run-to-run noise.
- The LLM sees fewer CyNER names, and its answers change: one threat-actor and
  one tool false positive fewer than the offline simulation predicted. It also
  named three actors the baseline did not have (Sandworm, Shathak, "Ministry of
  State Security of China"), real names that AnnoCTR does not annotate in those
  reports and that CyNER found in neither run.
- On train: threat actors 0.132 → 0.320 (recall 0.851 unchanged, 0 of 63 true
  positives lost); locations 0.440 → 0.602 and recall 0.401 → 0.445, with one of
  143 true positives lost ("The United States", annotated with a capital "The").

G1 to G5 hold for the threat-actor filter and for the place filter. The filters
cost a few microseconds per name.

## Options considered

Three more leads were designed on train and measured with these two. Each lost
no gold entity on dev. None reaches the +5 points G1 asks of a lead on its own,
so none is in the code.

| Lead | Dev precision, strict | Train |
|---|---|---|
| The rule of decision 2 applied to CyNER's malware | malware 0.205 → 0.231, +2.6 [+1.5, +4.0] | lost 2 of 153 TP: "BlackWater", twice, both found only in a URL slug |
| B. CyNER: reduce a name with its category around it to the name ("Ryuk ransomware", "hacking group TA505") and split on brackets | threat actor +1.2 [+0.4, +2.4], malware +3.0 [+1.2, +5.7] | lost none |
| C. spaCy: PRODUCT no longer proposes malware | malware 0.205 → 0.239, +3.5 [+1.8, +5.1] | lost 1 of 153 TP: "Taurus", found by spaCy alone |

- **Adopting the malware leads on their joint effect.** With all four leads in
  place, malware precision rose by 13.2 points [+9.1, +18.6] offline with
  nothing lost. That figure was read after the measurement. A gate that is
  moved once the numbers are known gates nothing. The combination would have to
  be registered as one lead before it is measured, on data this study has not
  read: dev has been read, and the test split is kept for frozen configurations
  (ADR-0060).
- **spaCy's own label majority.** Keep a place only if spaCy calls the same
  string a place at least as often as anything else in the chunk. On train it
  removed nothing and lost two places.
- **Dropping a place whose name is the host of a link in the chunk**
  (`proofpoint.com`). On train it removed 6 false positives and lost Doha.
- **A country list as the only test for places.** It loses 21 train true
  positives: cities and states.
- **Raising CyNER's threshold.** ADR-0050 already measured that generic spans
  sit in the same confidence range as real names ("malware" at 0.98, ARGUEPATCH
  at 0.93). No cutoff separates them.

## Consequences

- **What the bundle gets.** Fewer Threat Actor objects named after ordinary
  language, and Locations that now ship because Stage 4 finds them in its ISO
  table ("the United States" is now "United States"). Stage 4 already built no
  Location for a value outside `_COUNTRY_ISO` and recorded it as dropped, so the
  place filter changes the analyst's entity list more than the bundle.
- **The freshness list.** The change alters Stage 4's output for the same
  input, so the commit that lands it is listed in `BUNDLE_AFFECTING`
  (`pipeline/bundle_revisions.py`) by a follow-up commit that names its SHA, as
  was done for ADR-0063. Its scope is `extraction` (ADR-0086): the fix acts in
  Stages 2 and 2d, and a finalize rereads the rows a run wrote and cannot remove
  what the run extracted. Only a new run clears it. Stored bundles are not
  rebuilt.
- **Malware precision does not move.** It stays at 0.205 on dev: 93 of its 132
  false positives come from CyNER and 23 from spaCy. The follow-up is the
  malware leads above (A for malware, B, C), registered as one lead and
  measured on data this study has not read.
- **Known limits.**
  - A name written only in lowercase in a report written with capitals is
    dropped for threat actors. On train this cost none of the 63 true positives.
  - "Iranian Cyber Army" and "Pakistan Cyber Army" are dropped (every word is a
    nationality or category word), and so is an actor named "Cuba" (a country).
    Stage 2b's gazetteer still matches ATT&CK names, and gazetteer rows win the
    merge.
  - Vendor names that look like towns stay places: Proofpoint 15 times on
    train, then Gecko, Citrix, Cisco. Nothing in their spelling tells them from
    a town.
  - The lowercase-text exception is measured on no such report.
  - What remains among threat actors is mostly real names AnnoCTR does not
    annotate in that report (Fancy Bear, APT10, Sofacy, Lazarus, Winnti) and
    gazetteer matches outside this work.
- **The word lists need upkeep.** `_MORE_GENERIC` was read in one corpus's
  false positives, as ADR-0050's list was in one report's. A report will bring
  vocabulary it lacks, and an ordinary word that is also an actor's name will be
  dropped. The place filter has no list of towns to maintain: it tests the
  spelling.
- **Reproducing an earlier run.** `NER_PRECISION_FILTERS=false` gives the
  earlier output exactly. A run's `env` has no `NER_PRECISION_FILTERS` unless
  it was set, before this change as after it: the stage report tells them
  apart, with "precision filters on (ADR-0088)" on Stages 2 and 2d when the
  filters ran.

## Implementation

- `pipeline/ner_precision.py`: `enabled`, `text_is_cased`, `actor_is_ordinary`,
  `refine_cyner`, `place_name`, `refine_spacy`.
- `pipeline/stage2d_cyner.py`: `extract_cyner_entities` calls `refine_cyner`
  after the fragment is normalised and before the dedup.
  `pipeline/stage2_extraction.py`: `_extract_ner_entities` calls `refine_spacy`.
- `pipeline/orchestrator.py`: the stage-report note for Stages 2 and 2d.
  `api/run_config.py`: `NER_PRECISION_FILTERS` in `_CAPTURED_ENV`.
  `.env.example`.
- `docs/eval/ner-precision-2026-10.md`: the measurement.

Tests:

- `tests/test_ner_precision.py` (85 tests): the switch; what is dropped and what
  is kept for threat actors and for places; malware and other spaCy types
  unchanged; the lowercase-text exception and the hash appendix that must not
  trigger it; Stage 2d and Stage 2 with stubbed models, switch on and off,
  including the dedup order and the "the US" case.
- `tests/conftest.py`: the autouse fixture that removes the variable.
  `tests/test_run_config.py`: the variable is in the captured environment.
- Run locally on 2026-10-18 (PostgreSQL test server, `SKIP_HEAVY_MODELS=1`),
  filters on by default: full suite 2832 passed, 0 failed (2830 with the switch
  off, before the last two tests were added); the 9
  that did not run are 7 tests whose optional packages (google-re2,
  schemathesis, atheris) the local environment lacks and CI installs, and 2
  data-dependent skips. `ruff check .` clean, mypy no issues in 135 files,
  `reuse lint` 1230/1230.
