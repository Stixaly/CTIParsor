# ADR-0055 — Three Stage-2 precision fixes found via a real-corpus mix-vs-LLM comparison

**Status:** Accepted (implemented 2026-09-20)
**Date:** 2026-09-20
**Relates to:** [pipeline/stage2g_alias_list.py](../../pipeline/stage2g_alias_list.py), [pipeline/stage2d_cyner.py](../../pipeline/stage2d_cyner.py), [pipeline/base.py](../../pipeline/base.py), ADR-0050, ADR-0013

## Context

A comparison ran the current multi-stage pipeline and a single full-document
LLM pass side by side on 12 real reports already in the system (an
operator's live corpus, not a synthetic benchmark), then diffed the two
outputs entity-by-entity against the operator's own accept/reject decisions.
Three concrete, reproducible defects fell out of that diff — none visible
from reading the code in isolation, all visible once real report text was
run through it:

1. **Alias lists are never split by any Stage-2 extractor.** "Static Tundra
   (aka Berserk Bear, Ghost Blizzard, Sandworm Team, Seashell Blizzard)" — a
   real sentence, from `CERT_Polska_Energy_Sector_Incident_Report_2025.pdf`
   — reached the database with all five names attributed to `source="llm"`
   (Stage 3). Neither the MITRE gazetteer (Stage 2b), CyNER (Stage 2d), nor
   GLiNER (Stage 2e) split the construct — each is either a fixed-vocabulary
   lookup or a span classifier, and none of the three has logic for "this
   sentence names several aliases of the same thing." The names only reached
   the database because a chunked LLM call happened to read that sentence
   carefully; a report processed without Stage 3 (the CLI's default
   configuration, or LLM_PROVIDER unset) would lose all five.
2. **CyNER occasionally doubles a token inside a span.**
   `"COLDWELL COLDWELL Dropper"` reached the database verbatim from
   `apt44-unearthing-sandworm.pdf` — the real name is `COLDWELL Dropper`,
   once. ADR-0050's five-pass filter checks for generic vocabulary, list
   separators, sentence-boundary artifacts and known non-names, but nothing
   in it collapses an adjacent repeated token.
3. **Two sources can disagree on an entity's *type* and both survive.**
   `merge_into()`'s dedup key is `(value.lower(), entity_type)` — by design,
   so a value that is genuinely two different things (an IP that is also
   coincidentally a hostname string) is not incorrectly collapsed. But this
   also means that when the gazetteer correctly types "PsExec" `tool`
   (S0029, a whole-word dictionary hit against MITRE's own Software list)
   and CyNER *also* recognises the same string — CyNER 2.0 has no dedicated
   Tool label, so it can only emit `Malware` or `Threat_group` — both rows
   reach the review queue, contradicting each other on the same name. Same
   for "Rubeus" (S1071, tool vs. CyNER's malware). Confirmed on
   `apt44-unearthing-sandworm.pdf`.

None of these three are model-quality problems (CyNER/gazetteer/GLiNER are
not being asked to do something beyond their design) — they are integration
gaps between stages that individually behave correctly.

## Decision

Three independent, additive fixes, each testable in isolation:

### 1. Stage 2g — Alias-list extractor (new)

`pipeline/stage2g_alias_list.py`. Pure regex, no model, no network call —
`available()` is always `True`. Looks for the explicit "X (aka Y, Z, W)" /
"X, also known as Y and Z" / "X (formerly known as Y)" construct and emits
one `THREAT_ACTOR` entity per name mentioned (anchor included), deduplicated
by value. Scope is deliberately narrowed to `THREAT_ACTOR` — the
overwhelmingly dominant use of this construct in CTI reporting is
vendor-naming convergence for the same intrusion set (Microsoft "Weather"
names, CrowdStrike "Animal" names, etc.); malware aliasing is rarer and
already partly covered by CyNER's own comma-splitting (ADR-0050 step 1)
when it appears inside one recognised span.

Confidence is fixed at 0.55 — below the auto-accept range used elsewhere —
because this is a syntactic heuristic with no learned-model backing; it is
meant to land in the analyst review queue like a medium-confidence CyNER
hit, not auto-promote. The cutoff is wired through `get_threshold("alias_list",
...)`, the same ADR-0051 calibration mechanism every other stage uses, so
real accept/reject decisions on this source can raise or lower it later.

Registered as the *last* stage in `pipeline.registry._STAGE_CANDIDATES` and
in `api/worker.py`'s manual Stage-2 orchestration (the actual production
path — `worker.py` does not go through `StageRegistry.run_all`, see
"Superseded/related" below) — deliberately last, so `merge_into`'s
first-writer-wins semantics let any higher-precision stage that also finds
the same (value, type) win over this heuristic one.

### 2. CyNER repeated-token collapse

`_collapse_repeated_token()` in `pipeline/stage2d_cyner.py`, called
immediately after `_normalize_candidate()` in `extract_cyner_entities()`.
Splits a candidate on whitespace and drops any token that case-insensitively
repeats the token immediately before it. A real name never repeats its own
token back-to-back, so this is a safe, unconditional collapse — no
allow-list needed, unlike ADR-0050's denylist-vs-generic-token distinction.

### 3. Cross-source type-conflict resolution

`resolve_type_conflicts()` in `pipeline/base.py`. A second pass, run once
after every Stage-2 source has been merged (both in
`StageRegistry.run_all()` and in `worker.py`'s manual orchestration, right
before the `[Stage 2] Extracted N entities` log line): group entities by
`value.lower()`; where a group has more than one distinct `entity_type`,
keep only the type(s) reported by the highest-precision source, using a
small explicit ranking (`ioc`/`gazetteer` > `semantic` > `cyner`/`gliner` >
`spacy`/`alias_list`). A value only one source ever reported, or that every
source agreed on, is untouched — this function only resolves a genuine
disagreement, it is never a filter on its own. Two sources of *equal or
unranked* precedence disagreeing keep both types, on the theory that
silently picking one would destroy information neither side is more
trusted on.

This is intentionally a separate pass from `merge_into()`, not a change to
its dedup key — `merge_into()`'s current behavior (same value, different
type = two distinct rows) is correct and already regression-tested
(`test_merge_into_keeps_same_value_different_type`) for the case where two
types really are both true. `resolve_type_conflicts()` only fires when
there is an actual same-value type disagreement to arbitrate, which
`merge_into()` structurally cannot detect on its own since it processes one
stage's output against the accumulated list at a time.

## Options considered

- **Add the missing dual-use tool names (Cobalt Strike, PsExec, Rubeus,
  Mimikatz, Impacket, DCRAT, BloodHound) to the gazetteer** — investigated
  first, as the seemingly obvious fix for the PsExec/Rubeus mistyping.
  **Rejected**: all seven are already in `gazetteer.json`, correctly typed
  `tool`, with real MITRE Software IDs (verified by grep before writing any
  code). The actual defect was never gazetteer coverage — it was that
  CyNER's independent, conflicting `malware` row for the same string was
  never reconciled against the gazetteer's correct one. Adding entries that
  already exist would have shipped a no-op fix for the wrong cause.
- **Fix the type disagreement inside `stage2d_cyner.py` itself** —
  rejected: CyNER's `extract_cyner_entities()` is called independently of
  the gazetteer (see `api/worker.py` Stage 2 orchestration) and has no view
  of what the gazetteer already found at call time. The reconciliation can
  only happen after all sources are merged.
- **Widen `merge_into()`'s dedup key to `value.lower()` alone (drop
  `entity_type` from the key)** — rejected: this would also collapse
  genuinely-different entities that happen to share a literal string (the
  IP-that-is-also-a-hostname case the existing test locks), trading a real
  false-negative for the type-conflict fix. `resolve_type_conflicts()` gets
  the same practical result without that regression, because it only acts
  when the *type* actually disagrees, not merely when the *value* repeats.
- **Type every alias-list entity from context** (infer MALWARE vs.
  THREAT_ACTOR per match) — deferred: not observed often enough in this
  12-report corpus to justify the added false-positive risk of a
  context-cue heuristic; flagged in the module docstring as a future
  extension if malware-alias constructs turn out to be common elsewhere.

## Consequences

- **Easier:** the alias-list gap and the CyNER duplicate-token artifact are
  closed with zero new dependencies and zero added model latency — both are
  regex-only. The PsExec/Rubeus-style contradiction can no longer reach the
  review queue as two rows arguing with each other.
- **Harder / watch:** `resolve_type_conflicts()`'s precedence table
  (`_TYPE_PRECEDENCE` in `pipeline/base.py`) is a manually maintained
  ranking keyed on the `RawEntity.source` string — a new Stage-2 source
  that does not appear in it defaults to the lowest precedence tier
  (`_DEFAULT_PRECEDENCE`), which is a safe default (never wins a conflict
  it wasn't explicitly trusted for) but is easy to forget updating when
  adding a new stage. Trusting `ioc` unconditionally is also not always
  correct: measured on the real corpus (see below), a malware component
  name written in dotted notation ("NIKOWIPER.MBR") gets kept as `domain`
  over the correct `malware` type in 4 of 22 real resolutions, because the
  precedence is source-based, not type-pair-aware. A follow-up that special-
  cases `domain` vs. `malware`/`tool` (or fixes the regex `domain` pattern's
  false-positive on dotted malware/tool names directly) would close this,
  but was not built here to keep this change's blast radius small.
- **Not fixed here, but surfaced by measuring this one:** the real-corpus
  run found 137 cases (across the same 12 reports) of the regex IoC layer
  in `stage2_extraction.py` disagreeing with *itself* — the same string
  matched as both `domain` and `file` by two different patterns. That is a
  larger volume of noise than the three defects this ADR fixes combined,
  and `resolve_type_conflicts()` correctly refuses to arbitrate it (both
  rows are `ioc`-sourced, tied precedence) rather than silently guessing.
  Flagged as the natural next target — it needs a fix inside the regex
  classification logic itself, not another cross-source reconciliation
  pass.
- **Scope not covered here:** the alias-list stage only emits `THREAT_ACTOR`
  (see "Options considered"); it does not itself create `duplicate-of`
  relationships between the aliases it finds — that linking is left to the
  existing alias-canonicalisation path (ADR-0012) and Stage 4b (ADR-0013).
- **Superseded/related:** `api/worker.py` runs its own hand-written Stage-2
  orchestration rather than `StageRegistry.run_all()` — a fact already
  called out in a comment at the CyNER merge site before this ADR
  ("the worker calls this path directly rather than through
  StageRegistry.run_all"). All three fixes were applied to *both* paths so
  they do not diverge, but this dual-maintenance point pre-dates this ADR
  and is not resolved by it.

## Validation record (2026-09-20)

| Check | Result |
|---|---|
| New/updated unit tests | `tests/test_stage2g_alias_list.py` (9 tests, built from the real five-alias sentence plus edge cases: no-anchor prose, unrelated parentheticals, dedup, confidence range); `tests/test_stage2d_cyner.py` (+4: pure-function and end-to-end collapse tests); `tests/test_stage_registry.py` (+5: `resolve_type_conflicts`, including the exact PsExec/Rubeus/CHISEL scenario from the real report) |
| Full suite | 1155 passed, 15 skipped, 239 errors — every error is the pre-existing `CTIPARSOR_TEST_DATABASE_URL` requirement (ADR-0053, no local PostgreSQL test instance in this environment), present before this change on unrelated files (`test_relationships_api.py`, `test_rule_lookup.py`, `test_settings_api.py`, `test_thresholds_api.py`, …); zero new failures |
| ruff | `pipeline/stage2g_alias_list.py`, `pipeline/base.py`, `pipeline/stage2d_cyner.py`, `pipeline/registry.py`, `api/worker.py`, and the three test files — all clean |
| mypy | Same file set — clean, no output |
| Regex safety / perf | Alias-list patterns smoke-tested against a 20,000-word adversarial input with no closing parenthesis (0.03s) and a ~150k-char realistic repeat (0.01s) — no catastrophic-backtracking behavior observed |
| Real-sentence check | The exact motivating sentence (`Static Tundra (aka Berserk Bear, Ghost Blizzard, Sandworm Team, Seashell Blizzard)`) verified end-to-end against the live module before the test suite was written |
| **Real-corpus measurement** | Ran both fixes against the same 12 real reports the defects were found on (not a held-out set — see "Known limitation of this measurement" below) |

### Real-corpus measurement (2026-09-20)

**Alias-list stage**: 5 of 12 reports contained at least one "aka" construct;
29 new entities found in total that previously depended on Stage 3 reading
that exact sentence carefully (or were lost entirely without Stage 3).
`fighting-ursa-aka-apt28-illuminating-a-covert-campaign.pdf` alone yielded
8 (APT28, Fancy Bear, Forest Blizzard, Pawn Storm, Sednit, Sofacy, Strontium,
Fighting Ursa) from one sentence.

**Type-conflict resolution**: of the 166 same-value type disagreements found
across the 12 reports' *already-recorded* entity rows, only 22 involve
sources at genuinely different precedence and are resolved; the other 144
are two `ioc`-sourced rows disagreeing with each other (137 of those
`domain` vs. `file` on the same string) and are correctly left as both,
per this ADR's own design (equal precedence must not silently pick a side).

Of the 22 genuinely resolved: **18 are unambiguous wins** — the gazetteer's
dictionary-verified type beats CyNER's coarse Malware/Threat_group-only
labeling for known dual-use tools across three different reports (Impacket,
PsExec, Rubeus, DCRAT, Empire, PoshC2, Remcos, SDelete, Mimikatz — the same
"CyNER has no Tool label" defect recurs well beyond the one apt44 case that
motivated the fix) plus one correct gazetteer-malware-over-CyNER-actor call
(BlackEnergy). **4 are a real, disclosed limitation, not a win**:
`itchyspark.smb`, `itchyspark.wmi`, `meterpreter.python`, `nikowiper.mbr` —
malware component names written in dotted notation — get kept as `domain`
(the regex IOC pattern false-positives on the dotted shape) over the
correct `malware` type from CyNER/Stage 3, because this ADR's precedence
table trusts `ioc` unconditionally over every model-based source. This is
now a *known, documented* regression risk rather than a silent one; a
type-pair-aware precedence (not just source-aware) is the natural follow-up
but was not built here — see "Harder / watch" below.

**The single largest pattern this measurement surfaced was not one this ADR
fixes**: 137 of the 144 tied-precedence conflicts are the regex IoC layer
disagreeing with *itself* — the same string classified as both `domain` and
`file` by two different patterns in `stage2_extraction.py` (Stage 2, not
touched here). This is a bigger volume of noise than everything this ADR
addresses combined, and is the natural next target — but it requires
changing the regex classification logic itself (mutual exclusion between
the domain and file/extension patterns), not the cross-source
reconciliation this ADR adds.

**Known limitation of this measurement**: all three defects were *found* on
this same 12-report corpus, so measuring the fix on the same reports is not
an independent validation — it confirms the fix does what it was written to
do on the data that motivated it, not that it generalizes. The alias-list
and gazetteer-vs-CyNER patterns recurring across *multiple, unrelated*
reports in the corpus (not just the one each defect was originally spotted
on) is reassuring but not a substitute for testing on new, unseen reports.
