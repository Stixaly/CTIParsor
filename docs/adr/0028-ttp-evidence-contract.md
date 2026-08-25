# ADR-0028: TTPs must quote, not describe

**Status:** Proposed
**Date:** 2026-08-23
**Deciders:** maintainer

## Context

ADR-0027 gated policy-pin materialisation on textual co-occurrence, and had to
exempt `attack-pattern` and `course-of-action` because neither can be located in
the report: the MITRE name appears verbatim in 24.3% of cases, the ATT&CK
external id in 16.8%. That exemption leaves **47% of the candidate pool
ungated** — 8,679 pairs of 18,426 across the four stored bundles, and 7,838 of
those in a single rule on one report.

The obvious anchor for a technique is not its MITRE name but the sentence the
extraction quoted when it decided the technique was present. 94.9% of TTP
entities (280 of 295) carry such a `context`. So the question is whether that
context can locate the technique in the report.

### It cannot, and the reason is not what it looked like

Measured over all 280 TTP contexts, matching each against its own report after
normalising the punctuation PDFs substitute (curly quotes, en/em dashes,
non-breaking spaces, ligatures):

| | count | share |
|---|---|---|
| verbatim (≥95% of the context found as one run) | 103 | **36.8%** |
| partial (≥50%) | 11 | 3.9% |
| **not found (<50%)** | **166** | **59.3%** |

The first hypothesis was PDF mangling. Applying progressively looser repairs
attributes the failures precisely:

| repair | recovered |
|---|---|
| baseline normalisation | 114 (40.7%) |
| **+ rejoin end-of-line hyphenation** | **0 (0.0%)** |
| + alphanumeric skeleton (drop all punctuation) | 2 (0.7%) |
| + word-level fuzzy match ≥0.75 | 11 (3.9%) |
| **still unlocatable** | **153 (54.6%)** |

Hyphenation recovers nothing. This is not an extraction artefact.

### The contexts are paraphrase, not invention

For each of the 166 unlocatable contexts, its distinctive tokens (identifiers,
paths, device names, versions — stopwords and bare digits excluded) were checked
against the report:

| distinctive tokens present | contexts | share |
|---|---|---|
| 100% | 41 | 24.7% |
| ≥80% | 89 | 53.6% |
| ≥50% | 35 | 21.1% |
| **<50%** | **1** | **0.6%** |

**99.4% of unlocatable contexts are paraphrases of real report content.** The
model recomposes facts that are genuinely in the document — dates, equipment
names, registry paths — into a sentence of its own. There is no hallucination
problem here. One case in 166 falls below half.

### The cause is the contract, and it is one line

`TTPExtracted` has no evidence field at all:

```python
class TTPExtracted(BaseModel):
    technique_name: str
    mitre_id: str | None = None
    description: str = ""
```

What the pipeline reads as evidence is a **description**, and the prompt asks
for exactly that. The model did what it was told.

Twenty lines below, in the same file and the same call:

```python
class RelationshipExtracted(BaseModel):
    ...
    evidence_text: str | None = None   # verbatim quote from source text
    evidence_label: EvidenceLabel = EvidenceLabel.REPORTED
```

The prompt already carries the anti-fabrication rules — the five-grade table,
"do NOT upgrade the label", "never fabricate a supporting quote" — and applies
them **only to relationships**.

The comparison settles it. Same model, same report, same call:

| field | what is asked for | verbatim |
|---|---|---|
| `RelationshipExtracted.evidence_text` | "verbatim quote from source text" | **208/262 (79.4%)** |
| `TTPExtracted.description` | a description | **103/280 (36.8%)** |

Holding by grade: `reported` 79.0%, `observed` 78.4%, `assessed` 90.0%,
`inferred` 80.0%. Asked to quote, the model quotes four times out of five.

### Why no automatic filter can be tuned today

The review table holds **39 accepted, 0 rejected, 256 undecided** — the 39 come
from the single job that was reviewed. And the only numeric signal is flat:
confidence averages **0.900** on accepted rows and **0.906** on undecided ones,
with a minimum of 0.9 everywhere. Nothing to threshold on. This ADR therefore
changes what is *collected*, and defers every question about what to *reject* to
a report reviewed end to end.

## Decision

Give TTPs the evidence contract relationships already have.

### 1. Schema

```python
class TTPExtracted(BaseModel):
    technique_name: str
    mitre_id: str | None = None
    description: str = ""                    # kept — it is a useful summary
    evidence_text: str | None = None         # verbatim quote from the report
    evidence_label: EvidenceLabel = EvidenceLabel.REPORTED
```

`description` is **not** repurposed. It stays what it is and what it is good at;
the mistake was reading it as something else. Two fields, two jobs.

### 2. Prompt

The TTP section gains the same instruction the relationship section already
carries, in the same words, so there is one rule in the file rather than two
dialects: quote verbatim, never fabricate, grade honestly, emit `gap` with an
empty quote when no explicit support exists.

### 3. Storage

`entities` gains three additive columns, following the existing `ALTER TABLE`
migration list in `api/db.py`:

```
evidence_text  TEXT
evidence_label TEXT
evidence_start INTEGER    -- resolved offset, NULL when not locatable
```

`RawEntity` gains the matching optional fields. Nothing existing changes type or
meaning, so old rows stay valid and old bundles stay reproducible.

### 4. Locate, record, never delete

A quote that cannot be found in the report is **not** discarded and the
technique is **not** dropped. `evidence_start` stays NULL and the label is
demoted one grade (`reported` → `inferred`). The measured 99.4% paraphrase rate
is the reason: an unlocatable quote is overwhelmingly a formatting failure, not
a false claim, and deleting on it would remove true techniques.

This is the same doctrine as `rel_is_suggested` and ADR-0027's fail-open guards:
only remove what can be positively proven wrong.

### 5. What it unlocks

A technique with a resolved `evidence_start` has a sentence index. ADR-0027's
`_evidence_terms` can then stop returning `[]` for `attack-pattern`, and the two
rules holding 8,679 of the 18,426 candidate pairs become gateable by evidence
instead of bounded by a budget ceiling nobody can set in advance.

## Options considered

### Option 1 — Verify the existing `description` and demote what fails

**Pros:** no prompt change; measurable against today's data immediately.
**Cons:** would demote 54.6% of techniques whose facts are demonstrably in the
report, punishing the model for answering the question it was asked.
**Verdict:** rejected once the repair attribution came back — it fixes nothing
and costs real coverage.

### Option 2 — Numbered sentences: the model returns an index, not text

**Pros:** exact by construction; a model that cannot count characters can still
pick from a list.
**Cons:** restructures the TTP prompt and inflates every chunk with sentence
numbering, for a problem the existing relationship contract already solves at
79.4%.
**Verdict:** deferred. Revisit only if Option 3 measures below ~70%.

### Option 3 — Extend the relationship evidence contract to TTPs (adopted)

**Pros:** the pattern exists, works, and is measured in the same call; one
schema addition and one prompt paragraph; no new vocabulary.
**Cons:** ~79% expected, not 100% — some quotes will still miss.
**Verdict:** adopted.

## Consequences

- **Easier:** a technique can be located in the report, which is the precondition
  for gating the attack-pattern rules and for any future precision filter.
- **Harder:** two fields now mean two things that read similarly (`description`
  and `evidence_text`); the review UI must show the quote, not the summary, or
  the distinction is lost on the analyst.
- **Unchanged:** no technique is dropped. The volume in the review queue does
  not fall from this ADR alone — it falls once ADR-0027's gate can consume the
  offsets.
- **Open, and separate:** all 295 TTPs come from `llm` (280) and `ioc` (15);
  **none from `semantic`**, though `stage2c_ttp_semantic.py:606` already sets
  `context=evidence[:200]` from a real sentence. Either Stage 2c was disabled on
  these runs or it contributes nothing. ADR-0024 noted the same anomaly across
  all entity sources without resolving it; `run_config_json` now makes it
  answerable. Tracked separately — it is a diagnosis, not this change.

## Results

### The locator, measured on both populations

`pipeline/evidence_span.py` normalises the substitutions PDF extraction
introduces (curly quotes, en/em dashes, five kinds of space, five ligatures)
while keeping an index map back to original offsets, then falls back from exact
match to longest prefix and longest suffix. Run over every stored quote:

| field | what is asked for | exact | partial | **located in a sentence** |
|---|---|---|---|---|
| `RelationshipExtracted.evidence_text` | a verbatim quote | 215/277 (77.6%) | 22 (7.9%) | **237 (85.6%)** |
| `TTPExtracted` → `context` (a description) | a summary | 103/280 (36.8%) | 6 (2.1%) | **109 (38.9%)** |

**2.2× apart, same model, same reports, same call.** The prefix/suffix fallback
is worth 7.9 points over exact matching alone, so the locator is not the limiting
factor — the contract is. This is the measurement the decision rests on, and it
was taken before the new prompt shipped, so it is a genuine baseline rather than
a self-report.

The ligature entry earned its place: `_CHAR_MAP` may only hold one-character
substitutions, because the index map depends on that invariant, so ligatures
(one character becoming two or three) are handled separately by emitting the
same original offset for every character produced.

### Verified against the live model

A 12,000-character chunk of GREYVIBE, run through `enrich_chunk` under the new
contract:

| | exact | located |
|---|---|---|
| GREYVIBE, old contract (`description`) | 20.5% | 23.1% |
| **GREYVIBE chunk, new contract (`evidence_text`)** | **6/6 (100%)** | **6/6 (100%)** |

Every quote returned was a verbatim sentence, every one carried a grade, none
was empty. The prediction — 38.9% moving toward 85.6% — is met and exceeded on
this sample.

**The sample is six techniques from one chunk, not a corpus.** Stage 3f removed
17 of 23 candidates as unsupported before this count, and only the first 12 KB
of the report was sent. The direction is unambiguous and the mechanism is
confirmed — the model copies when asked to copy — but the corpus-wide figure
still needs a full re-run.

### Two ceilings the contract broke, both found only on real data

The new field roughly doubles a TTP-heavy response, and that immediately hit
two independent guards that were sized for the old contract. Both destroy the
whole chunk rather than degrade:

| guard | was | symptom | now |
|---|---|---|---|
| `max_tokens` on the API call | 4096 | reply cut mid-object at 14,812 chars; **TTPs, relationships and malware families all lost** | `_MAX_OUTPUT_TOKENS`, default 8192 |
| `_MAX_RESPONSE_LENGTH` | 16,000 chars | a **complete, valid** 23,324-char reply truncated into invalid JSON | 48,000 chars |

The second is the more dangerous of the two: it does not cap the model, it cuts
a string that was already correct. The two are now coupled in a comment — the
character cap must stay above the token ceiling times ~4, or it silently undoes
it.

Neither was visible in unit tests. Both showed up on the first real call, which
is the whole argument for the project's step 8.

**Deliberately not predicted:** how many techniques change grade. ADR-0024
recorded a wrong directional prediction as a lesson; this ADR does not repeat it.

## Related

Unblocks the exemption ADR-0027 was forced to make. Applies the evidence
vocabulary of ADR-0009 to the one extraction output that never carried it.
Depends on nothing; every question about *rejecting* low-quality TTPs waits on a
reviewed report, which is the ground truth ADR-0023 Phases 3-6 also wait on.
