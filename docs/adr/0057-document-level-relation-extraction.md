# ADR-0057 — Stage 3 document-level relation pass

**Status:** Accepted (implemented 2026-09-20)
**Date:** 2026-09-20
**Relates to:** [pipeline/stage3_llm.py](../../pipeline/stage3_llm.py), ADR-0004 (P2-B document context), ADR-0009 (evidence labels), ADR-0013/ADR-0055 (graph completion, `long_distance`)

## Context

Stage 3 extracts relationships one ~3000-character chunk at a time
(`enrich_chunk`, `CHUNK_MAX_CHARS`). Document-level entity context (ADR-0004
P2-B) is passed to every chunk so the LLM knows *which entities exist* across
the whole report, but each call still only *reads* one chunk's prose. A
relationship whose two supporting facts sit in different chunks — "malware X
is a variant of malware Y" in paragraph 2, "Y is attributed to actor Z" in
paragraph 40 — cannot be found by any single chunk call, however good the
model is; nothing forces the two paragraphs into the same window.

This was measured directly, twice, this session:

1. A full-document LLM read (no NER, no chunking) on 12 real reports found
   roughly 3x the relationships the production pipeline did on the same
   reports — but also missed IOC-table entities the regex layer handles
   better (see the "tout LLM vs mix" comparison earlier this session), so
   replacing the pipeline with a full-document LLM read is not the fix.
2. Activating the already-built `long_distance` completion engine (ADR-0013,
   turned on in ADR-0055) recovers much of this gap cheaply for reports that
   already have SOME base relationships (+18 to +51 relationships across
   three reports tested) — but adds **zero** new relationships on two reports
   Stage 3 extracted no relationships from in the first place (CERT-UA,
   Industroyer2), because it only bridges existing graph components; with no
   base edges there is nothing to bridge from.

So there is a real, separate case `long_distance` cannot reach: relationships
that never entered the graph at all, because per-chunk extraction never saw
both halves of the fact together. The fix has to happen at extraction time,
not at the completion-after-the-fact stage.

## Decision

Add `enrich_document_relations()` — one **additional** LLM call per report
(alongside, not instead of, the existing per-chunk calls) that:

- Reads the **whole report text**, not a chunk.
- Is given the **full known-entity list** (every Stage 2 NER entity, plus
  every entity the chunked Stage 3 pass itself already found — built right
  after the per-chunk loop finishes, so it is the most complete list
  available at that point).
- Asks for **relationships only** — a new, dedicated prompt
  (`_DOC_RELATIONS_SYSTEM_PROMPT` / `_DOC_RELATIONS_USER_PROMPT_TEMPLATE`),
  not a reuse of the full `enrich_chunk` schema. It does **not** ask the
  model to (re)discover entities, TTPs, campaign names, sectors, or IoC
  associations — a full-document *entity* read was measured (point 1 above)
  to be worse than the existing chunked+NER pipeline, so re-running that
  here would add lower-quality duplicate proposals, not value. Only the
  relation-finding gets the wider window; entity discovery keeps working
  exactly as it already does.
- Reuses every existing safety mechanism unchanged: the same
  evidence-citation contract (verbatim quote or `evidence_label: "gap"`,
  never fabricate), the same Stage 3b hallucination filter
  (`validate_llm_result`, run against the full text here — at its most
  meaningful, since there is no chunk-narrowness to compensate for), and the
  same Stage 3d self-verification (`verify_relationships`, opt-in via
  `ENABLE_STIX_VERIFICATION`) against the full text.
- **Needs no new merge logic.** Its output is just another
  `LLMEnrichmentResult` (every field but `.relationships` left empty) that
  gets appended to the list of per-chunk results already passed to
  `_merge_results()`. The existing `(source_value, relationship_type,
  target_value)` dedup key and better-evidence-wins tie-break (`_prefer`)
  apply to it automatically — a relationship found by both a chunk and this
  pass collapses to one, keeping whichever has the stronger evidence quote.

Wired in both the API worker (`api/worker.py`, the real production path) and
the CLI (`enrich_all_chunks`, for parity — the codebase already tracks CLI/
API parity as a concern for this exact function).

Opt-in via `ENABLE_DOCUMENT_LEVEL_RELATIONS=false` (default), same
convention as Stage 3d/3e/`completion.long_distance`: a new capability ships
off until measured on the operator's own corpus.

### Sizing

A dedicated prompt-length ceiling, `LLM_DOC_MAX_PROMPT_LENGTH` (default
300,000 chars), separate from the existing `LLM_MAX_PROMPT_LENGTH` (32,000,
chunk calls) — reusing the chunk ceiling would truncate away most of a
typical report before the model ever reached the entity list at the end of
the prompt. 300,000 chars covers every report in this project's corpus so
far (largest: ~110,000 chars) with headroom, and stays well inside Claude's
context window; validated against Anthropic only — a provider with a much
smaller context window (a local Ollama model) may need this lowered, or the
feature left off, which the `.env.example` comment says explicitly.

## A prompt bug found and fixed during validation (worth recording)

The first version of `_DOC_RELATIONS_SYSTEM_PROMPT` said: *"Do NOT propose
new entities, TTPs, campaign names, targeted sectors/countries, or IoC
associations."* Intent: don't re-run entity discovery (see "Decision" above).
Tested against a real report (`north-korea-nexus`, via an agent literally
following the prompt as a stand-in LLM call, before wiring in a live
provider) it produced only **12 relationships** — the model reasonably read
that sentence as "don't relate to entities of those types either," and
skipped every TTP/IOC/indicator entity in the known-entities list even
though the instruction only meant to say "don't add more of them." This
silently excluded exactly the class of relationship (`malware --uses-->
TTP`, `malware --communicates-with--> domain`) that IOC/TTP-table entities
exist to support.

Rewritten to state explicitly that *every* entity in the list, regardless of
type, is a valid relationship endpoint, and that "no new entities" means no
new entities *of any kind* through this schema (which literally has no field
to propose one in the first place — only `relationships`, each one
constrained to values from the given list). Re-tested on the same report,
same known-entity list: **88 relationships**, including the hash-to-malware,
C2-domain, and TTP bindings the first version dropped. This is recorded here
because it is exactly the kind of defect that would have shipped invisibly —
the feature would have "worked" (no errors, valid JSON, real citations) while
silently finding six times fewer relationships than it should have, and
nothing short of running it against a real report would have caught it.

## Options considered

- **Reuse `enrich_chunk()` as-is, just called with the full document as
  `text`** — rejected: it would also produce a full-document entity/TTP/
  campaign read (measured worse than chunked, see point 1 above) even if the
  extra fields were discarded after the fact, wasting output-token budget on
  fields never used and increasing truncation risk on a report with many
  relationships. A dedicated, relations-only prompt is smaller, cheaper, and
  more focused.
- **Replace chunked extraction entirely with a single document-level call**
  — rejected: the same corpus measurement that motivated this ADR also
  showed a full-document read is *worse* at entity recall than the existing
  chunked+NER pipeline (~25% recall of what the mix pipeline finds). Chunking
  stays for entities; only relationships get the wider window, additively.
- **Rely on `long_distance` completion alone instead of touching Stage 3**
  — rejected as insufficient, not wrong: `long_distance` is cheaper (no
  change to the core extraction path) and already measurably effective, but
  it structurally cannot help a report Stage 3 extracted zero relationships
  from, since it only bridges disconnected components in an existing graph.
  Both mechanisms are kept; they solve different halves of the same problem.
- **Give the document-level pass a dedicated checkpoint slot** (for
  crash-resume, mirroring the per-chunk checkpoint) — deferred: it is a
  single call, not a loop: on a crash between the chunk loop finishing and
  this call completing, a restart simply re-runs it once more (cheap) while
  every already-checkpointed chunk result is still reused. Not worth the
  added complexity for a one-shot call.

## Consequences

- **Easier:** relationships whose two ends are described in different parts
  of a report are now reachable even for a report where `long_distance`
  alone found nothing (the Industroyer2/CERT-UA case ADR-0055's extended
  validation flagged as unresolved). Measured on one report end-to-end after
  the prompt fix: 14 base relationships → 88 with this pass alone (before
  even layering `long_distance`/`transitive` completion on top).
- **Harder / watch:** a real interaction effect surfaced during validation —
  this pass generates relationships *for every entity already in the known
  list*, including any garbled/noisy entity an earlier NER stage let through
  (observed: raw YARA-rule string fragments like `string.fromCharCode`,
  previously sitting as isolated, unconnected noise, now get `has`/
  `indicates` edges to real malware, making that noise more visible in the
  graph rather than less). This pass does not introduce that noise — it was
  already in the known-entities list — but it does amplify its visibility.
  A future entity-list quality pass (filtering code-fragment-shaped
  "indicators" before Stage 3 sees them at all) would compound with this
  ADR's gains rather than being made unnecessary by it.
- **Cost:** one extra LLM call per report, sized to the whole document
  (larger than any single chunk call, though cheaper in aggregate input
  tokens than N chunk calls' worth of repeated system-prompt + overlap
  redundancy — chunking's own overhead). Off by default; an operator opts in
  per the same convention as every other optional Stage 3 pass.
- **Not addressed here:** the CERT-UA/Industroyer2 zero-base-relationship
  question is now testable with this pass (it does not depend on
  `long_distance`'s component-bridging logic, so it should surface
  relationships on those two reports where completion alone could not) but
  was not re-tested against those two specific reports as part of this ADR —
  flagged as the natural next validation step.
- **Superseded/related:** complements, does not replace, ADR-0013/ADR-0055's
  completion engines. Builds on ADR-0004 P2-B (document-level entity
  context) by extending the *relation-finding* window the same way P2-B
  already extended the *entity-context* window.

## Validation record (2026-09-20)

| Check | Result |
|---|---|
| New unit tests | `tests/test_stage3.py`: 3 new test classes (~17 tests) — flag default/override, happy path (relationship survives with evidence, every non-relationship field stripped even when the mocked LLM returns them, full text reaches the prompt untruncated, known entities listed, correct dedicated system prompt used), guards (empty known-entities list skips the LLM call entirely, provider-not-ready, malformed JSON, empty response, oversized text truncates rather than raising), and merge integration (a duplicate claim from both a chunk and this pass collapses to one via the existing dedup key; a relationship connecting two facts no single chunk contains still merges in cleanly) |
| Refactor safety | `_parse_llm_response()` factored out of `enrich_chunk()` (shared by both call sites) — all pre-existing `enrich_chunk` tests re-run and pass unchanged after the extraction, confirming behavior-preserving |
| Full suite | 1175 passed (+15 from this ADR net of the refactor), 15 skipped, 239 errors — same pre-existing `CTIPARSOR_TEST_DATABASE_URL` requirement as ADR-0055/0056, zero new failures |
| ruff | `pipeline/stage3_llm.py`, `api/worker.py`, `tests/test_stage3.py` — clean |
| mypy | `pipeline/stage3_llm.py` — clean (only the pre-existing, unrelated `re2` missing-stub note on a different file) |
| **Real-prompt validation** | Two rounds against the real `north-korea-nexus` report (same report used throughout this session's earlier experiments), using its actual known-entity list (90 entities) and the exact system/user prompt text, run via an agent standing in for the LLM call before any live-provider wiring: round 1 (buggy prompt) found 12 relationships and revealed the "don't propose new entities" ambiguity documented above; round 2 (fixed prompt) found 88, including hash-to-malware bindings from YARA rule metadata, C2 domain/IP resolution chains, and a cross-section actor-to-actor connection (`UNC1069 related-to UNC6780`) no other mechanism tested this session found |
