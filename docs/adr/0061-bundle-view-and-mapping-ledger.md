# ADR-0061 — The graph shows the bundle that ships, and Stage 4 says what it did to each row

**Status:** Accepted
**Date:** 2026-09-28
**Deciders:** maintainer
**Relates to:** ADR-0009 (trust & provenance — the observable → ObservedData →
Indicator chain it established, amended here), ADR-0012 (relationship
precision), ADR-0013 (graph completion), ADR-0024 (edge provenance), ADR-0035
(bundle staleness), ADR-0041 (observables route through their Indicator)

## Context

The Graph page drew the job store's rows — `entities` and `relationships` — and
never the bundle. The bundle is built from those rows (Stage 4) and then differs
from them in three ways the analyst could not see:

1. **Edges added.** Measured on the seven stored bundles in `output/`
   (2026-09-13/14): on *Breeze Comet* 104 of 124 relationships had no row
   behind them — 41 `indicator based-on observed-data`, 42 `threat-actor targets
   location/identity` (every actor × every targeted country and sector),
   20 IoC `indicates`, 1 transitive. On *UNC6671*, 103 of 103. Policy pins and
   Stage 4b completion (ATT&CK reference, transitive, long-distance) add more.
2. **Rows rewritten.** A verb STIX does not suggest for the pair becomes
   `related-to` (on *Industroyer2 IEC-104*, 12 of 12 extracted edges); a pinned
   rule replaces the verb; an observable endpoint opposite an SDO is replaced by
   its Indicator (ADR-0041).
3. **Rows dropped, silently.** An endpoint that resolves to no object, a
   self-loop created by alias resolution, an observable ↔ technique edge
   (ADR-0012), a country with no ISO code, a named entity found by NER but not
   echoed by the LLM (the first build maps malware/actors/tools from the LLM's
   lists only; finalize includes every stored row).

The analyst was therefore validating a graph that is not the one exported, and
could not tell which rows ship as drawn. Two further defects surfaced while
tracing this: link edits made on the Graph page never rebuilt the bundle (only
the Review page did), so its Download served a bundle that ignored them; and
the `ObservedData` wrapping each IoC asserted a sighting — `first_observed` /
`last_observed` set to the build time — that nobody made.

## Decision

### 1. A mapping ledger, written beside the bundle

`build_stix_bundle` takes an optional `MappingLedger` (`pipeline/bundle_ledger.py`)
and records, as it decides:

- for each **input relationship** (the rows): `emitted` (the SRO id, the final
  verb, each change — verb `not_suggested` / `policy_pin` / `unknown_verb`,
  endpoint `reroute`), `merged` (the edge it duplicates — another row, or a
  Stage 4 edge), or `dropped` with a reason (`unresolved_source|target|both`,
  `self_loop`, `observable_to_attack_pattern`, `no_indicator`, `invalid`);
- for each **input entity**: the object it became, the object it was merged
  into (`same_value`, `same_observable`, `same_technique`, `alias_canonical`),
  or why it was dropped (`no_iso_country`, `not_representable`,
  `not_in_llm_lists`);
- for each **object and SRO**, why it exists (`entity`, `extracted`,
  `ioc_indicator`, `ioc_based_on`, `ioc_association`, `targeted_location`,
  `embedded_rule`, `policy_pin`, `completion_*`, …);
- what the Stage 4b alias merge **removed after creation** (absorbed objects,
  self-loops and duplicates it produced, endpoints it rewired).

The bundle is byte-for-byte the same with or without a ledger (tested). The
ledger is stored in `jobs.bundle_ledger_json`, written in the same `UPDATE` as
`bundle_json` by both the pipeline run and finalize — never on its own, so it
always describes the stored bundle. `GET /api/jobs/{id}/bundle/ledger` serves
it (404 for a bundle built before this change; a rebuild produces one). It is
not STIX content and is not put in the bundle.

### 2. The Graph page has a bundle view, and it is the default

- **STIX bundle** (default, remembered per viewer): the bundle's objects and
  SROs; each link coloured by why it exists (from the report, Stage 4 mapping,
  policy rule, ATT&CK reference, inferred, embedded `*_ref` property), each
  toggleable in a legend with counts. Rows the bundle rewrote are amber. Rows
  and entities it dropped are drawn where they would have been, as hollow
  dashed **ghosts**, with the reason. The report, author identity, markings and
  the embedded source document are listed under "Also in the bundle".
  A **Differences** panel lists everything dropped, rewritten, merged, removed
  by 4b, and every review change the stored bundle predates.
- **Review rows**: the stored rows, as before, each annotated with its fate in
  the bundle (red dashed = not in the bundle, amber = ships rewritten), with a
  chip in the link editor and a detail panel that links to the edge in the
  bundle view.
- Every link edit on the Graph page schedules the same debounced quick
  finalize as the Review page; Download flushes a pending one first.
- Edges are clickable; the focused node's edges show their verb.

### 3. `indicator --based-on--> <SCO>`, directly; no ObservedData

The Indicator now points at the observable it was built from. `ObservedData`
is no longer emitted. This pair is not in the STIX 2.1 suggested-relationship
table, so it is recorded as the one documented project extension in
`stix_rel_spec._PROJECT_EXTENSIONS` (`rel_is_allowed`); `rel_is_suggested`
stays the verbatim spec check. The edge takes no policy override: it is the
Indicator's derivation, not a claim a pinned rule may rewrite.

## Options considered

| Option | Verdict |
|---|---|
| Recompute the differences in the browser from bundle + rows | Rejected: the reasons (alias canonicalisation, the spec table, the policy, ADR-0041 routing, 4b merges) live in Stage 4; re-deriving them in TypeScript would drift the first time either side changed |
| Put the ledger in the bundle (a custom property on the Report) | Rejected: it describes the build, not the intelligence; consumers would carry per-row review bookkeeping |
| Only annotate the review graph | Rejected: 80–100 % of the edges on the measured bundles have no row, so the review graph cannot show them at all |
| Keep ObservedData, draw it | Rejected by the user: the observable the analyst extracted is the object the Indicator derives from; the wrapper adds a fabricated sighting time |

## Consequences

**Easier:** the analyst works on the graph that ships and can see, per row, why
it ships as drawn, rewritten, merged or not at all. Measured on a seeded report
(`industroyer2-preview`): 3 of 9 rows dropped with their reason, 1 rewritten
(`malware communicates-with domain-name` → `related-to` to the domain's
Indicator), a deleted row visibly re-created by ATT&CK reference grounding.

**Harder / revisit:**
- The default `stix2validator` run still passes; its strict mode reports `{202}`
  on `indicator based-on <SCO>` (strict mode already failed these bundles on
  `{103}` UUIDv4 ids, `{303}` and `{401}` custom properties).
- Edges Stage 4 generates (mapping, pins, completion) cannot be rejected from
  the graph — only understood. Deleting a row does not remove an edge that
  ATT&CK reference or a policy pin re-creates; the view now shows this, it does
  not prevent it.
- ADR-0041 routing turns `malware communicates-with domain-name` — a
  *suggested* STIX pair — into `malware related-to indicator`. The ledger makes
  the loss visible; whether the routing should keep suggested SCO pairs is a
  separate decision.
- A bundle built before this change has no ledger: the view classifies its
  edges from their provenance properties only and offers a rebuild.

## Validation

`tests/test_bundle_ledger.py` (15 tests: every outcome and reason, origins,
4b alias merge, bundle unchanged by the ledger, storage + API round-trip),
`tests/test_stage4.py` (based-on to the SCO; a pinned `indicator>domain-name`
rule does not rewrite it), `frontend/src/components/graph/buildBundleGraph.test.ts`
(10 tests). Checked in the browser on the seeded report: both views, ghost
node/edge detail, the Differences panel, review → bundle navigation, and an
edit that rebuilt the bundle.
