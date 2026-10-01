# ADR-0065: Review shows what nobody decided; an IoC indicates a technique through its Indicator

**Status:** Accepted
**Date:** 2026-10-01
**Deciders:** maintainer
**Amends:** ADR-0012 (the observable ↔ attack-pattern guard)
**Relates to:** ADR-0041 / ADR-0062 (observables route through their
Indicator), ADR-0058 (decision provenance), ADR-0061 (mapping ledger)

ADR-0064 is taken by the whole-document relation fixes, which were still in
review when this was written.

## Context

An analyst reported that they could not link an IoC to a technique, and asked
whether some links are never offered for validation. Both turned out to be
true. The checks below ran on a copy of `ctiparsor_measure` (7 real reports).

**1. An IoC → technique link never shipped.**
- The relationship form offered all 35 verbs for an observable and a technique,
  and suggested `related-to`.
- Stage 4 then dropped every observable ↔ attack-pattern edge, whatever its
  verb. The guard (ADR-0012) was aimed at the LLM's type errors, such as
  "domain communicates-with T1071". It ran before the Indicator routing of
  ADR-0041/0062, so it caught the analyst's links too.
- Reproduced: `link.ps1 indicates Group Policy Modification`, created and
  accepted in Review, was `dropped` with reason `observable_to_attack_pattern`.
- STIX 2.1 lists `indicator indicates attack-pattern`.
- The form's search also matched only the name and type, not the ATT&CK id, and
  stopped at 8 results. Typing "ttp" listed 8 of a report's techniques.

**2. No relationship was ever offered for validation.**
- The worker stores every relationship already accepted, with
  `decision_origin = 'default'` (ADR-0058).
- The rail's "pending" tab counted only `accepted IS NULL`. It read 0 on all 7
  reports, while all 150 relationships shipped: finalize exports pending and
  accepted rows alike, and only rejected ones are left out.
- Relationships had no bulk action. Entities do, by type.

**3. Some edges have no review row at all** (not changed here):
- IoC → malware `indicates`, from Stage 3's `ioc_associations`;
- `targets` to the countries and sectors Stage 3 lists;
- embedded rule titles;
- Stage 4b completion edges;
- policy pins.

The Graph page's bundle view shows each of them with its ledger origin, but
Review cannot accept or reject them.

## Decision

1. **Stage 4 routes an observable ↔ attack-pattern row through the
   observable's Indicator when its verb is `indicates`.**
   - The result is `indicator indicates attack-pattern`.
   - A row written technique → observable is turned around. The ledger records
     it as a `direction` change, next to the `reroute`.
   - Every other verb is still dropped (ADR-0012).
2. **The relationship form**
   - offers only `indicates` for an observable and a technique, either way
     round, with a one-line explanation (`verbsForPair`; `suggestRelType` now
     reads the same rule);
   - searches the ATT&CK id too;
   - lists up to 50 results, scrolling.
3. **The rail**
   - "To review" is every row no analyst has decided: pending, or accepted by
     the pipeline's `default`. A `default` chip marks the latter, and ✓ on it
     confirms it. ✓ used to reset it, since it was "accepted".
   - "Accepted" is what a person accepted.
   - **By target** (on by default) groups the rows that share a target, matched
     case-insensitively as Stage 4 resolves endpoints.
   - A group of two or more rows has ✓ all / ✗ all, applied to the rows the
     current tab shows.
4. **`POST /api/jobs/{id}/relationships/bulk {ids, action}`**
   (`accept` | `reject` | `reset`).
   - It is one statement through `decisions.record`, with each row journaled
     as `human_bulk` (calibration does not read it).
   - Ids of another job are not touched.
   - At most 500 ids per call.

**Not changed.**
- What ships: rows are still stored accepted by default. Making them pending at
  storage would change nothing in the export (finalize ships pending rows), but
  would rewrite ADR-0058's choice and every stored job.
- The edges without a row (context, point 3). The next step would be to store
  `ioc_associations` and the targeted locations as relationship rows, so they
  can be reviewed. Finalize must then stop rebuilding them from the stored LLM
  result, or a rejected row comes back.

## Verification

Done on a copy of `ctiparsor_measure`, with the API and the page running.
- UNC6671 report:
  - "to review" reads 42 (it read "pending 0").
  - The groups are Helix 6, BlackFile 5, Falcon 5, Pink 5, and so on.
  - ✓ all on Helix → 6 rows `accepted, human_bulk`, and "to review" falls to 36.
- Industroyer2 report: the `link.ps1 indicates Group Policy Modification` row
  that was dropped now ships as `indicator indicates attack-pattern`.
- Tests:
  - `test_bundle_ledger.py`: routed, turned around, other verbs dropped;
  - `test_relationships_api.py`: bulk decides, journals, refuses and ignores
    other jobs;
  - `RelationshipRail.test.tsx` and `tokens.test.ts`: to review, groups, ✓ on a
    default row, verbs for the pair.

## Consequences

- An analyst's IoC → technique link reaches the bundle, in the one form STIX
  defines for it.
- The review page now says how many relationships nobody has looked at, and a
  group sharing a target is decided in one click. `default` stays the stored
  origin, so a group accepted in bulk reads `human_bulk`, never `human`.
- The rail's tab counts change meaning: "to review" is no longer always 0, and
  "accepted" no longer includes the pipeline's defaults.
