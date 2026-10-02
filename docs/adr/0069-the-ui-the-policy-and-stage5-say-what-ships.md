# ADR-0069: The UI, the policy and Stage 5 say what ships

**Status:** Accepted
**Date:** 2026-10-02
**Deciders:** maintainer
**Relates to:** the STIX relationship review of 2026-10-02
(`docs/stix-relationships-review.md`), points 1, 2, 5, 7 and 9; ADR-0041 /
ADR-0062 (observables routed through their Indicator), ADR-0061 (ledger),
ADR-0066 (OpenCTI is the interop target)

## Context

The review found five places where what the project shows or accepts differs
from what Stage 4 ships:

1. **The UI offered verbs that do not ship.** `relConstraints.ts` added
   `duplicate-of` and `derived-from` to every pair. STIX §3.7 and
   `stix_rel_spec.py` keep them for two objects of the same type, so
   `malware duplicate-of tool` shipped as `related-to`. A pair absent from the
   table offered all 35 verbs, and Stage 4 kept only `related-to`. The Policy
   page's warning said a non-spec verb "will still be emitted". It is not:
   Stage 4 ships it as `related-to`.
2. **The policy API stored any object as a rule.** A pinned rule whose verb
   does not ship emitted `related-to` edges labelled with a verb they did not
   carry. Two rules for the same pair: the later one silently replaced the
   earlier one, even when the later one was disabled (`_pol_index`).
3. **Stage 5 answered `True` without schemas**, the same answer as for a
   bundle the schemas accepted. It dropped the validator's best-practice
   warnings, and it restored its schemas from the moving `master` branch.
4. **`NETWORK_TRAFFIC` shipped as `Software(name=...)`.** That kept the
   words and lost the type, the destination and the port.
5. **A comment called the observable → technique edge "not a valid STIX
   relationship".** STIX permits it as a custom relationship. Dropping it is
   this project's precision choice (ADR-0012).

## Decision

1. **One rule for "ships as written", held to one matrix.**
   `verb_ships_as_written(src, verb, tgt)` (`stage4_stix_mapping.py`)
   restates the semantic loop's decisions by type: the observable/technique
   guard, the routing through the observable's Indicator, then the
   `rel_is_allowed` downgrade. `shippedVerbs(src, tgt)` (`relConstraints.ts`)
   is the same rule for the review selects and the Policy page.
   `frontend/src/stix/shippedVerbs.fixture.json` holds the verbs that ship
   for each of the 33×33 pairs of types. It is generated from the Python rule
   (`python -m tests.test_rel_constraints_parity --write`). pytest fails when
   the fixture disagrees with Stage 4, and vitest fails when `shippedVerbs`
   disagrees with the fixture. Along the way:
   - `commonVerbs(src, tgt)` returns `related-to`, plus `duplicate-of` and
     `derived-from` for a same-type pair.
   - The two frontend pairs listed for `related-to` alone are removed.
     `file>malware` hid `indicates`, which ships through the IoC's Indicator.
   - The Policy warning now says that the verb ships as `related-to`.
   - The frontend table must equal `_SUGGESTED` exactly, and its observable
     and SCO lists must equal Stage 4's.
2. **The policy API validates each rule as Stage 4 will apply it.**
   - `src` and `tgt` are STIX 2.1 SDO or SCO types.
   - `verb` is in the vocabulary.
   - `mode` is `pin` or `auto`, and `enabled` is a boolean.
   - There is one rule per pair.
   - An enabled pinned rule must ship as written.

   The Policy page shows a refused save with the server's message. Before,
   the save failed silently and the page kept the edit.
3. **Stage 5 returns a `ValidationResult`**: `validated`, `unverified` (no
   schemas, only the stix2 library checked) or `invalid`, with the
   validator's errors and warnings. The orchestrator records the status and
   the warning count. The schema archive is pinned to commit `9af1db4` of
   `oasis-open/cti-stix2-json-schemas` (master on 2026-01-19). It is not
   pinned by checksum: GitHub does not guarantee byte-stable archives.
4. **A network-traffic observable is a `network-traffic` to its
   destination** (`pipeline/network_traffic.py`). An IP, or a domain with a
   protocol word, becomes `dst_ref`, with `dst_port` and `protocols` taken
   from the text. An IP gives `ipv4`/`ipv6` by construction, and nothing else
   is guessed. Its pattern is
   `[network-traffic:dst_ref.value = '…' AND network-traffic:dst_port = …]`.
   A value with no destination (`tcp/445`) is left out with ledger reason
   `no_traffic_endpoint`: STIX requires `src_ref` or `dst_ref`. Only analysts
   create this type; Stage 2 does not extract it.
5. **The wording says what the filter is**: a precision choice, in the code
   and in the Graph page's reason text.

## Not done, on purpose

- **`av-analysis-of` (review point 4).** The errata that introduces it is a
  Committee Specification Draft. OpenCTI and the installed stix2-validator
  both use `analysis-of`, and the project builds no `malware-analysis` object.
- **Verbs outside the vocabulary (point 3).** OpenCTI refuses a relationship
  type outside its schema (`checkRelationConsistency`). Shipping such a verb
  would break the import.
- **`duplicate-of` in OpenCTI.** It appears in no entry of OpenCTI's
  `stixCoreRelationshipsMapping`, so OpenCTI would refuse it on every pair.
  It is still offered for same-type pairs until an import confirms that.
- **A catalogue served by the API (point 4).** The fixture keeps the two
  copies equal. Serving the table is a larger change.
