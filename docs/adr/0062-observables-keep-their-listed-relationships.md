# ADR-0062: An observable keeps the relationships STIX 2.1 defines for it

**Status:** Accepted
**Date:** 2026-09-28
**Deciders:** maintainer
**Amends:** ADR-0041 (observables route through their Indicator)
**Relates to:** ADR-0061 (the mapping ledger, which surfaced this), ADR-0026 /
ADR-0027 (pin budget and evidence gate), ADR-0038 (the Policy page's rule
template)

## Context

ADR-0041 replaces an observable (SCO) endpoint with its Indicator whenever the
other endpoint is an SDO, and it does so *before* the verb is checked. Its
motivating case was `file related-to malware`: the observable as evidence of
the malware, which the Indicator states better.

But STIX 2.1 defines some relationships on the observable itself. From the
per-object tables (`pipeline/stix_rel_spec.py`, `_SUGGESTED`), every pair with
an SDO on one side and an SCO on the other:

| source | verb | target |
|---|---|---|
| `malware` | `communicates-with` | `domain-name`, `ipv4-addr`, `ipv6-addr`, `url` |
| `malware` | `downloads`, `drops` | `file` |
| `infrastructure` | `communicates-with` | `domain-name`, `ipv4-addr`, `ipv6-addr`, `url` |
| `infrastructure` | `consists-of` | any SCO |
| `indicator` | `based-on` | any SCO (project extension, ADR-0061) |

No table lists a pair with the SCO as the *source* and an SDO as the target.

Routed through the Indicator, each of these claims becomes `malware
communicates-with indicator`, a pair no table lists, so `rel_is_allowed`
downgrades it to `related-to`. The bundle loses a precise, spec-valid claim
and gains nothing: the Indicator and its `based-on` edge exist anyway. ADR-0041
rejected routing observable↔observable pairs for exactly this reason ("forcing
those through Indicator-to-Indicator produces a pair STIX doesn't even list as
suggested"). It never checked the same argument against the SDO↔SCO pairs STIX
*does* list.

The ledger (ADR-0061) made the loss visible. On the seeded Industroyer2 report,
the row `Industroyer2 communicates-with update-check.example.net` carries two
changes: a `reroute` to the domain's Indicator, then `communicates-with` →
`related-to` (`not_suggested`). ADR-0061 named this as an open question.

The pin engine applies the same routing, and the Policy page's own template
(ADR-0038) pins five SDO→SCO rules that STIX lists: `malware communicates-with
domain-name`, `malware communicates-with ipv4-addr`, `malware drops file`,
`infrastructure consists-of ipv4-addr` and `infrastructure consists-of url`.
Every edge these rules materialised shipped as `<x> related-to indicator`,
under an `x_policy_rule` label naming the verb it did not carry.

A second, quieter effect: the semantic loop looked the policy up on the
*rerouted* pair (`malware>indicator`). A pinned `malware>domain-name` rule
never applied to an extracted malware→domain row, even though the policy's
contract is that a pinned rule sets the verb for its pair of types.

### Measured

**Method.** The jobs behind the stored bundles could not be used: the main
PostgreSQL was not readable from the measuring session, and the stored
bundles, built with no policy, keep only the downgraded verb. So the seven
distinct reports behind `output/*_bundle.json` (text taken from each Report's
`description`) were run again through the whole pipeline into a throwaway
database: Stage 2 with its NER models, Stage 3 on Qwen3.8-27B served by vLLM.
Then `re_run_final_stages(job, skip_rescan=True)` rebuilt each job with a
`MappingLedger`, at the parent commit and with this change. It ran once with
no policy (the factory default a fresh install runs) and once with the Policy
page's template (21 pinned rules). A row is *lost* when its ledger entry holds
a `reroute` followed by a `not_suggested` downgrade. Stage 3 ran afresh, so
these are the real reports but not the original rows.

| report | rows | lost at HEAD, no policy | of which listed for the direct pair |
|---|---|---|---|
| Industroyer2 — IEC-104 analysis | 22 | 8 | 3 (`Industroyer2 communicates-with <IP>` ×3) |
| Industroyer2 — Industroyer reloaded | 23 | 0 | 0 |
| AI tool use, Latin America | 22 | 4 | 0 |
| Breeze Comet | 26 | 0 | 0 |
| INDUSTROYER.V2 (Mandiant) | 8 | 1 | 0 |
| ADFS signing keys | 7 | 0 | 0 |
| UNC6671 | 42 | 2 | 0 |
| **total** | **150** | **15** | **3** |

The 12 other lost rows name a verb no table lists for the pair:
`malware targets ipv4-addr` ×3, `threat-actor uses domain-name` ×3, `file
variant-of malware` ×2, `ipv4-addr hosts malware|tool` ×2, `threat-actor
communicates-with ipv4-addr`, and `malware indicates file`. For those,
`related-to` an Indicator is the best edge available, and this ADR leaves them
alone. No row used a verb listed only in the other direction.

| all 7 reports | HEAD, no policy | this ADR, no policy | HEAD, template | this ADR, template |
|---|---|---|---|---|
| rows rerouted | 31 | 28 | 31 | 24 |
| rows rerouted then downgraded | 15 | 12 | 12 | 5 |
| pinned edges from a listed SDO→SCO rule shipped as `related-to` an Indicator | — | — | **304 of 1,245** | **0** |
| SDO↔observable edges in the bundles (`based-on` excluded) | 0 | 3 | 0 | 308 |
| relationships in the bundles | 1,497 | 1,500 | 3,276 | 3,276 |

The pin engine carries most of the loss. Under the template, one pinned edge
in four shipped with a verb other than the one its rule names: `malware drops
file` ×160, `malware communicates-with ipv4-addr` ×73, `malware
communicates-with domain-name` ×71. On the three rules' own pairs the pinned
edge count is unchanged; only the target and the verb move.

The +3 relationships with no policy are claims the routing used to merge. The
three `Industroyer2 communicates-with <IP>` rows and the three `Industroyer2
targets <IP>` rows all became `malware related-to indicator(<IP>)`, so each
pair of rows merged into one edge (19 rerouted rows merged at HEAD, 16 now).

On the seeded report where the ledger surfaced the issue
(`industroyer2-preview`), 1 row → 0. Under the template, 21 of 67 pinned
edges → 0.

## Decision

**Route through the Indicator only when the direct pair does not list the
verb.** `_route_observables_through_indicators(source, verb, target,
sco_id_to_indicator)` now takes the verb. It returns the pair unchanged when
`stix_rel_spec.rel_is_listed(source.type, verb, target.type)`; otherwise it
behaves exactly as ADR-0041 (Indicator, or drop when there is none).
Both-observable and no-observable pairs are still left alone.

Five precise choices:

1. **"Listed", not "suggested".** `rel_is_suggested` (and `rel_is_allowed`)
   return True for `related-to`, since §3.7 makes it valid between any two
   objects. Read literally, "route only when the pair is not suggested" would
   keep every `related-to` edge on the raw observable, and so undo ADR-0041
   for its own motivating case. `rel_is_listed` is True only when the
   per-object tables (or the project's `indicator based-on <SCO>` extension)
   name the verb for this exact pair. It excludes the §3.7 common
   relationships, and it gives unknown types no benefit of the doubt.
2. **The verb judged is the one the direct edge would carry.** In the semantic
   loop, the order becomes: normalise the verb (unknown → `related-to`), apply
   the policy pin for the *direct* pair, decide the routing on that verb, then
   apply the policy of the pair the edge lands on, and finally the
   `rel_is_allowed` downgrade. A pinned `malware>domain-name` rule therefore
   reaches extracted rows again, as its contract says. A routed edge still
   takes the policy of its new pair: the template's `indicator indicates
   malware` still turns `evil.com hosts X` into `indicator indicates X`.
   Measured under the template, this reaches 4 of 150 rows. Three are
   `Industroyer2 targets <IP>` → `communicates-with`, which merge into the
   extracted `communicates-with` edges. The fourth,
   `INDUSTROYER.V2 indicates <md5>` (the model's reversed "this hash is the
   sample"), becomes `malware drops file`, a specific claim where `related-to`
   was vague but true. That is the pin's own blunt contract, the same one it
   applies to every SDO↔SDO pair, and the pin engine asserts `malware drops
   file` wholesale from the same rule (160 edges on these reports).
   Judging the row's verb alone (Option E) would keep that row vague but
   leave 9 rows downgraded instead of 5.
3. **Direction is judged as extracted.** `domain-name communicates-with
   malware` is not listed (only `malware → domain-name` is), so it is still
   routed and downgraded. Flipping it would be a different claim for `drops`
   and `downloads` (a file does not drop its malware). None of the 150 rows
   measured above was such a row; asking Stage 3 for the spec's direction is
   a separate change if one ever matters.
4. **The pin engine uses the same helper, with the rule's verb.** A rule whose
   triple is listed is pinned on the observable itself. It no longer needs the
   Indicator to exist (a listed rule's candidates do not depend on a STIX
   pattern being buildable). The evidence gate (ADR-0027) anchors on the SCO's
   value instead of the Indicator's pattern literals, which are the same
   strings. A row and a pin for the same pair now produce the same key, so the
   pin deduplicates against the row, as ADR-0026 intended.
5. **The verb is a required argument.** No caller can fall back to ADR-0041's
   unconditional routing by leaving it out.

The ledger needs nothing new: an edge kept on its observable has no `reroute`
change. The Graph page's sentence for a reroute ("an observable never stands
opposite an SDO") stopped being true and now says why the row was routed.

## Options considered

| Option | Verdict |
|---|---|
| **A — keep ADR-0041 as is; the ledger shows the loss** | Rejected: the bundle ships a vaguer claim than the one extracted, for no benefit. The Indicator chain is complete without it |
| **B — the literal rule: route unless `rel_is_suggested` / `rel_is_allowed`** | Rejected: `related-to` is always "suggested", so every `related-to` row, ADR-0041's motivating case included, would go back to the raw observable |
| **C — route, then pick a verb the Indicator pair allows** (`communicates-with` → `indicates`) | Rejected: `indicator indicates malware` ("the domain signals the malware") is a different claim from `malware communicates-with domain-name` ("the malware talks to it"). A rewrite that changes the meaning is worse than `related-to` |
| **D — emit both the direct edge and the routed one** | Rejected: it doubles the edge and adds a derived claim nobody made |
| **E — decide on the row's verb only, ignore the policy** | Rejected: pinned SDO>SCO rules would stay unreachable for extracted rows, and a row and a pin on the same pair could ship as two different edges. Measured under the template: 9 rows downgraded instead of 5, 3,279 relationships instead of 3,276 (the extra three are `related-to` edges beside the pinned `communicates-with` on the same pairs). It keeps `INDUSTROYER.V2 indicates <md5>` vague rather than turning it into `drops` (choice 2) |
| **F — listed-verb exemption, judged on the verb after the direct pair's pin, at both call sites** (chosen) | Keeps the spec's own claims, restores the policy contract, and changes nothing for `related-to` and every other unlisted verb |

## Consequences

**Easier:**
- The claims STIX defines on an observable ship as extracted. A pin rule
  labelled `malware communicates-with domain-name` emits exactly that edge.
- Extracted rows and pinned edges on the same pair agree and deduplicate.
- The ADR-0060 relationship score on the shipped bundle
  (`evaluation/__main__.py::_bundle_relations`) resolves an endpoint by
  name. A routed edge's target was "Indicator: evil.com", so a gold triple
  `malware communicates-with evil.com` could never match, even undirected and
  untyped. Now it can.

**Harder / revisit:**
- Bundles again contain SDO→SCO relationships. ADR-0041's invariant ("no
  Relationship has an observable endpoint opposite an SDO") no longer holds,
  and the README said it did. It now holds for every verb STIX does not
  define on the observable. Every IoC still has its Indicator and `based-on`
  edge; only the claim edge moves.
- Rows in the reverse direction still lose their verb (choice 3). None
  occurred in the 150 rows measured.
- 12 of 150 rows (no policy) still ship as `related-to` an Indicator, because
  their verb is listed for no form of the pair. Most are type confusions
  upstream: an IP that `malware targets` is infrastructure, a domain a
  `threat-actor uses` is infrastructure. Stage 3's typing is the place to fix
  them, not the routing.
- Stage 4b: no transitive rule composes through `communicates-with`, `drops`,
  `downloads` or `consists-of` (`_TRANSITIVE_RULES`), and the alias merge
  excludes SCOs, so the direct edges infer nothing new.
- Stored bundles are unchanged until rebuilt (ADR-0035). `re_run_final_stages`
  rebuilds one at no LLM cost.

## Validation

- Unit tests: `tests/test_stix_rel_spec.py` (new: listed vs allowed for the
  common verbs, unknown types, direction); `tests/test_pin_budget.py` (the
  helper keeps listed pairs, including the `*SCO*` wildcard and the extension,
  and routes reversed, wrong-type and `related-to` pairs);
  `tests/test_pin_evidence.py` (a listed pin rule is emitted on the observable
  with or without an Indicator); `tests/test_stage4.py` (six listed pairs ship
  as extracted; `related-to` and the reversed direction still route; a pin on
  the direct pair decides); `tests/test_bundle_ledger.py` (a listed row has no
  change; an unlisted one is rerouted then downgraded; a routed row takes the
  policy of the pair it lands on). Against the parent commit, the 17
  new-behaviour tests fail and the ones that lock unchanged behaviour pass.
- Full suite: 1561 passed, 5 skipped. ruff and mypy clean on the changed
  modules. Frontend `tsc` and the graph tests (27) pass.
- In the browser, on a copy of the seeded preview database: the Differences
  panel showed the row rewritten (reroute, then `communicates-with` →
  `related-to`). After a rebuild with this change, the row ships as a direct
  "From the report" edge and the Rewritten section is empty.
- The real-report measurement above.
