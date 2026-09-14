# ADR-0041: Observables route through their Indicator, never straight to a threat SDO

**Status:** Accepted
**Date:** 2026-09-14
**Deciders:** maintainer
**Relates to:** extends ADR-0009 (STIX trust & provenance) and the observable→ObservedData→Indicator
chain it already established; sits next to ADR-0012 (relationship precision), ADR-0024
(edge-synthesis provenance), ADR-0026 (pin budget), ADR-0027 (evidence-gated pin materialisation)

## Context

Stage 4 already builds the STIX 2.1 best-practice chain for every accepted IoC —
`SCO ◄─object_refs─ ObservedData ◄─based-on─ Indicator` — and audits it with
`verify_ioc_coverage`. What it does **not** do is stop a raw observable (SCO)
from becoming the direct endpoint of a `Relationship` to a threat SDO (malware,
threat-actor, intrusion-set, campaign, tool, infrastructure, …). Two independent
code paths can still do that:

1. **LLM-derived relationships** (`llm_result.relationships`, the "semantic
   relationships" loop). Only the observable↔attack-pattern pair is guarded
   (`_is_spurious_observable_ttp_edge`, ADR-0012); a claim like "this domain
   hosts this malware" wires the raw `domain-name` SCO straight to the
   `malware` SDO.
2. **The Relationship Policy's pin engine** (`_materialise_pinned_edges`).
   This is the *larger* source, not the smaller one: ADR-0024 measured 872 of
   1,140 shipped edges on one report coming from here, and ADR-0027's own
   results table shows the policy already contains rules whose `tgt` is a raw
   SCO type — `malware communicates-with domain-name`, `malware drops file`,
   `indicator related-to domain-name` all appear side by side in the same
   default policy today.

### Measured on the stored bundles (`output/*_bundle.json`, 2026-09-14)

| bundle | relationships touching a raw SCO | breakdown |
|---|---|---|
| Industroyer2 IEC-104 Analysis | 12 / 29 | 5× `file related-to ipv4-addr`, 4× `file related-to file`, 3× `ipv4-addr related-to ipv4-addr` |
| Industroyer2 / Industroyer reloaded | 2 / 45 | 2× `file related-to malware` |
| 4 other stored bundles | 0 / 0–6 | — |

Two things this measurement changes about the plan:

- **The observable↔threat-SDO case is real but not the majority one** (`file
  related-to malware`, 2 edges) — the majority of raw-SCO edges seen today are
  **observable↔observable** (`file↔file`, `file↔ipv4-addr`, `ipv4-addr↔ipv4-addr`).
- STIX 2.1 has no single correct answer for observable-to-observable facts —
  the spec's own mechanism for them is embedded ref properties
  (`resolves_to_refs`, `src_ref`/`dst_ref`, `parent_directory_ref`, …), which
  differ per SCO-type pair and don't exist for most of the pairs seen above
  (a hash "related-to" an IP has no defined embedded ref at all). Solving that
  properly is a separate, larger piece of modelling work.

### A second, adjacent gap

`EntityType.NETWORK_TRAFFIC` maps to a `stix2.Software` SCO (a placeholder,
flagged as such in the code comment — full `network-traffic` objects need
`protocols` and `src_ref`/`dst_ref`, which nothing upstream extracts today),
and `_build_stix_pattern` has no branch for `"software"`. Its Indicator is
therefore silently never built — `verify_ioc_coverage` would report every
`NETWORK_TRAFFIC` IoC as `missing_indicator`. Under the stricter rule this ADR
adopts (route through the Indicator, or drop), that silent gap would turn into
silently dropping every network-traffic relationship, which is a regression
worth closing in the same change since it's directly downstream of it.

## Decision

**Scope, precisely:** when a `Relationship`'s two endpoints are one observable
(SCO) and one non-observable SDO, the observable is replaced by its own
Indicator before the edge is built. When both endpoints are observables, or
neither is, nothing changes — that combination is out of scope (see above).
When the observable side has no Indicator (no STIX pattern could be built for
it), the edge is dropped rather than falling back to the raw SCO.

Implementation, one helper shared by both call sites:

```python
def _route_observables_through_indicators(source, target, sco_id_to_indicator):
    """Redirect exactly one endpoint — the one that is an observable — to its
    Indicator, when the other endpoint is a real SDO. Leaves the pair alone
    when both or neither endpoint is an observable (see ADR-0041 scope).
    Returns (None, None)-shaped drop when the observable side has no
    Indicator to route through."""
```

Applied in two places:

1. **Semantic relationships loop** — after the existing
   `_is_spurious_observable_ttp_edge` check (kept exactly as-is: a technique
   is still only ever attributed via `malware/actor --uses--> attack-pattern`,
   never through an observable's Indicator either), before verb resolution.
2. **`_materialise_pinned_edges`** — inside the Pass-1 candidate loop, per
   pair, before `_pin_edge_key` and the evidence gate. `sco_id_to_indicator`
   becomes a new keyword parameter, built once in `build_stix_bundle` from the
   already-populated `name_to_stix` (no new O(n²) work — it's one pass over an
   existing dict).

`_build_stix_pattern` gains a `"software"` branch (`[software:name = '<value>']`)
so `NETWORK_TRAFFIC` observables get a real Indicator and stop being silently
dropped by the new rule.

### Backward compatibility with the pin-engine's own unit tests

`_materialise_pinned_edges` is unit-tested directly (`test_pin_evidence.py`,
`test_pin_budget.py`) against bare fake objects (`_Obj("domain-name", ...)`,
`_Obj("malware", ...)`) that deliberately have no Indicator behind them — those
tests exercise budget allocation and evidence-gating in isolation, not the
Indicator chain. Making the redirect unconditional would silently drop every
candidate in five existing tests and force them to grow indicator fixtures
that test something they don't intend to test.

`sco_id_to_indicator` is therefore `None` by default: `None` means "the
redirect step is not engaged" (today's behaviour, exactly), a provided dict
means "engaged, and an observable with no entry in it has no Indicator."
`build_stix_bundle` — the only production caller — always passes the real,
populated dict. This is the same idiom the file already uses for
`report_text=""` disabling the evidence-gate: an absent optional context turns
a feature off rather than turning it into an always-empty error state.

## Options considered

| Option | Verdict |
|---|---|
| **A — redirect any observable endpoint unconditionally** (both LLM relationships and pins, regardless of the other endpoint's type) | Rejected by measurement: `domain-name resolves-to ipv4-addr` (`test_pin_budget.py`) and the `file↔ipv4-addr` / `file↔file` edges actually seen in stored bundles are observable-to-observable; forcing those through Indicator-to-Indicator produces a pair STIX doesn't even list as suggested, and reads as a materially stranger claim than the direct one for no proven benefit |
| **B — redirect only the LLM relationships loop, leave the pin engine alone** | Rejected: ADR-0024 measured the pin engine as the *majority* source of edges (872/1,140 on one report); fixing only the smaller path leaves the problem mostly in place |
| **C — scope to observable↔non-observable pairs only, both call sites, opt-in via an explicit parameter** (chosen) | Fixes the case actually described (an observable linking to malware/threat-actor/etc.), leaves the genuinely different observable-to-observable question for separate, dedicated work, and costs the pin-engine's own unit tests nothing |
| **D — also drop observable↔attack-pattern edges in the pin engine, matching the semantic-relationships loop's guard** | Rejected for now: that guard exists specifically to protect against the *LLM* hallucinating a technique attribution from an observable; a pin rule is an analyst's deliberate, reviewed configuration, not a guess to defend against. Left as a known, separate inconsistency — see Consequences |

## Consequences

**Easier:** an observable that participates in a threat-attribution edge (`X
communicates-with malware`, `X drops`, `X indicates`, …) is now always backed
by a real Indicator with a `pattern`, from either extraction path — which is
also what `verify_ioc_coverage` was already asserting must be true for every
accepted IoC, just not yet enforced at the relationship-building step.

**Harder / revisit:**
- Observable-to-observable relationships (`file related-to ipv4-addr`, 12/29
  of the edges measured above) are explicitly out of scope. The correct STIX
  2.1 answer is per-SCO-type embedded ref properties, not a Relationship SRO
  at all — a separate, larger redesign, not attempted here.
- The pin engine's attack-pattern/course-of-action guard remains inconsistent
  with the semantic-relationships loop's (Option D, rejected for now). An
  analyst who pins `domain-name → attack-pattern` will get
  `Indicator --related-to--> AttackPattern` edges after this change (spec-legal,
  new behaviour where today it silently pins the raw SCO — this ADR does not
  claim that specific combination is wrong, only that it wasn't evaluated).
- `NETWORK_TRAFFIC` stays a `Software` placeholder SCO; only its missing
  Indicator is fixed. Modelling it as a real `network-traffic` object needs
  structured src/dst extraction that does not exist upstream today.

## Validation

Targeted (`test_stage4.py`, `test_pin_evidence.py`, `test_pin_budget.py`) then
full suite, both green. 11 new tests added, one existing test
(`test_ioc_coverage_flags_missing_indicator`) rewritten — it had locked in the
NETWORK_TRAFFIC gap by name and now asserts the fix.

### Real data: `re_run_final_stages` on the Industroyer2 job (zero LLM cost)

Rebuilding Stage 4+5 for `a0d1eb8c` (Industroyer2 / Industroyer reloaded)
from its already-accepted entities, bypassing nothing else:

| | relationships | observable↔observable | observable↔SDO |
|---|---|---|---|
| before (stored bundle) | 45 | 0 | **2** (`file related-to malware` ×2) |
| after (this ADR) | 310¹ | 0 (unchanged, confirms scope held) | **0** |

¹ The jump to 310 is Stage 4b graph completion (`+17 reference, +85
transitive`), unrelated to this change — re-running it is a side effect of
`re_run_final_stages`, not of ADR-0041.

The two dropped `file --related-to--> malware` edges did not just vanish:
querying the after-bundle for `indicator --indicates--> malware` edges whose
indicator pattern is a `file:name` or `file:hashes.*` literal finds **40**
such edges (`[file:hashes.'SHA-1' = '6fa04992...'] --indicates--> CaddyWiper`,
etc.) — the fix is rerouting real attribution claims through real Indicators
at scale, not merely deleting the two edges the "before" measurement happened
to catch.

(Validating this required bypassing `validate_and_export`'s file write:
`output/Industroyer2_*_bundle.json` and one other stored bundle are
root-owned from the same 2026-09-09 event documented in memory
`dev-environment.md` — monkeypatched around for this one-off check rather
than touching permissions.)
