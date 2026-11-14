# ADR-0101: The targets product needs one actor

**Status:** Accepted
**Date:** 2026-11-14
**Deciders:** maintainer
**Amends:** ADR-0061 (the origin `targeted_location` is built only for a report
with one threat actor), ADR-0013 (amendment of 2026-10-26: the ledger's
`refused` list gains the reason `ambiguous_actor`), ADR-0093 (the "Why" text of
that edge)
**Relates to:** [the measurement](../eval/relation-false-positives-2026-11.md)

## Context

Stage 4 built a `targets` relationship for every threat actor of the report
(`threat_actors`) times every entry of `targeted_countries` and
`targeted_sectors`. The LLM's lists say what the report targets, not which actor
targets it. With several actors in the report, the product is an attribution by
co-mention.

The measurement of 2026-11 looked at the bundle of commit fe0b0f3 on the 8
reports of the in-house set
([the page](../eval/relation-false-positives-2026-11.md)). This method produced
1,354 relationships. None matched the gold: 66.3 % of the 2,041 relationships
that matched nothing.

That figure has a reserve. The gold holds one `targets` relationship only, so
the figure measures a gap with the gold, not only false relationships. Reading
30 samples of the same measurement shows attributions to the wrong actor, for
example a target of APT44 attributed to a persona.

## Decision

**The product is built only if the report names one threat actor.**

- The count is by object, after the alias merge of Stage 4b. Two spellings of
  one actor are one actor.
- With two actors or more, no edge of the product is built. Each pair that no
  edge of the bundle already covers goes to the mapping ledger, in `refused`,
  with origin `targeted_location`, reason `ambiguous_actor`, and the keys
  `actor` and `target`.
- A `targets` row that the report states still ships, with its quote, whatever
  the number of actors.
- A review decision (rejection, hold) keeps its own reason in `refused`.
- The "Why" text of the edge (ADR-0093) now says that the actor is the only one
  the report names.

## Alternatives rejected

- **(a) Remove the product in every case.** With one actor the attribution is
  not ambiguous.
- **(b) Keep the product and mark it `inferred`.** The relationship would stay
  in the imported bundle.
- **(c) A setting for the old behaviour.** No use case was measured for it.

## Consequences

- In a report with several actors, the targeted countries and sectors stay in the
  bundle as objects (and in the Report) but are no longer linked to an actor,
  unless the report states the relationship. The analyst can add the
  relationship in the review.
- When the product is built after the alias merge, Stage 4b does not see these
  edges and composes nothing from them.
- The one-actor case stays an inference. Its label `reported` is unchanged. This
  is a known limit, not treated here.
- No setting brings the old behaviour back.
- The bundle output changes: a `BUNDLE_AFFECTING` entry scoped "mapping" goes
  with the commit. No migration and no API change.

## Not measured

The effect on the precision and the recall of the bundle. No run was made with
this change. The measurement to redo is `inhouse-bundle`.

## Tests

`tests/test_targets_product_single_actor.py`. The references
`tests/fixtures/stage4_reference/expected/apt_report.json` and
`policy_pin.json` are regenerated.
