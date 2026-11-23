# ADR-0105: A name two ATT&CK entities share is resolved by its context

**Status:** Accepted (2026-11-23)
**Date:** 2026-11-23
**Deciders:** maintainer
**Relates to:** ADR-0021 (represent ambiguity rather than settle it silently), ADR-0104
(census of silent empty returns, where #914 was left open), the ordinary-word policy of
the gazetteer ([gazetteer-ordinary-words.md](../gazetteer-ordinary-words.md))

## Context

Issue #914. Stage 2b (the gazetteer) claims a span for the first entry that matches it.
Six names of `pipeline/data/gazetteer.json` are carried by two entities of the same type:

| Name | Type | Entities, in index order |
|---|---|---|
| `thrip` | threat_actor | Lotus Blossom (G0030), Thrip (G0076) |
| `uac-0056` | threat_actor | Ember Bear (G1003), Saint Bear (G1031) |
| `corona updates` | malware | Corona Updates (S0425), Concipit1248 (S0426) |
| `concipit1248` | malware | Corona Updates (S0425), Concipit1248 (S0426) |
| `dnsmessenger` | malware | POWERSOURCE (S0145), TEXTMATE (S0146) |
| `spicyomelette` | malware | SpicyOmelette (S0646), More_eggs (S0284) |

For such a name the first entity reserved the span and the second was lost, even when the
report named it with its own identifier ("Thrip (G0076)" produced Lotus Blossom). The
loss was silent: nothing in the stage report or the log said that a second entity existed.

The triage comment on the issue noted that the claim is the intended tie-break of
`_Claims`, and that ADR-0021 asks for ambiguity to be represented rather than settled
silently. Removing the claim would emit two identities for one mention. The maintainer
chose among three options (emit all, emit one, decide by context) the third.

## Decision

**A mention of a shared name goes to the entity its context names.** For a document, the
gazetteer builds the groups of shared names once (`_shared_groups`: entries with one name
and one `entity_type` and at least two distinct canonicals). On both matching paths (Aho-Corasick and
regex), an entry of a shared name is kept for a mention only when `_context_winner` picks its entity
for that mention; the other entities of the group are not matched on that span. A text with no shared
name is not changed.

`_context_winner` applies five rules in order. Each keeps the rivals it points to, and the
first rule that keeps exactly one distinct entity decides:

0. the rival's canonical name ends just before the mention (at most 40 characters), with
   nothing but an alias link between them: "(", "aka", "a.k.a.", "also known as", "known as",
   "also called", "alias" ("Lotus Blossom, also known as Thrip", "More_eggs (aka
   SpicyOmelette)"). Without it, rule 2 would give "Thrip" to G0076, an actor the sentence
   does not name; "Lotus Blossom and Thrip" or "Corona Updates (S0425) vs Concipit1248" is
   no link;
1. the rival's `mitre_id` is written right after the mention: at most 12 characters later,
   with no letter or digit between them ("Thrip (G0076)", "Thrip: G0076", "\"UAC-0056\" (G1031)");
2. the mention, lowercased, is the rival's canonical name;
3. the rival's `mitre_id` is written elsewhere in the text, as a whole word;
4. the rival's canonical name is written elsewhere in the text, as a whole word.

If no rule keeps exactly one rival, the first rival in index order is kept, and one
`INFO` line per shared name and document says which entity was kept and which were
possible ("shared alias 'uac-0056' left ambiguous: Ember Bear (G1003) kept, Saint Bear
(G1031) possible"). A rule that keeps two rivals does not decide; the next rule is tried.

**An identifier before the mention does not count (rule 1).** In "Concipit1248 (S0426):
we analyzed Corona Updates", S0426 belongs to the name it follows. Read as context for
the next mention, it would hand "Corona Updates" to Concipit1248. Only an identifier written
after the mention is read by rule 1; the second "Corona Updates" in that sentence stays
with S0425 (through rule 2).

**Interaction with the ordinary-word policy.** The choice by context is made before the
policy judges the mention, and does not bypass it. In `apply` mode, a mention with no
identity of its own stays withheld: "UAC-0056 was active." gives no entity, and the trace
holds the form `uac-0056` with the reason `ambiguous_identity`. With the policy off, the
same text gives Ember Bear (G1003), the first rival, and the log line above (both are
tested).

## Alternatives rejected

- **Emit every entity of a shared name.** It would publish two identities for one
  mention, and an analyst or a downstream platform would take both as stated by the report.
- **Emit one, without context** (the behaviour before this ADR). The first entity in
  index order won every time, and an entity the report named with its own identifier
  was lost without a trace.

## Consequences

- Both entities of a shared name can now appear in one document when the report
  distinguishes them: "Thrip (G0076) and Lotus Blossom (G0030) and Thrip." gives Thrip
  (G0076) and Lotus Blossom (G0030); the Corona Updates / Concipit1248 sentence gives
  S0425 and S0426. Both paths give the same result on the tested texts.
- A mention that no rule decides still goes to the first entity in index order,
  but it is now logged. The log is the only trace: the stage report does not carry it.
- The rules read the text of the document only. A shared name whose context names neither
  entity (rule 4 included) is attributed by index order, which carries no information
  about the report.
- `_shared_groups` is cached like the index and is never cached on an unreadable
  gazetteer (ADR-0104).
