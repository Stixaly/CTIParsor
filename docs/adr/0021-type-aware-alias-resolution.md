# ADR-0021 — Type-aware alias resolution

**Status:** Proposed
**Date:** 2026-08-16
**Fixes:** [0012](0012-hallucination-measurement-and-canonicalization.md) — canonicalisation collapses aliases that denote *different* objects
**Affects:** [0013](0013-graph-completion.md) — ATT&CK reference grounding resolves report SDOs through the same index

## Context

ADR-0012 canonicalises named entities against the shipped gazetteer so that
"APT34" and "OilRig" become one STIX node instead of two. It fixed alias
*fragmentation*. It also introduced alias *conflation*, and the conflation is
silent.

`pipeline/aliases.py` builds its index with

```python
name2id[name] = mid       # last write wins
```

A surface form is assumed to identify exactly one MITRE object. Measured on the
shipped `pipeline/data/gazetteer.json` (1,827 entries, 1,814 distinct surface
forms), that assumption is false for **23 forms**, and for **18 of them the two
candidates carry different canonical names**:

| Surface form | Resolves to | Loses to | Consequence |
|---|---|---|---|
| `snake` | G0010 **Turla** (group) | S0022 Uroburos (malware) | the Snake rootkit is renamed "Turla" |
| `sofacy` | G0007 **APT28** (group) | S0137 CORESHELL (malware) | malware renamed to the group |
| `sednit` | G0007 **APT28** | S0044 JHUHUGIT | idem |
| `projectsauron` | G0041 **Strider** | S0125 Remsec | idem |
| `strongpity` | G0056 **PROMETHIUM** | S0491 StrongPity | idem |
| `cozyduke` | G0016 **APT29** | S0046 CozyDuke | idem |
| `uac-0056` | G1031 **Saint Bear** | G1003 Ember Bear | **two distinct groups merged** |

The rename is the visible half. The damaging half is in
`stage4_stix_mapping._register_named`:

```python
canon = canonical_name(name)              # type-blind
...
for form in alias_surface_forms(name):    # aliases of the WINNING id
    name_to_stix.setdefault(form, obj)
```

A report describing the **Snake malware** therefore registers `turla`,
`secret blizzard`, `krypton`, `group 88`, `iron hunter` and `belugasturgeon` in
`name_to_stix`, all pointing at the *malware* node. Every subsequent
relationship that names "Turla" attaches to the malware object instead of the
threat actor. The exported bundle carries wrong endpoints, and nothing in the
pipeline reports an anomaly.

The deterministic id is derived from `(canonical, stix_type)`, so the two SDOs
do not merge into one object. It is the display name and the alias table that
get crossed — which is why this has been invisible: node counts look right.

`stage4b_graph_completion._gazetteer_attack_ids()` builds the same
`name → mitre_id` map with the same last-write-wins collapse, and feeds
`_attack_id_for()`, which drives ATT&CK reference grounding. A malware node
resolving to a *group* id gets that group's curated edges attached to it.

## Options considered

**A. Prefer one prefix (G over S).** One line. Wrong for roughly half the
collisions — `spicyomelette` and `concipit1248` are software-vs-software — and
it encodes a guess as a rule. **Rejected.**

**B. Refuse to canonicalise any ambiguous form.** Safe and honest, but it gives
up canonicalisation for names an analyst genuinely needs folded. "Sofacy" is one
of the most common aliases in real reporting; passing it through unchanged
reintroduces the ADR-0012 fragmentation for exactly the busiest names.
**Rejected as the primary rule, kept as the fallback.**

**C. Resolve with the caller's STIX type, fall back to B.** The gazetteer
already carries `entity_type` on every entry (`malware` 1,123, `threat_actor`
597, `tool` 107), aligned one-to-one with the id prefix (G→threat_actor,
S→malware|tool). `_register_named` already knows the type it is about to create
— it passes `"threat-actor"`, `"malware"` or `"tool"` — and `_attack_id_for`
already computes `_otype(obj)`. The information needed to disambiguate is
present at both call sites and was simply never used. **Chosen.**

## Decision

Alias lookups take an optional STIX type and resolve in this order:

1. Build `name → {mitre_id, …}` keeping **every** candidate instead of
   overwriting. Ambiguity becomes representable rather than silently resolved.
2. **Exactly one candidate** → return it, whatever the requested type. This is
   the path for 1,791 of 1,814 forms, so established behaviour is untouched.
3. **Several candidates and a type was supplied** → keep those whose gazetteer
   `entity_type` maps to that STIX type. Exactly one survivor → return it.
4. **Otherwise** (no type given, or the type does not narrow to one) → return
   `None` / the name unchanged. Two distinct groups sharing an alias are never
   merged; they stay separate nodes.

The STIX-type → gazetteer-`entity_type` mapping:

| STIX type | gazetteer `entity_type` |
|---|---|
| `threat-actor`, `intrusion-set` | `threat_actor` |
| `malware` | `malware` |
| `tool` | `tool` |
| anything else | *(no candidates — falls to rule 4)* |

Rule 2 is what keeps this a bug fix rather than a behaviour change. Type
filtering is applied **only** to break a tie, never to reject an unambiguous
match — so a name the LLM classified as `malware` while the gazetteer calls it a
`tool` still canonicalises exactly as it does today.

`alias_surface_forms` follows the same resolution and, when it cannot resolve,
returns only the name itself — never another object's alias set.

## Consequences

- The 18 harmful collisions resolve correctly when the caller supplies a type,
  which both production call sites do.
- `uac-0056` (G1031 vs G1003) and the four other same-type collisions now
  resolve to nothing and pass through unchanged. That is the intended outcome:
  merging two distinct ATT&CK groups is an attribution error, and refusing is
  strictly better than guessing.
- The public signatures gain an optional parameter. Existing callers that omit
  it keep today's behaviour for unambiguous names and become *safe* (rather than
  wrong) for ambiguous ones — they get the name unchanged instead of another
  object's identity.
- **What becomes harder:** the index is now `dict[str, set[str]]`, so a caller
  that wants "the id for this name" with no type must accept `None` for 23
  forms. Code that assumed a total function must handle the miss. This is the
  cost of making ambiguity visible, and it is the point.
- The gazetteer's `entity_type` becomes load-bearing. If a future gazetteer
  build drops or renames that field, disambiguation degrades to rule 4 —
  passthrough — which is safe but silently loses the fix. `_load()` therefore
  keeps entries with a missing `entity_type` as untyped candidates rather than
  discarding them.
