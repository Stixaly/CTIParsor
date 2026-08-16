# ADR-0019 — Multi-format corpus management in the settings UI

**Status:** Proposed
**Date:** 2026-08-16
**Extends:** [0007](0007-in-app-configuration-panel.md) (settings panel), [0006](0006-multi-corpus-detection-ingestion.md) (registry + adapter seam)
**Blocked-for-yield-by:** [0015](0015-multi-format-detection-matching.md) — the Suricata/YARA *adapters*

## Context

The settings panel manages detection corpora, and it is Sigma-only in three
places at once:

| Layer | Constraint |
|---|---|
| `api/routes/settings.py:55` | `if body.adapter != "sigma": raise HTTPException(400, …)` |
| `frontend/.../Settings.tsx:46` | heading reads *"Detection Corpora (Sigma)"* |
| the add form | collects **name, git, license** only |

That form cannot express what the registry already supports, and the gap is not
theoretical — it blocks the corpora committed in ADR-0015:

- **`subdir`** — 3 of the 5 YARA corpora need it (`signature-base`,
  `elastic-artifacts`, `rl-yara` all keep rules under `yara/`). Without it the
  adapter parses the whole clone, including tests and docs.
- **`tarball`** — ET Open is published *only* as a tarball, and is 70% of all
  Suricata rules. `git:` cannot fetch it.
- **`enabled`** — and this one is a defect I introduced. ADR-0015 committed seven
  corpora as `enabled: false`, and **the UI has no way to enable them.** `Remove`
  writes a *disable override* into the overlay; there is no re-enable. The only
  route back is hand-editing `detection_corpora.local.yaml`.
- **`priority`** — dedup authority (ADR-0010/0017). Invisible and uneditable.

## The honesty problem

The Suricata and YARA **adapters do not exist**. ADR-0015 delivered the atom
extractors (`suricata_atoms.py`, `yara_atoms.py`) but not the
`RuleCorpusAdapter` implementations, so `_ADAPTERS` still holds only `sigma`.

If the UI simply offered a free-text `adapter` field, a user could add a YARA
corpus, clone 12,000 rules, hit Rebuild, and get **zero rules with no
explanation** — `registry.iter_rules` logs `unknown adapter '…' — skipped` to a
server log the user never sees. Failing silently is worse than not offering it.

## Options considered

**A — Free-text adapter field, validate nothing.** Verdict: **rejected.** Produces
the silent-zero-rules failure above.

**B — Hardcode the three formats in the UI.** Verdict: **rejected.** It would
claim a capability the backend does not have, and would need editing again the
day the adapters land — the same coupling that produced three Sigma-only
constraints in the first place.

**C — Derive availability from the adapter registry.** The API reports which
formats are actually registered; the UI offers those and marks anything else
unavailable. Verdict: **chosen.** Honest by construction, and it lights up on its
own when ADR-0015's adapters are registered — no UI change required.

## Decision

### 1. Format availability comes from `_ADAPTERS`, never from a literal

New `GET /api/settings/formats`:

```json
{"formats": [
  {"format": "sigma",    "available": true,  "corpora": 8, "rules": 11396},
  {"format": "yara",     "available": false, "corpora": 5, "rules": 0},
  {"format": "suricata", "available": false, "corpora": 2, "rules": 0}
]}
```

`available` is `format in _ADAPTERS`. The listed set is `_ADAPTERS` ∪
`KNOWN_FORMATS` ∪ the adapters actually configured, so a corpus for a format the
build cannot parse is *visible* rather than silently inert.

### 1b. Configuring and ingesting are separate gates

*Revised during implementation — the first version of this ADR said `POST
/corpora` should validate against `_ADAPTERS`, and that was wrong.*

Since only `sigma` is registered, gating creation on `_ADAPTERS` would make the
API **refuse to create the very corpora the committed registry already holds** —
ADR-0015 committed seven suricata/yara entries. It would also stop an operator
staging a repo ahead of its adapter shipping, which is a legitimate thing to want.

So there are two distinct gates:

| Gate | Source | Meaning |
|---|---|---|
| may be **configured** | `KNOWN_FORMATS` = {sigma, suricata, yara} | the project recognises this format |
| may be **ingested** | `_ADAPTERS` | a parser is compiled in |

`POST /corpora` validates against `KNOWN_FORMATS` and returns a `warning` field
when the adapter is missing, so the operator is told at the moment of creation
rather than discovering zero rules after a Rebuild. An unrecognised format is
still a 400.

### 2. The registry's full vocabulary becomes editable

`CorpusIn` gains `subdir`, `tarball` and `priority`. Each row shows its format,
licence, priority and rule count; the table groups by format with per-format
totals.

### 3. Enable/disable becomes a first-class action

`PATCH /api/settings/corpora/{name}` with `{"enabled": bool}`, writing to the
overlay like every other mutation. This closes the trap in §Context: seven
corpora are currently unreachable from the UI.

`Remove` keeps its ADR-0006 semantics (a committed corpus gets a disable
override, never an edit to the committed file) — but it is no longer the *only*
way to turn something off, which is what made it a one-way door.

### 4. Unavailable adapters are labelled, not hidden

A corpus whose adapter is not registered renders with an `adapter unavailable`
badge and a disabled Rebuild affordance, explaining that the format needs its
adapter before it will ingest. The alternative — hiding it — would make the
seven ADR-0015 rows vanish, which is how the current UI already loses them.

### 5. The committed registry is still never written

Unchanged from ADR-0006: every mutation goes to `detection_corpora.local.yaml`.
Private corpora remain CLI-only for sync so git credentials stay out of the app.

## Consequences

**Easier**

- The seven ADR-0015 corpora become manageable without hand-editing YAML.
- `subdir` and `tarball` stop being CLI-only, which is what ET Open and three
  YARA corpora need.
- The UI stops needing an edit per new format.

**Harder**

- Two of the three formats will show as unavailable until ADR-0015's adapters
  land. That is the truth, displayed — but it is a UI that visibly promises
  something the backend cannot yet do, and that has to read as "not yet"
  rather than "broken".
- `tarball` has no revision to pin, unlike a git SHA, so a tarball corpus is
  less reproducible than a cloned one. The row shows its source type so the
  operator can see which they have.
- More editable fields means more ways to misconfigure a corpus; `priority` in
  particular silently changes dedup authority (ADR-0010/0017).

**Not in scope:** the actual `tarball:` fetch in `sync_corpora.py`, and the
Suricata/YARA adapters. This ADR makes them *configurable*; it does not make
them *work*.

## Validation

1. `GET /formats` reflects `_ADAPTERS` — registering an adapter flips
   `available` with no UI change.
2. `POST /corpora` with an unregistered adapter 400s and names what is available.
3. A disabled corpus can be re-enabled from the UI and reappears in
   `load_corpora`, i.e. the ADR-0015 seven are reachable again.
4. `subdir`/`tarball`/`priority` round-trip through the overlay YAML unchanged.
5. `tsc --noEmit` clean; the committed `detection_corpora.yaml` is byte-identical
   after any UI mutation.
