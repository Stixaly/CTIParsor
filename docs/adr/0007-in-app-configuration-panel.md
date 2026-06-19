# ADR-0007: In-App Configuration Panel (LLM keys + detection corpora)

**Status:** Proposed
**Date:** 2026-06-19
**Deciders:** maintainer

## Context

After install, users want a Settings UI to (1) set the LLM provider + API key and
(2) add/remove public Sigma corpora — instead of hand-editing `.env` and
`detection_corpora.yaml`. CTIParsor already has the pattern: the `/policy` page is
a settings UI backed by an API + a singleton DB table.

The complication is **secrets over a local web surface**: CTIParsor serves on
`localhost` with CORS `allow_origins=["*"]` and no auth. A read endpoint for
non-secret config is fine; an endpoint that *writes an API key* is a real risk —
any site open in the browser can POST to `localhost:8000`. Two more forces:
the LLM clients are created once and cached (`_anthropic_client` etc.) so a new
key needs a reload hook; and corpora sync/rebuild are slow (SigmaHQ ≈ thousands
of rules) so they must run in the background.

## Decision

Ship a **Settings page in two slices**, lower-risk first:

1. **Corpora panel (no secrets)** — list/add/remove public Sigma repos, background
   Sync + Rebuild with progress. UI writes additions to the gitignored
   `detection_corpora.local.yaml` overlay (no churn on the committed registry;
   "promote to committed" is a later action).
2. **Keys panel (secrets — gated on the security work)** — provider + key, stored
   masked, with the CORS/auth hardening and the client-reload hook below.

Cross-cutting decisions:
- **Secret storage:** a singleton `app_settings` DB row (mirrors
  `relationship_policy`), in the already-gitignored `cti_stix.db`. The key is
  **write-only** over the API — `GET` returns it masked (`sk-…1234`), never plaintext.
- **Endpoint hardening:** the mutating/secret settings routes are restricted to a
  **loopback-origin guard** (reject non-localhost). CORS stays `*` only for
  read-only, non-secret data.
- **Runtime reload:** saving LLM settings calls a `reload_llm_config()` that clears
  the cached clients and re-reads config, so changes apply without a restart.
- **Background work:** Sync/Rebuild reuse the existing worker + SSE progress pattern.

## Options Considered — secret storage

### Option A: `app_settings` DB row (chosen)
| Dimension | Assessment |
|---|---|
| Complexity | Low — mirrors `relationship_policy` |
| Security | DB already gitignored; key write-only + masked on read |
| Portability | Self-contained; no extra deps |

### Option B: Write to `.env` from the app
| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Security | Mixes app-written secrets into a dotfile other tooling reads; easy to leak via misconfig |

Rejected — `.env` is for bootstrap/dev, not a runtime-mutated secret store.

### Option C: OS keychain (keyring)
| Dimension | Assessment |
|---|---|
| Security | Best |
| Complexity | New dependency + per-OS behavior; overkill for a local single-user tool |

Deferred — revisit if multi-user/hosted.

## Options Considered — endpoint exposure for secrets

- **A (chosen):** loopback-origin guard on mutating settings routes; key masked on read. Cheap, closes the cross-site POST risk for a local tool.
- **B:** a local settings token the UI must present. Stronger, more setup; revisit if CTIParsor is ever exposed beyond localhost.
- **C:** rely on CORS `*` + no auth — **rejected** for anything touching secrets.

## Trade-off Analysis

The corpora panel has no secrets, so it ships immediately on the existing pattern.
The keys panel's risk is entirely about the **write surface for secrets on a
permissive localhost API** — so the work there is 80% security plumbing (loopback
guard, masked read, reload hook) and 20% UI. Splitting the slices lets the useful,
safe half land now without waiting on the security half. Storing secrets in the
gitignored DB (Option A) is the pragmatic local-tool choice; keychain (C) is the
right answer only once CTIParsor is multi-user or hosted.

## Consequences

- **Easier:** post-install setup without editing files; corpora managed visually.
- **Harder / revisit:** the loopback guard assumes localhost-only deployment — if
  CTIParsor is ever served remotely, the secret endpoints need real auth (Option B+).
  A key in the DB is plaintext-at-rest on disk (gitignored, same posture as the
  report content already there) — acceptable locally, not for shared hosts.
- **Watch:** never log or return the raw key; corpora added via UI land in the
  gitignored overlay, so they're not reproducible until promoted to the committed file.

## Action Items

**Slice 1 — corpora panel (this change)**
1. [ ] `GET/POST/DELETE /api/settings/corpora` (writes the local overlay) + `POST …/rebuild` (background).
2. [ ] Refactor the build core into a callable `rebuild_store()`; Settings page + sidebar link.

**Slice 2 — keys panel (next, gated on security)**
3. [ ] `app_settings` table; `GET/PUT /api/settings/llm` (write-only key, masked read).
4. [ ] Loopback-origin guard on settings mutations; `reload_llm_config()` to reset cached clients.
5. [ ] "Test connection" action; keys panel UI.
