# Security Model

CTIParsor is a **local, single-user** tool for turning CTI reports into STIX. This
document describes its security posture, the surfaces it exposes, and the
deliberate limits. It is defensive in scope.

## Threat surfaces & how they're handled

### 1. Untrusted input documents (prompt injection)
Reports are attacker-influenced text. Before any LLM call, **only the user message
is sanitised** — the system prompt is developer-controlled and never run through the
sanitiser (`pipeline/stage3_llm.py::_sanitize_text_for_prompt`). Sanitisation:
- strips null bytes / control chars and removes HTML/XML tags and code fences,
- redacts common injection phrasings (`ignore previous…`, `role: system`, jailbreak/DAN, developer-mode),
- caps length to the prompt budget.

Defence in depth after the LLM: every returned name is fuzzy-matched against the
source text (Stage 3b hallucination filter), MITRE IDs are normalised against the
real ATT&CK corpus (Stage 3c), relationships can be self-verified (Stage 3d) and
cross-checked across two models (Stage 3e). A malicious document cannot inject
arbitrary entities that aren't grounded in its own text.

### 2. Local web API (CORS + auth)
The web UI serves on `localhost` with `CORS allow_origins=["*"]` and **no
authentication**. This is acceptable for **local single-user** use of *read/non-secret*
endpoints. It is **not** safe to expose CTIParsor on a shared host or the internet
as-is. In particular, **no endpoint that writes a secret exists today** — the LLM
API-keys settings panel is deliberately deferred (ADR-0007 Slice 2) until it ships
with a loopback-origin guard, write-only/masked key storage, and the client-reload
hook. Do not add secret-writing endpoints without that hardening.

### 3. Secrets & data at rest
All sensitive state is **gitignored**, never committed:
- `.env` — LLM API keys (bootstrap config).
- `cti_stix.db` — SQLite holding report text, generated bundles, and the
  detection-rule store. Treat as sensitive (it contains the CTI you processed).
- `uploads/`, `output/`, `input/*` — uploaded/produced report artifacts.
- `corpora/` and `detection_corpora.local.yaml` — local rule clones and the
  **private** corpus registry (private repo URLs and anything derived from them
  stay local; see ADR-0006).

Keys/DB are plaintext-at-rest on disk — adequate for a local workstation, **not**
for shared/multi-user hosts (use OS-level disk encryption there).

### 4. Detection-rule corpora
Public corpuses are committed (`detection_corpora.yaml`); private ones live only in
the gitignored overlay. Fetching uses your **ambient git auth** (SSH agent /
credential helper) via `scripts/sync_corpora.py` — CTIParsor never stores git
credentials. Rule parsing is pure (no execution of rule content). Per-corpus
`license` travels with every rule so export/drill-down can respect redistribution
terms (e.g. SigmaHQ Detection Rule License).

### 5. Sharing controls
Every emitted bundle carries a **TLP** marking (and optional **PAP**) plus an
authoring `Identity`, so downstream OpenCTI/MISP can apply sharing policy. Set
`STIX_TLP` (or per-job `tlp_level`) before exporting outside your team.

## Offline by default
No telemetry, no analytics, no outbound calls except the **optional** LLM provider
(Anthropic/Mistral) — and Ollama keeps even that local. With no API key the
pipeline still produces valid STIX. ML models are downloaded once and cached.

## What this is NOT
- Not a multi-user / hosted service — there is no authn/authz.
- Not hardened for internet exposure — keep it on localhost or behind your own auth proxy.
- Not a malware sandbox — it parses *documents and rule text*, it never executes samples.

## Reporting a vulnerability
Open a private security advisory on the repository, or contact the maintainer
directly. Please do not file public issues for exploitable vulnerabilities.
