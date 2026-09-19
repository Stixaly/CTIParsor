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
The web UI serves on `localhost` with **no authentication**. There is also no
CORS middleware: one uvicorn process serves both the API and the built React
UI, so the browser only ever calls this API from the same origin it loaded
the page from, and the dev server proxies `/api` the same way (`frontend/vite.config.ts`)
— nothing in this codebase needs a cross-origin browser call, so none is
allowed. That closes the drive-by vector (a page on another site reading this
API's responses in the analyst's browser) but changes nothing about direct
access: this is acceptable for **local single-user** use of *read/non-secret*
endpoints, not for a shared host or the internet — anyone who can reach the
port at all (curl, another process on the same machine, a proxy) still has
full access. (In the container stack the API process itself binds `0.0.0.0` — a
container has no "localhost" of its own to bind — but the same guarantee is
kept one layer out: compose publishes it on `127.0.0.1` on the *host* by
default, so the reachability is identical, just enforced at a different
point. See [docs/docker.md](docs/docker.md).) In particular, **no endpoint that writes a secret exists today** — the LLM
API-keys settings panel is deliberately deferred (ADR-0007 Slice 2) until it ships
with a loopback-origin guard, write-only/masked key storage, and the client-reload
hook. Do not add secret-writing endpoints without that hardening.

### 3. Secrets & data at rest
All sensitive state is **gitignored**, never committed:
- `.env` — LLM API keys (bootstrap config), and the PostgreSQL password
  (`CTI_DB_PASSWORD` / `PGPASSWORD`).
- PostgreSQL (`DATABASE_URL`, mandatory — ADR-0045, ADR-0053) — report text,
  generated bundles, and the detection-rule store all live there now; no
  SQLite file exists any more. Treat as sensitive (it contains the CTI you
  processed); `scram-sha-256` authentication only, and the compose service
  publishes no port.
- `uploads/`, `output/`, `input/*` — uploaded/produced report artifacts.
- `corpora/` and `detection_corpora.local.yaml` — local rule clones and the
  **private** corpus registry (private repo URLs and anything derived from them
  stay local; see ADR-0006).

Keys/DB are plaintext-at-rest on disk — adequate for a local workstation, **not**
for shared/multi-user hosts (use OS-level disk encryption there).

### 4. Stage 2 regex extraction (ReDoS)
Stage 2 (`pipeline/stage2_extraction.py`) runs ~19 regexes against
attacker-influenced report text. Most route through `_compile_pattern`,
which uses `google-re2` (guaranteed linear-time matching, no catastrophic
backtracking) when it's installed, falling back to stdlib `re` when it
isn't. Seven sub-patterns use negative lookaround (`(?<!...)`, `(?!...)`),
syntax no non-backtracking engine — RE2 included — can parse; those stay on
stdlib `re` unconditionally. They're checked, not just assumed, safe: none
has the nested-unbounded-quantifier shape that makes backtracking
exponential (see [ADR-0049](docs/adr/0049-redos-guard-actually-wired-in.md)'s
validation record for the stress test). `google-re2` ships prebuilt wheels
(cp312+, no toolchain); a platform without one just loses the guarantee on
the other 12 patterns, silently — `setup.sh` warns at install time.

### 5. Detection-rule corpora
Public corpuses are committed (`detection_corpora.yaml`); private ones live only in
the gitignored overlay. Fetching uses your **ambient git auth** (SSH agent /
credential helper) via `scripts/sync_corpora.py` — CTIParsor never stores git
credentials. Rule parsing is pure (no execution of rule content). Per-corpus
`license` travels with every rule so export/drill-down can respect redistribution
terms (e.g. SigmaHQ Detection Rule License).

### 6. Sharing controls
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
  `API_HOST` in `.env` controls the bind address; see [docs/deployment.md](docs/deployment.md)
  for the three supported postures (SSH tunnel, firewalled interface, nginx + TLS + basic auth).
- Not a malware sandbox — it parses *documents and rule text*, it never executes samples.
- The container image ([docs/docker.md](docs/docker.md), ADR-0044) adds **isolation, not
  authentication**: non-root, read-only root filesystem, all capabilities dropped, seccomp
  profile that keeps the Chromium sandbox on, API published on loopback only. Everything
  above still applies inside it; API keys reach the container through `env_file` and are
  readable by whoever holds the Docker socket.

## Reporting a vulnerability
Open a private security advisory on the repository, or contact the maintainer
directly. Please do not file public issues for exploitable vulnerabilities.
