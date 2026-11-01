# Security Model

CTIParsor is a **local, single-user** tool for turning CTI reports into STIX. This
document describes its security posture, the surfaces it exposes, and the
deliberate limits. It is defensive in scope.

## Threat surfaces & how they're handled

### 1. Untrusted input documents (prompt injection)
Reports are attacker-influenced text. Every prompt that embeds it encloses it
between two marker lines carrying a nonce (a hash of the text), and the system
prompt names those markers and says that what lies between them is data, never
instructions (spotlighting, `pipeline/llm_parse.py::fit_report`, ADR-0074).
Before any LLM call the user message is also prepared by
`pipeline/stage3_llm.py::_sanitize_text_for_prompt`, which deletes nothing the
report says:
- removes control characters and invisible ones (zero-width, direction marks,
  bidi overrides and isolates, BOM), counted in the stage report;
- defuses chat-template markup (`<|im_end|>`, `<|im_start|>`, `<think>`,
  `[INST]`…) by inserting a space, because vLLM, Ollama and LM Studio would
  otherwise tokenize it as the real control token; also counted;
- caps length to the prompt budget.

Phrasings such as "ignore previous instructions" are no longer redacted: the
rule deleted genuine descriptions of malware behaviour and missed every
synonym or other language (ADR-0074).

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

### 7. Reference STIX bundles (ADR-0090)
A STIX 2.1 bundle sent to enrich a report is untrusted input. A bundle over 20 MB,
or with more than 10,000 objects, is refused (`pipeline/baseline_stix.py`,
`api/routes/_common.py`). Each object is checked against the STIX schemas
when the job runs, and an object that fails is left out, not repaired. A request
body over its route's budget gets a 413 before the application reads the rest
(`api/body_limit.py`).

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

## Supply chain (ADR-0075)
- **Pinned inputs.** Python dependencies install from hashed locks
  (`make lock`, ADR-0080) with `pip install --require-hashes`: a file whose
  sha256 differs from the lock's fails the install, and torch's index serves
  torch alone. The Dockerfile's base images and every compose image are
  pinned by digest. Dependabot proposes new digests, GitHub Actions and UI
  packages as pull requests.
- **Audited on every push.** The `dependency-audit` CI job runs `pip-audit` on
  the lock and `npm audit` on the UI's production dependencies, and blocks
  the image: a known vulnerability ships only if it is listed below.
- **Static analysis.** CodeQL (`security-extended`) scans the Python, the
  TypeScript and the GitHub Actions workflows on every push and weekly;
  findings are in the Security tab.
- **Image scan (ADR-0078).** Grype scans the built image's operating-system
  packages on every push, every PR and weekly; vulnerabilities with a fix are
  reported to Code scanning (category `container-image`).
- **Pull requests (ADR-0078).** Dependency review fails a PR that adds or
  changes a dependency with a known vulnerability of high severity or worse.
- **Pinned workflows (ADR-0078).** Every GitHub Action is pinned to a full
  commit SHA (Dependabot updates it); tokens are read-only unless a job
  asks for more, and no checkout keeps its credentials. OpenSSF Scorecard
  rates these practices weekly (README badge).
- **Protected `main` (ADR-0078).** A change reaches `main` only through a
  pull request whose 13 required checks pass: tests, audits, the image
  build, CodeQL and the fuzzers. A CodeQL alert of medium severity or higher
  that the pull request adds blocks it. Force-push and deletion are blocked,
  and secret scanning with push protection is on.
- **Weekly, without a push.** CI runs every Monday, so a vulnerability
  published on a version already shipped is found within a week.
- **Fuzzing (ADR-0081).** Atheris fuzzes the code that reads
  attacker-controlled input (report text, quoted rules, dates, the prompt
  enclosure, and a reference STIX bundle, `baseline_intake`) on every pull request
  and weekly; a crash, a broken invariant, an input slower than 10 s or a memory
  blow-up fails the run.
- **Verifiable image.** Each image pushed to GHCR carries a CycloneDX SBOM and
  two signed attestations bound to its digest, build provenance and that SBOM:

  ```
  gh attestation verify oci://ghcr.io/stixaly/ctiparsor@sha256:<digest> -R Stixaly/CTIParsor \
    --signer-workflow Stixaly/CTIParsor/.github/workflows/ci.yml --source-ref refs/heads/main
  ```

  Without `--signer-workflow`, an attestation signed by any workflow of the
  repository would pass.
- **Releases (ADR-0085).** A release is a tag `vX.Y.Z` on a commit of `main`
  whose CI passed. Its image is the one that run built and attested, named by
  digest in the Release notes: nothing is rebuilt. The Release's files carry
  their SLSA build provenance, signed by the release workflow:

  ```
  gh attestation verify ctiparsor-X.Y.Z.tar.gz -R Stixaly/CTIParsor \
    --signer-workflow Stixaly/CTIParsor/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
  ```

  The release workflow's checks catch mistakes. What stops a person who can
  push a tag is a tag ruleset on `v*`, a repository setting described in
  [docs/releasing.md](docs/releasing.md). That ruleset is not set yet
  (2026-10-30).

  The first release,
  [v0.1.0](https://github.com/Stixaly/CTIParsor/releases/tag/v0.1.0), was
  published on 2026-10-17, from the tag `v0.1.0` on commit 4bdfa8f. Its
  archive, its SBOM and its image pass the pinned verify commands of its
  notes (checked 2026-10-23). Release immutability was turned on after
  v0.1.0 was published, so that Release is not immutable.
  [v0.2.0](https://github.com/Stixaly/CTIParsor/releases/tag/v0.2.0),
  published on 2026-10-29 from the tag `v0.2.0` on commit ce59cfb, is the
  first immutable one: its files and its tag can no longer change, and
  `gh release verify v0.2.0` checks GitHub's release attestation. Its
  archive, its SBOM and its image pass the pinned verify commands of its
  notes (checked 2026-10-30).

### Not shipped
**diskcache** (PYSEC-2026-2447 / CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v,
unsafe pickle deserialisation, no fixed release) was accepted here until
2026-10-04. It is now left out of every lock (`scripts/lock.sh`), and every
install is `--no-deps`, so it is in neither the image nor CI. pySigma declares
it, but only its ATT&CK and D3FEND data cache imports it
(`sigma/data/mitre_attack.py`, `mitre_d3fend.py`), which CTIParsor never
loads. `tests/test_pattern_check.py::test_the_sigma_gate_never_needs_diskcache`
fails if the Sigma gate ever needs it. Expect `pip check` in the image to report
"pysigma requires diskcache, which is not installed": that is this decision.
Scorecard's Vulnerabilities check still finds it: its scanner, OSV-Scanner,
resolves `requirements/requirements.txt` (ranges, not the lock) through pySigma's
declared dependencies. `requirements/osv-scanner.toml` leaves it out, until the
date it gives.

### Accepted vulnerabilities
The image scan's accepted ones (Grype, Code scanning) are also listed in
`.grype.yaml`, each rule tied to the exact package version reviewed. The scan
leaves them out, and reports them again as soon as that version changes, for
a new review. The ones in a manifest, which Scorecard's Vulnerabilities check
scans with OSV-Scanner, are listed in the `osv-scanner.toml` next to that
manifest (`frontend/osv-scanner.toml` for the UI's), each until a review date;
Scorecard reports them again after it. A row here and its rule there are
added together.

| Id | Package | Why it is accepted | Reviewed |
|---|---|---|---|
| CVE-2025-15367, CVE-2026-12345 (Grype, Code scanning) | CPython 3.14.10, fixed in 3.15 only | `poplib` command injection: CTIParsor never imports `poplib`. `tempfile.TemporaryDirectory` cleanup race: needs a local attacker who can change the directory tree while it is cleaned up. CTIParsor's own code uses it only in scripts the application never runs: `scripts/measure_web_capture.py` and `scripts/measure_review_revision_trigger.py` (measurements) and `scripts/check_migration_from.py` (a CI check). A dependency uses it too: `huggingface_hub`, when it downloads a model into `HF_HOME`. The container's `/tmp` is its own tmpfs and the model cache is written by the application's user only, so the attacker would already be that user. Revisit when the image moves to Python 3.15 (ADR-0079). | 2026-10-31 |
| CVE-2026-103995 (Grype, Code scanning) | CPython 3.14.10, fixed in 3.16 only | `http.client` misreads a chunked response whose chunk size is negative or not hexadecimal, so it can take part of the body for framing or the reverse. Only the server that answers can send such a response, and that server already chooses the body it sends: the flaw gives it nothing more. CTIParsor's own `urllib.request` calls are the ones that use it: the detection-corpus downloads (`pipeline/detection/sync.py`, HTTPS, every URL and redirect validated), the NVD lookup of Stage 2f (`pipeline/stage2f_cve_enrichment.py`, HTTPS) and the vision provider (`pipeline/vlm.py`, the operator's own server). `requests` goes through urllib3 and `httpx` through h11, which parse chunks themselves. Revisit with the next Python 3.14 release that carries the fix, or the move to 3.15 (ADR-0079). | 2026-10-31 |
| CVE-2026-114603 (GHSA-xcq7-p3pf-p88h), PYSEC-2026-3447 (CVE-2026-59890), GHSA-xmj3-9gf7-h52w (OSV-Scanner, `requirements/requirements-opencti.lock.txt`) | opentelemetry-api 1.35.0 and setuptools 82.0.1, which pycti 7.260930.0 pins (`opentelemetry-api~=1.35.0`, `setuptools~=82.0.0`) | That lock installs only the venv of the OpenCTI check (TESTING.md) on the maintainer's machine, never the image or CI, and the venv runs pycti as a client of a throwaway OpenCTI on loopback. opentelemetry-api's flaw is in parsing an inbound `tracestate` header, which only a server does; setuptools' are in building a source distribution on macOS and in installing a legacy egg on Windows, which the venv never does (pip installs wheels, on Linux). The image's lock has setuptools 84.2.1 and no opentelemetry. Revisit when the check moves to a pycti that lifts the pins. | 2026-11-01 |

## Supported versions
Fixes land on `main` and ship in the next release. Only the latest release is
supported: [the Releases page](https://github.com/Stixaly/CTIParsor/releases/latest)
names it (0.2.0 since 2026-10-29).

## Reporting a vulnerability
Report it privately:
[open a security advisory](https://github.com/Stixaly/CTIParsor/security/advisories/new)
(Security tab → "Report a vulnerability"), or contact the maintainer directly.
Please do not file public issues for exploitable vulnerabilities.

The advisory stays private between you and the maintainer until it is
published. You get a first answer within 14 days. A confirmed vulnerability
is fixed in a pull request; the advisory is then published, with a CVE
requested through GitHub when the issue warrants one, and the CHANGELOG
names the fix.
