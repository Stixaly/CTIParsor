# ADR-0040 — Offline (air-gapped) installation bundle

**Status:** Accepted (implemented and validated 2026-09-09)
**Date:** 2026-09-09
**Relates to:** [0015](0015-multi-format-detection-matching.md) §5 (tarball corpora),
[0019](0019-multi-format-corpus-management.md) (corpus registry),
[0029](0029-pasted-text-and-captured-url-ingestion.md) (Chromium capture),
[0036](0036-architecture-service-multi-utilisateur.md) / [0037](0037-scaling-to-30-40-users.md) (how the service is deployed)

## Context

CTIParsor is meant for SOC and CTI teams, and a fair share of those work on
networks that reach nothing outside. `setup.sh` cannot run there: it fetches
from **twelve** distinct network sources, and until today the only way to
install without them was to reverse-engineer the script by hand.

Inventoried from `setup.sh` and measured on this workstation (Ubuntu 26.04,
Python 3.14, 2026-09-09):

| Step | Source | What comes down | Measured |
|---|---|---|---|
| `[1/6]` system packages | Ubuntu archive | python3-venv, build-essential, tesseract, poppler, libxml2/xslt, git… | full dependency closure: **452 packages, 436 MB** |
| `[1b/6]` Node.js 24 | deb.nodesource.com | one `.deb` | `nodejs_24.21.0-1nodesource1_amd64.deb`, 39 MB |
| `[3/6]` Python packages | PyPI | `requirements*.txt` resolved for this interpreter | **167 wheels, 3.1 GB** in 446 s — torch 554 MB plus 15 `nvidia_*` CUDA wheels (2.2 GB) |
| Stage 2c/2d/2e models | huggingface.co | `all-MiniLM-L6-v2`, `CyNER-2.0-DeBERTa-v3-base`, `gliner_large-v2.1` | **2.6 GB** (175 MB + 712 MB + 1.7 GB) after dropping the ONNX/OpenVINO/TF/Rust copies |
| `[5/6]` spaCy model | github.com/explosion | `en_core_web_sm` wheel | ~12 MB, optional |
| `[4/6]` MITRE bundles | raw.githubusercontent.com | enterprise, mobile, ics, capec | ~65 MB |
| corpora | 14 git remotes + rules.emergingthreats.net | Sigma/YARA clones + ET Open tarball | **684 MB** (`corpora/`, after ADR-0015 §5) |
| STIX icons | github.com/oasis-open | 27 SVG | 108 KB, already in the repo |
| web capture | playwright CDN | Chromium build | ~170 MB |
| frontend | registry.npmjs.org | `npm ci` | 249 MB `node_modules` → 4 MB `dist/` |
| LLM (Stage 3) | github.com/ollama + ollama.com registry | runtime + one model | `ollama-linux-amd64.tar.zst` 1.4 GB + `mistral` ~4.1 GB |

Roughly **13 GB** with the default model. The operator's instruction was
explicit: size is not the constraint, completeness is — the bundle must let
the tool *run* on the air-gapped host, LLM included, not merely install.

Two facts shape the design more than the size does:

1. **Most of `setup.sh` already has an "already present → skip" branch.** MITRE
   files are searched before being downloaded, models are loaded from cache,
   `playwright install` skips a browser that is there, icons are counted, the
   corpora step builds from local clones. Offline mode can mostly *pre-stage*
   files and let the existing branches fire, instead of forking the script.
2. **pip and HuggingFace honour environment variables.** `PIP_NO_INDEX=1` +
   `PIP_FIND_LINKS=<dir>` make every `pip install` in the script use the
   wheelhouse with no code change; `HF_HUB_OFFLINE=1` makes every
   `from_pretrained` refuse the network and read the cache.

## Options

**A — one self-contained bundle + `setup.sh --offline=<dir>`.** A script on a
connected twin of the target collects everything into `offline/`, records what
it was built with, and tars the source tree with it. On the target, `setup.sh`
verifies the bundle, installs the `.deb`s with `dpkg`, points pip and HF at the
bundle, stages the rest, and runs its ordinary steps.
Verdict: **chosen.** One artefact, one command, no infrastructure on the
air-gapped side, and the bundle doubles as a reproducible record (checksums,
git revision, build date, versions).

**B — internal mirrors** (devpi/Nexus for PyPI, an apt mirror, an HF mirror, an
npm mirror) with `setup.sh` unchanged and env vars pointing at them.
Verdict: rejected as the first step. It needs four or five services on the
air-gapped side, and each mirror still has to be *seeded* — with exactly the
artefacts A collects. A is the seed; B can be layered on later.

**C — a container image** (`docker save`) with everything baked in.
Verdict: deferred. It would remove the Python/distro coupling below, but the
deployment doc, the Chromium sandbox, GPU access and the worker model (ADR-0002)
all assume a host install, and the image would still have to embed the same
models and corpora. A's `offline/` directory is what a Dockerfile would `COPY`.

**D — trim** (CPU-only torch, no LLM, no `node_modules`).
Verdict: rejected by the operator. Kept as flags (`--no-llm`, `--no-corpora`,
`--no-browsers`) for people who want a smaller bundle, never as the default.

## Decision

### 1. `scripts/package_offline.sh` builds the bundle on a connected machine

Run from the project's `.venv` on the **same distribution and Python
major.minor as the target**, because the wheelhouse is built for the running
interpreter. It fills `offline/` (gitignored):

| `offline/…` | How it is collected |
|---|---|
| `wheels/` | `pip wheel -r requirements.txt -r requirements-api.txt playwright pip setuptools wheel` + the `en_core_web_sm` wheel; `re2` best-effort (needs `libre2-dev` on the builder) |
| `debs/` | `apt-cache depends --recurse` closure of the packages `setup.sh` installs + `libre2-dev` + `zstd` + Chromium's runtime libraries, fetched with `apt-get download` (no root); the NodeSource `.deb` fetched from its `Packages` index |
| `hf/` | `huggingface_hub.snapshot_download` of the three models with `HF_HOME=offline/hf`, plus the tokenizer/config files of every GLiNER encoder named in `gliner_config.json` (`microsoft/deberta-v3-large`) — GLiNER fetches them at load time |
| `browsers/` | `PLAYWRIGHT_BROWSERS_PATH=offline/browsers playwright install chromium` |
| `data/` | the four MITRE bundles, same URLs as `setup.sh` |
| `corpora.tar` | `scripts/sync_corpora.py` then tar of `corpora/` (git clones + ET Open with its `.sync.json`) |
| `frontend-dist.tar`, `node_modules.tar` | `npm ci && npm run build` |
| `ollama/` | latest `ollama-linux-amd64.tar.zst` from GitHub releases; the model pulled by running that binary with `OLLAMA_MODELS=offline/ollama/models` |
| `bundle.env` | `BUNDLE_PYTHON`, `BUNDLE_CODENAME`, `BUNDLE_ARCH`, `BUNDLE_GIT_REV`, `BUNDLE_BUILT_AT`, `BUNDLE_NODE_DEB`, `BUNDLE_OLLAMA_MODEL` |
| `SHA256SUMS` | every file above |

Then `dist/cti-parsor-offline-<rev>-<codename>-py<ver>.tar` = source tree
(`git archive HEAD`, or the working tree with `--worktree`) + `offline/`.
Every collector is resumable: an artefact already present is kept.

### 2. `setup.sh --offline=<dir>` installs from it

Before anything else: `sha256sum -c SHA256SUMS`, and refuse if
`python3 --version` or the distro codename differ from `bundle.env`. Then the
existing steps run with these differences, implemented as small hooks that
call functions in `scripts/offline_lib.sh`:

- `[1/6]` `sudo dpkg -i --skip-same-version offline/debs/*.deb` replaces
  `apt-get install`. Node.js arrives with it, so `[1b/6]` finds `node`.
- `[3/6]` `PIP_NO_INDEX=1 PIP_FIND_LINKS=offline/wheels` exported; the pip
  commands are unchanged.
- models: `offline/hf` copied to `~/.cache/huggingface`, `HF_HUB_OFFLINE=1`
  and `TRANSFORMERS_OFFLINE=1` exported for the run **and written to `.env`**,
  because `run_api.py` loads `.env` before the worker imports transformers and
  a bare `SentenceTransformer(...)` otherwise probes the Hub and waits for the
  timeout on every start.
- `[4/6]` `offline/data/*.json` copied to `data/` — the search loop finds them.
- corpora: `corpora.tar` extracted; `sync_corpora.py` is **skipped**,
  `build_detection_index.py` runs as usual.
- `[5/6]` `pip install en_core_web_sm` from the wheelhouse instead of
  `spacy download`.
- capture: `offline/browsers` copied to `~/.cache/ms-playwright`;
  `playwright install chromium` then finds it; `install-deps` is skipped
  (its libraries came with the `.deb`s) and the real launch test still runs.
- frontend: `dist/` and `node_modules/` extracted; `npm ci` skipped;
  `FRONTEND_OK=true` when `dist/index.html` exists.
- LLM: Ollama extracted to `/usr/local` (sudo), models copied to
  `~/.ollama/models`; a fresh `.env` gets `LLM_PROVIDER=ollama` and
  `OLLAMA_MODEL=<bundled>`; the summary says how to start `ollama serve`.

Design rules, in priority order: reuse the step's own "present → skip" branch;
prefer an environment variable to a code change; never touch the host before
the checksums pass; every skipped network action prints *why* it was skipped.

## Consequences

**Easier**

- Air-gapped installs become one `tar xf` and one command, and the bundle says
  exactly what it contains (revision, date, versions, checksums).
- The wheelhouse is a de-facto lockfile: two hosts built from the same bundle
  run identical packages, which the online `setup.sh` never guaranteed.
- The same `offline/` tree is what a future container image or internal mirror
  (options B, C) would be seeded from.

**Harder**

- **Python and distro coupling.** Wheels are built for one interpreter
  (`cp314` here) and `.deb`s for one release. A bundle must be built on a twin
  of the target; the installer refuses anything else rather than failing
  half-way with a message about a package.
- **Staleness.** Security fixes in wheels, corpus updates and new ET Open drops
  all require a rebuild and a re-transfer. `.sync.json` and `bundle.env` at
  least say *when* each part was frozen.
- **Licences travel.** The bundle carries `Elastic-2.0` and `none`-licence
  corpora (ADR-0015 §6) and a GPL/BSD mix of rules; redistributing the bundle
  is redistributing them. The manifest lists the corpora and their licences
  for that reason.
- **Size.** ~13 GB per bundle; CUDA wheels are 2.2 GB of it and are kept on
  purpose so a GPU host works without a second bundle.
- **Scope.** v1 is Debian/Ubuntu (`dpkg`) and x86_64. RHEL/Fedora would need a
  `dnf download --resolve` collector and `rpm -i`. The Ollama systemd unit is
  documented, not created.

## Validation

1. Build the bundle on this workstation; record sizes and durations per part.
2. Extract it to a directory on the Linux filesystem and run
   `setup.sh --offline=offline` with `PIP_NO_INDEX=1`, both proxies pointed at
   a dead port (so any stray network call fails fast) and `sudo`/`dpkg`
   stubbed, because root is not available here. Every step must report
   present/cached; the venv, indexes and rule store must be built.
3. With the same dead proxies: load the three models, run `build_indexes.py`
   and `build_detection_index.py`, launch Chromium.
4. Not possible here and recorded as the Linux-host procedure: the real
   `dpkg -i` of 452 packages, Ollama inference (the WSL distro dies at the
   first Stage 3 call — see ADR-0038), and a clean `--network none` container
   (the Docker socket needs root on this station).

## Validation results (2026-09-09)

Built on this workstation (Ubuntu 26.04 "resolute", Python 3.14.4, x86_64)
with `scripts/package_offline.sh --worktree`:

| Part | Measured |
|---|---|
| First build, everything from the network | 30 min 51 s |
| Resumed build (all parts kept) | ~3 min, dominated by `pip wheel` re-resolving from its cache and the 13 GB `tar` |
| `wheels/` | 168 wheels, 3.1 GB (torch 554 MB + 15 `nvidia_*` wheels 2.2 GB) |
| `debs/` | 457 `.deb`, 388 MB, incl. `nodejs_24.21.0-1nodesource1_amd64.deb` |
| `hf/` | 2.6 GB — MiniLM 175 MB, CyNER 712 MB, GLiNER 1.7 GB, **+ `microsoft/deberta-v3-large` tokenizer 2.4 MB** |
| `browsers/` | 655 MB (Playwright 1.62 installs chromium, chromium-headless-shell and ffmpeg) |
| `data/` | 65 MB |
| `corpora.tar` | 663 MB |
| `frontend-dist.tar` + `node_modules.tar` | 3.9 MB + 242 MB |
| `ollama/` | 5.5 GB — runtime v0.33.3 1.4 GB + `mistral` 4.4 GB (pulled at 29 MB/s) |
| `SHA256SUMS` | 1,314 files |
| Tarball | `dist/cti-parsor-offline-8e02c55-resolute-py3.14.tar`, 13.9 GB |

Replayed with `scripts/check_offline_bundle.sh` (scratch `HOME` on ext4,
proxies on a closed port, `sudo`/`dpkg` stubbed — 458 `.deb` handed to the
stub): **713 s**, venv from the wheelhouse, MITRE indexes built from the
staged MiniLM, rule store **87,407 rules** (suricata 52,878 · yara 23,065 ·
sigma 11,464 — identical to the online path), Chromium launches, Ollama
extracted into the scratch prefix and serving `mistral` (7.2B Q4_K_M) from
the staged files, GPU auto-detected. 17 of 18 checks passed on the first
replay; the failures were real, not harness noise:

1. **GLiNER needs its encoder's tokenizer from the Hub.** `gliner_config.json`
   names `microsoft/deberta-v3-large`; the checkpoint carries that encoder's
   weights but `AutoTokenizer.from_pretrained` still goes to the Hub, and
   `HF_HUB_OFFLINE=1` turned that into "couldn't find them in the cached
   files". The packager now reads `model_name` from every GLiNER config and
   snapshots that repo with `allow_patterns` limited to tokenizer and config
   files. Verified: `GLiNER.from_pretrained` succeeds offline once they are
   staged.
2. **A bare `TTP_EMBEDDING_MODEL=all-MiniLM-L6-v2` in `.env` is a 401 on the
   Hub.** sentence-transformers prefixes `sentence-transformers/` silently;
   `snapshot_download` does not. The packager applies the same rule.
3. The Ollama smoke test itself grepped for `"mistral"` with a closing quote
   while `/api/tags` reports `mistral:latest` — harness defect, fixed.

The rebuilt bundle (same tarball name, 13.9 GB, 1,314 files) replayed at
**18 of 18 checks in 706 s**; the only warnings left in the install log are
the two the online path prints on this host as well (Python 3.14 newer than
CI's 3.12; no `re2` wheel).

Two limits of this workstation, not of the design: `npm ci` fails with
`EACCES` on `/mnt/c` (DrvFs), so the packager packed the existing `dist/`
and `node_modules/` after warning; and `re2` has no wheel because
`libre2-dev` is not installed here, so the replayed install falls back to
Python's `re` exactly as the online install does on such a host.
