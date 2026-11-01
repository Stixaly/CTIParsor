# Roadmap

What CTIParsor 1.0 promises, what comes after it, and what is not planned. One
person maintains the project, so this page gives no dates and promises nothing
the documents it links to do not already say. Where this page and those
documents differ, they win.

- **Releases** are on the
  [Releases page](https://github.com/Stixaly/CTIParsor/releases).
  [CHANGELOG.md](CHANGELOG.md) lists what each one shipped, and under
  `[Unreleased]` what is merged on `main` and not yet in a release.
- **1.0 is not released.** What it promises is written in the
  [support policy](docs/support-policy.md); the decision, and the options
  rejected, are in [ADR-0094](docs/adr/0094-what-1-0-promises.md), whose
  status is Proposed. Until 1.0, a minor release may change any surface, and
  the CHANGELOG says what an operator must do
  ([releasing.md](docs/releasing.md#versioning)).

- [1.0](#10)
- [After 1.0](#after-10)
- [Not planned](#not-planned)
- [Proposing something](#proposing-something)

## 1.0

### What it promises

Three things, and only these
([support policy](docs/support-policy.md#what-10-promises)):

1. **A stable contract:** the stable surfaces change incompatibly only in a
   new major version.
2. **Data that survives** an upgrade from the previous release and a restore:
   reports, review decisions, baselines and bundles.
3. **Measured, published limits:** each release publishes the extraction
   measured on the bundle it exports, with its denominators and limits.

It is for one analyst, on a self-hosted Docker Compose install, who reviews the
extractions before exporting them
([who 1.0 is for](docs/support-policy.md#who-10-is-for)). It certifies no level
of precision ([what it does not promise](docs/support-policy.md#what-10-does-not-promise)).
The [capability matrix](docs/support-policy.md#capability-matrix) marks each
capability supported, experimental or not supported, with its limits and its
evidence.

### What gates the tag

1.0 is tagged when no [release blocker](docs/support-policy.md#release-blockers)
is open (data loss, a lost review decision, an invalid export presented as
validated, an unusable essential journey) and the eleven work items of
ADR-0094 are done: a contract snapshot, the migration from the last release,
backup and restore, the browser journey, the in-house gold set, the
measurement of the exported bundle, the worker status, the OpenCTI import of
the candidate, the clean install from the published image, a freeze with real
use, and a recorded run with the default provider. The state of each, what it
proves and what it does not cover are in the ADR's
[action plan](docs/adr/0094-what-1-0-promises.md#action-plan); the
[readiness checklist](docs/releases/1.0-readiness.md) records each gate on the
release candidate.

Supported, with evidence still missing, as the capability matrix says:

- IoC extraction and relationships, against a gold set: items 5 and 6.
- The `anthropic` provider, a recorded run: item 11.

## After 1.0

Nothing here is scheduled, and no date is promised. These are the capabilities
the support policy marks experimental ("works, without commitment"; it can
change, or go, in a minor release) and the gaps the documents name. Each
experimental row of the
[capability matrix](docs/support-policy.md#capability-matrix) gives its limits.

- **LLM providers `gemini`, `mistral`, `lmstudio`, `ollama`, and vLLM with
  another model.** Wired, with no recorded run in the repository. A provider
  is supported only with a recorded run
  ([ADR-0094](docs/adr/0094-what-1-0-promises.md), decision 13).
- **Figure reading (Stage 1f).** Off by default.
- **The air-gapped install.** No commitment in 1.0; CI checks only that the
  bundle's images come back from `docker save` and `docker load`.
- **Reports in French.** The named-entity models are English, and no gold
  report is in French.
- **OCR of fully scanned PDFs.** No fully scanned report is in the in-house
  set.
- **A second annotator for the in-house set.** Welcome, and not a condition of
  1.0 ([ADR-0094](docs/adr/0094-what-1-0-promises.md), *Consequences*).
- **A warning for a deprecated variable that is still set.** No variable is
  deprecated and no such check exists; the first deprecation adds it
  ([support policy](docs/support-policy.md#breaking-changes-and-deprecation)).
- **The LLM API-keys settings panel.** Deliberately deferred until it ships
  with a loopback-origin guard and write-only key storage
  ([SECURITY.md](SECURITY.md#2-local-web-api-cors--auth)).
- **Evidence the contract snapshot does not have yet.** It does not record the
  response fields of most operations, and it does not check
  `x_ctiparsor_enrichment`
  ([support policy](docs/support-policy.md#stable-surfaces), *Evidence today*).

## Not planned

Marked not supported by the support policy, or rejected by ADR-0094, for the
reason given. The documents hold no plan to change any of them.

- **An install other than Docker Compose**, a host install included. Docker
  Compose is the only supported install
  ([ADR-0054](docs/adr/0054-full-docker-installation.md)); a host install is
  kept only as a migration path ([upgrading.md](docs/upgrading.md)).
- **Several analysts, authentication, access control.** The 1.0 target is one
  analyst on a local install, and CTIParsor is not a multi-user service
  ([SECURITY.md](SECURITY.md)). ADR-0094 declines to do it before 1.0:
  [ADR-0036](docs/adr/0036-architecture-service-multi-utilisateur.md)
  (Proposed) treats authentication as a project of several weeks.
- **An import into MISP.** There is no connector and no import test. A
  MISP-shaped STIX 2.1 bundle is accepted as a baseline to enrich.
- **A GPU.** The image carries torch's CPU build.
- **A Python package, or `pipeline/` as a library.** There is no sdist, wheel
  or PyPI package ([ADR-0085](docs/adr/0085-releases-promote-the-image-main-built.md)):
  it would be a second install to build and support, without the models,
  corpora, Chromium and PostgreSQL the image carries.
- **Fixes on an older version line, or a support duration.** Only the latest
  minor version gets fixes, because one person maintains the project
  ([Maintenance of 1.x](docs/support-policy.md#maintenance-of-1x)).
- **A precision threshold that blocks a release.** The data cannot support one
  ([ADR-0094](docs/adr/0094-what-1-0-promises.md), decision 1).
- **An `/api/v1` prefix.** Moving every route would itself be the breaking
  change 1.0 must avoid ([ADR-0094](docs/adr/0094-what-1-0-promises.md#options-rejected)).

## Proposing something

A proposal goes through a
[feature request](https://github.com/Stixaly/CTIParsor/issues/new/choose).
Say which of the lists above it touches, and, if it is on *Not planned*, what
changes the reason given there. A bug goes through the bug report form, and a
vulnerability through the private channel of
[SECURITY.md](SECURITY.md#reporting-a-vulnerability). To send the change
yourself, [CONTRIBUTING.md](CONTRIBUTING.md) explains how it gets in.
