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
  rejected, are in [ADR-0094](docs/adr/0094-what-1-0-promises.md), accepted
  on 2026-11-01. Until 1.0, a minor release may change any surface, and
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
([who 1.0 is for](docs/support-policy.md#who-10-is-for)). That changes if
[ADR-0097](docs/adr/0097-1-0-is-a-shared-service-for-one-team.md) is accepted
(accepted on 2026-11-08): 1.0 is one install shared by one team, behind
authentication, with roles. It certifies no level
of precision ([what it does not promise](docs/support-policy.md#what-10-does-not-promise)).
The [capability matrix](docs/support-policy.md#capability-matrix) marks each
capability supported, experimental or not supported, with its limits and its
evidence.

### What gates the tag

1.0 is tagged when no [release blocker](docs/support-policy.md#release-blockers)
is open (data loss, a lost review decision, an invalid export presented as
validated, an unusable essential journey) and the thirteen work items of
ADR-0094 are done: a contract snapshot, the migration from the last release,
backup and restore, the browser journey, the in-house gold set, the
measurement of the exported bundle, the worker status, the OpenCTI import of
the candidate, the clean install from the published image, a freeze with real
use, a recorded run of the qualified LLM configuration (a local vLLM,
[ADR-0100](docs/adr/0100-a-local-vllm-is-the-1-0-llm-configuration.md)), figure reading on by
default, and a run's record of the models it actually loaded (item 13, added
2026-11-08). The state of each, what it
proves and what it does not cover are in the ADR's
[action plan](docs/adr/0094-what-1-0-promises.md#action-plan).

[ADR-0097](docs/adr/0097-1-0-is-a-shared-service-for-one-team.md) also adds
work items 14 to 24, and the tag waits for them: authentication and roles,
sessions and tokens, the egress policy by TLP, the audit, metrics and alert
rules, scheduled backups, bounds on the job list and on requeues, the false
backup log, response models, a load and failure recipe, and an end-to-end
journey with the real models. Their code is on `main`. Their qualification is
not finished: the [capabilities section](docs/support-policy.md#capabilities-implemented-qualified-limits)
says, for each, what has been shown and what is still open.

The [readiness checklist](docs/releases/1.0-readiness.md) records each gate on the
release candidate.

Supported, with evidence still missing, as the capability matrix says:

- IoC extraction and relationships, against a gold set: items 5 and 6.
- The qualified LLM configuration (a local vLLM, [ADR-0100](docs/adr/0100-a-local-vllm-is-the-1-0-llm-configuration.md)),
  a recorded run with figure reading on: gate `default_provider_measured`.
  The `anthropic` provider stays supported and is not qualified for 1.0.
- Figure reading (Stage 1f), on by default with the provider chosen for the
  text: not yet measured with the qualified configuration, figures on (ADR-0100).

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
- **Beyond one team on one host.** Named in
  [ADR-0097](docs/adr/0097-1-0-is-a-shared-service-for-one-team.md) as not
  covered: isolation between teams (an owner per report, filtered queries),
  high availability, object storage, an OpenCTI connector with retries, and
  SAML.
- **An import into MISP.** A target after 1.0
  ([ADR-0094](docs/adr/0094-what-1-0-promises.md), decision 14). There is no
  connector and no import test today; a MISP-shaped STIX 2.1 bundle is
  accepted as a baseline to enrich.
- **A quality track for extraction (1.1).** Proposed on 2026-11-08 and not
  scheduled. Each step names what it should bring: better predictions, fewer
  false positives, or a lower cost.
  1. **The CyNER and GLiNER contributions, by entity type.** This comes first
     because the evidence already points there: on AnnoCTR dev, CyNER produced
     87 of the 98 false positive actors and 93 of the 132 false positive malware.
     Four variants are compared with the rest of the pipeline unchanged: neither
     model, CyNER, GLiNER, both. Per type, they show the right entities only one
     model finds, the false positives it adds, and what the fusion loses.
     A model stays on only for the types where it helps.
  2. **ATT&CK retrieval encoders.** MiniLM (today's), ATTACK-BERT and a
     cybersecurity sentence encoder, each with its vectors rebuilt on the same
     corpus (descriptions and procedure examples). Measured with the existing
     tools before any change:
     - `python -m evaluation retrieval`: candidate recall per chunk at several k,
       the rank of the right technique, the useless candidates, time and memory;
     - `python -m evaluation ttp-errors` (ADR-0072): whether a technique is lost
       at retrieval or at selection.

     If the right techniques are already retrieved and then rejected, the
     selection is the thing to fix, not the encoder. SecureBERT+ is a masked
     language model, not a sentence encoder: it is not a candidate as is.
  3. **Fusion rules by type and by kind of evidence.** No model wins
     everywhere. The fusion keeps each mention's span, type, source, score and
     competing proposals, and separates detection, typing and resolution. Raw
     scores of two models are not compared; thresholds come from annotated
     results.
  4. **GLiNER's next version with explicit category definitions**, against
     the best configuration of step 1: it needs an integration change, not
     only a variable.
  5. **Fine-tuning**, only for the errors that remain after steps 1 to 4. The
     data is split by document into training, calibration and a final test.

  The rule for every step: models and thresholds are chosen on AnnoCTR train
  and dev. AnnoCTR test is read once per decision (ADR-0060), and the in-house
  gold is never used to choose; it measures the release. The names of the
  newer models (a "SecureBERT 2.0" bi-encoder, "GLiNER 2.5") must be checked
  before the work starts.
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
