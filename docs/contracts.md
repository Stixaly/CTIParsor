# The recorded contracts: a guide for consumers and forks

What the files under `contract/` record, how to read the custom STIX properties
of a CTIParsor bundle, how to change a recorded surface without breaking the
contract tests, and what a fork does not get. The promises themselves are in
[support-policy.md](support-policy.md#stable-surfaces); this page does not add
one. 1.0 is not released ([support-policy.md](support-policy.md)): until it is,
a minor release may change any surface, and the CHANGELOG says what an operator
must do.

This page was checked against the repository at commit 8d528d4 on 2026-11-15.
The counts below are those of that commit.

- [What is recorded](#what-is-recorded)
- [Reading a bundle: the custom properties](#reading-a-bundle-the-custom-properties)
- [Reading the configuration contract](#reading-the-configuration-contract)
- [Changing a recorded surface (forks and contributors)](#changing-a-recorded-surface-forks-and-contributors)
- [What the contracts do not catch](#what-the-contracts-do-not-catch)
- [Official image and fork](#official-image-and-fork)

## What is recorded

`scripts/contract.py` reads each stable surface from the code and compares it
with a file of `contract/`. `tests/test_contract.py` runs
`python scripts/contract.py check` on every pull request and fails on any
difference, a compatible one included, so a file always equals the code
([TESTING.md](../TESTING.md#the-stable-contract-adr-0094-item-1)).

| File | Records | Entries | Read from |
|---|---|---|---|
| [`contract/openapi.json`](../contract/openapi.json) | each operation of the API schema: parameters, request body, responses, field by field | 1352 | the schema the app publishes at `/openapi.json` |
| [`contract/cli.json`](../contract/cli.json) | the arguments of `main.py`, the stage ids, the container commands, `make db-upgrade` | 36 | `build_parser()`, `docker/entrypoint.sh`, the Makefile |
| [`contract/config.json`](../contract/config.json) | the variables of `.env.example` (set or shown, and their values), the Compose project, services with their profiles, named volumes | 177 (162 variables, 9 services, 5 volumes, 1 project) | `.env.example`, `compose.yaml` |
| [`contract/stix.json`](../contract/stix.json) | the custom STIX properties with their JSON types, and the deterministic ids of the reference bundles' objects | 103 (13 properties, 90 ids) | the Stage 4 reference bundles, `tests/fixtures/stage4_reference/expected/` |
| [`contract/formats.json`](../contract/formats.json) | the SSE event names and the layout of the detection export ZIP | 12 | `api/routes/progress.py`, `api/routes/coverage.py` |

Each difference is classed `breaking`, `default` or `compatible`
(`scripts/contract.py`, [support-policy.md](support-policy.md#breaking-changes-and-deprecation)).
A breaking change needs a major version after 1.0.

What the contract guarantees, per surface, is what
[support-policy.md, Stable surfaces](support-policy.md#stable-surfaces) lists.
The contract files are the evidence that a change was seen, not the guarantee:
a surface that no file records is not covered
([What the contracts do not catch](#what-the-contracts-do-not-catch)).

## Reading a bundle: the custom properties

The bundle follows STIX 2.1. CTIParsor adds properties whose name starts with
`x_`. [`contract/stix.json`](../contract/stix.json) records 13, each under the
object type where the reference bundles carry it, with its JSON type. Their
meaning is documented in [stix-output.md](stix-output.md).

| Property | On | JSON type (recorded) | Meaning | Where it is documented |
|---|---|---|---|---|
| `x_evidence_label` | relationship | string | the evidence grade: `observed`, `reported`, `assessed`, `inferred` or `gap`; MITRE's edges from graph completion carry `external-reference` | [stix-output.md](stix-output.md) |
| `x_evidence_text` | relationship | string | the sentence of the report that supports an extracted relationship | [stix-output.md](stix-output.md), ADR-0093 |
| `x_inference_rule` | relationship | string | how graph completion derived the edge, for example `transitive:uses+uses` | [stix-output.md](stix-output.md) |
| `x_inferred_from` | relationship | array | the ids of the premise edges | [stix-output.md](stix-output.md) |
| `x_policy_rule` | relationship | string | the relationship-policy rule that added the edge, for example `malware drops file` | [stix-output.md](stix-output.md) |
| `x_pin_evidence` | relationship | string | which anchoring check applied to an edge the pin pass emitted: `cosentence`, `window:N`, `unanchorable` or `unchecked` | [api.md](api.md) (relationship policy) |
| `x_temporal_assertions` | relationship | array | the dates the source gave for the relationship, each with its role, verbatim text, value and status | [ADR-0063](adr/0063-relationship-dates-keep-what-the-source-said.md) |
| `x_source_published` | report | object | the document anchor that dates the source: its `value`, and its `source` and `detail` when set (never a file-metadata anchor) | [ADR-0063](adr/0063-relationship-dates-keep-what-the-source-said.md) |
| `x_synthesis_stats` | report | object | the counters of the pin pass and of Stage 4b | [stix-output.md](stix-output.md) |
| `x_opencti_files` | report | array | the source file, which OpenCTI attaches to the Report on import | [stix-output.md](stix-output.md), ADR-0093 |
| `x_ctiparsor_enrichment` | report | object | on a baseline Report re-issued by enrichment: the baseline's sha256 and bundle id, the build time, the counts and the synthesis statistics | [stix-output.md](stix-output.md#enriched-bundle-adr-0090), [ADR-0090](adr/0090-enriching-an-existing-stix-bundle.md) |
| `x_cvss_v3_score` | vulnerability | number | the CVSS v3 score added by CVE enrichment (Stage 2f) | [configuration.md](configuration.md#cve-enrichment-stage-2f) |
| `x_cvss_v3_vector` | vulnerability | string | the CVSS v3 vector, when the record has one | [configuration.md](configuration.md#cve-enrichment-stage-2f) |

What is stable, and what is not:

- **Stable** ([support-policy.md, STIX output](support-policy.md#stix-output)):
  the property's name, its JSON type and its meaning. Removing or renaming one,
  or changing its type, is a breaking change. A new property is not.
- **Not recorded by the contract:** the keys inside an `array` or an `object`
  value. The contract holds `array` for `x_temporal_assertions` and `object` for
  `x_ctiparsor_enrichment`, nothing more. Their inner keys are described in the
  ADRs and shown in the examples below; whether the policy's promise covers
  each inner key is not qualified.
- **Varies, and is not a breaking change:** which objects and relationships a
  report yields, their `confidence`, the generated text, the ids of
  relationships and of the Report ([support-policy.md](support-policy.md#stix-output)).
  A consumer must not key on those.
- **Ids.** A domain object, an indicator or a marking has a deterministic id
  ([ADR-0066](adr/0066-stix-ids-are-opencti-standard-ids.md)); a relationship
  and the Report have a random one. `contract/stix.json` records the ids of the
  reference bundles' objects: a changed id is a breaking change. An object that
  an enriched bundle keeps from the baseline keeps the upstream's id and is not
  recorded.
- **A consumer ignores what it does not know.** A new `x_` property is
  compatible ([support-policy.md](support-policy.md#breaking-changes-and-deprecation)).
- **OpenCTI drops the bundle's `x_` properties** on import, except that it
  attaches the file of `x_opencti_files`
  ([support-policy.md](support-policy.md#capability-matrix), Import into
  OpenCTI). A consumer that needs the evidence label reads the exported bundle,
  not OpenCTI.

### Examples

Taken from `tests/fixtures/stage4_reference/expected/apt_report.json`, the
reference bundle that `tests/test_stage4_reference.py` keeps equal to the code
(the file holds `objects` and a `ledger`; the times are replaced by
`<build-time>`).

A relationship the report states, with its evidence and one temporal assertion
(`relationship--R22`):

```json
{
  "relationship_type": "uses",
  "x_evidence_label": "reported",
  "x_evidence_text": "The attachment dropped a loader called SUNBURST.",
  "x_temporal_assertions": [
    {"anchor": "explicit", "id": "t-start-01", "origin": "llm",
     "precision": "day", "qualifier": "none", "role": "start",
     "status": "verified", "time_text": "in March 2024", "value": "2024-03-15"}
  ]
}
```

An edge graph completion inferred (`relationship--R1`), which names its premises:

```json
{
  "x_evidence_label": "inferred",
  "x_inference_rule": "transitive:uses+uses",
  "x_inferred_from": ["relationship--R22", "relationship--R17"]
}
```

An edge a relationship-policy rule added
(`tests/fixtures/stage4_reference/expected/policy_pin.json`):

```json
{
  "x_evidence_label": "assessed",
  "x_pin_evidence": "cosentence",
  "x_policy_rule": "malware drops file"
}
```

The Report of an enriched bundle
(`tests/fixtures/stage4_reference/expected/opencti_enriched.json`) carries
`x_ctiparsor_enrichment` with `baseline_bundle_id`, `baseline_sha256`,
`built_at`, `counts` (`baseline_dropped`, `baseline_kept`, `baseline_stated`,
`merged_into_baseline`) and `synthesis` (`completion`, `pin`).

Reading them with the standard library only; it was run on the first file
above, and printed `transitive:uses+uses <- ['relationship--R22', 'relationship--R17']`
for the first inferred edge, and `uses start 2024-03-15 day verified` for the
dated relationship:

```python
import json, sys

objects = json.load(open(sys.argv[1]))["objects"]
for o in objects:
    if o["type"] == "relationship" and o.get("x_evidence_label") == "inferred":
        print(o["x_inference_rule"], "<-", o["x_inferred_from"])
        break
for o in objects:
    if o["type"] == "relationship" and "x_temporal_assertions" in o:
        for t in o["x_temporal_assertions"]:
            print(o["relationship_type"], t["role"], t["value"], t["precision"], t["status"])
```

A bundle served by the API has the same `objects`. A consumer should first
check the `X-Bundle-Validation` header (`validated`, `unverified`), since a
bundle Stage 5 refuses is answered with 409 and not served
([support-policy.md](support-policy.md#http-api)).

## Reading the configuration contract

[`contract/config.json`](../contract/config.json) has one entry per variable of
[`.env.example`](../.env.example): `set` is true when a line sets the variable
and false when the file only shows it commented, and `values` lists the values
as written. From the file:

```json
"env AUTH_MODE":    {"set": false, "values": ["off"]}
"env LLM_PROVIDER": {"set": true,  "values": ["anthropic"]}
```

`AUTH_MODE` is commented out and shows `off`, the value a fresh install runs
with. `LLM_PROVIDER` is set to `anthropic`. The Compose layout is in the same
file: the project name `ctiparsor`, each service with its profiles (`app` and
`postgres` have none; `proxy`, `bootstrap`, `ollama` and `backup` have their
own) and the named volumes.

What it guarantees: the name of a variable, its meaning and the values it
accepts are stable. A changed default is allowed in a minor release when the
CHANGELOG names it, and the contract classes a changed `set` or `values` as a
`default` difference. Removing a variable is breaking. Two variables are left
out on purpose: `SKIP_HEAVY_MODELS` (tests only) and
`TTP_RETRIEVAL_EXCLUDE_CITED` (the evaluation). The default values of
calibrated settings, and the default model of a stage or a provider, are
recorded but not promised
([support-policy.md, Configuration](support-policy.md#configuration)).
[configuration.md](configuration.md) describes each variable; where it and
`.env.example` differ, `.env.example` wins.

## Changing a recorded surface (forks and contributors)

The procedure is the one `CONTRIBUTING.md` and
[TESTING.md](../TESTING.md#the-stable-contract-adr-0094-item-1) give. The
Python commands run inside the project's containers or its WSL environment
([development.md](development.md)).

1. Make the change in the code.
2. Check what the contract sees:
   `python scripts/contract.py check` prints one line per difference with its
   severity (about 90 s on a `/mnt/c` checkout, TESTING.md).
3. Record it: `make contract`, and commit `contract/` with the change.
   `make contract` runs `scripts/contract.py write` in the `dev` container. It
   refuses a breaking change unless you add `ACCEPT_BREAKING=1`, which after
   1.0 needs a major version and a CHANGELOG entry. Recording a change does not
   approve it.
4. Run `tests/test_contract.py` (and `tests/test_contract_rules.py`,
   `tests/test_contract_cli_config.py`, `tests/test_contract_stix.py`
   if you changed an extractor).

By kind of change:

| You want to | Do | The contract sees |
|---|---|---|
| Add a variable | add a line to `.env.example`: `NAME=value` to set it, or `# NAME=value` (one space, no blank in the value) to show a default; document it in [configuration.md](configuration.md) | `compatible`: a new `env NAME` entry |
| Change a default | change the value in `.env.example` and the code's fallback together | `default`: name it in the CHANGELOG, with the value that restores the old behaviour |
| Rename or remove a variable | not allowed in a minor release after 1.0 | `breaking` |
| Add a custom STIX property | write it in Stage 4, then regenerate the reference bundles: `UPDATE_STAGE4_REFERENCE=1 SKIP_HEAVY_MODELS=1 python -m pytest -q tests/test_stage4_reference.py`, then `make contract`. The extractor reads the reference bundles: a property no scenario emits is not recorded | `compatible`: a new `property <type> <name>` entry |
| Change a property's JSON type | same regeneration | `breaking` when the property may now hold a type it did not before; `compatible` when it narrows (`_types_change`, response side) |
| Change an identity rule | regenerate the references; a changed id | `breaking` |
| Add a route or a response field | the OpenAPI schema changes | `compatible`, except a required parameter or field added to a request that already exists (`breaking`) |

A line of `.env.example` that looks like a variable but is prose (for example a
command line in a comment) makes `tests/test_contract_cli_config.py` fail, with
`test_every_commented_variable_is_read_or_named_as_prose`: write the prose so it
does not start with `# NAME=`, or add it to that test's list of named prose
lines.

A change to Stage 4 or 5 that changes the output also adds a `BUNDLE_AFFECTING`
entry in `pipeline/bundle_revisions.py`, in the same pull request (TESTING.md,
*Stage 4 reference bundles*; `tests/test_bundle_staleness.py`).

## What the contracts do not catch

From [support-policy.md](support-policy.md#stable-surfaces) and
[1.0-readiness.md](releases/1.0-readiness.md) (gate `contract`):

- the response fields of an operation whose schema declares none (11 of the 78
  operations on 2026-11-12, per the readiness record), and the 409 body of a
  refused bundle, which route tests check but the contract does not record;
- the keys inside the `array` and `object` values of the custom properties;
- only `.env.example` is read, not the code: a variable the code stops
  reading, or a code default that no longer matches the file, is not caught;
- the ids a baseline's objects keep as received;
- `scripts/`, `python -m evaluation`, `python -m api.migrate`, the SQL schema
  and an import of `pipeline/`, `api/` or `models/` from your own code are not
  interfaces.

The missing contract work is tracked in
[#657](https://github.com/Stixaly/CTIParsor/issues/657); this page does not
close it.

## Official image and fork

**Only the Docker Compose install is supported**
([ADR-0054](adr/0054-full-docker-installation.md);
[support-policy.md](support-policy.md#what-10-does-not-promise)). This is a
limit, not a recommendation to leave it: a host install, a Python package and
`pipeline/` as a library are not supported
([support-policy.md](support-policy.md#capability-matrix)).

| | Official image | Fork or local build |
|---|---|---|
| What you run | `ghcr.io/stixaly/ctiparsor` by digest, built once by `ci.yml` and published as the image CI tested ([releasing.md](releasing.md#the-image-mains-ci-publishes)) | an image built with `docker compose build` from a clone ([README](../README.md#quick-start): at a release tag, with no `CTI_IMAGE` in `.env`) |
| Provenance | `gh attestation verify oci://ghcr.io/stixaly/ctiparsor@sha256:<digest> -R Stixaly/CTIParsor --signer-workflow Stixaly/CTIParsor/.github/workflows/ci.yml --source-ref refs/heads/main` ([releasing.md](releasing.md#verifying-a-release)) | that command names `Stixaly/CTIParsor`'s workflow: it describes the project's image, not your build. A build of your own has no provenance in this repository's documentation |
| Contract | the CI run of the release commit passes `tests/test_contract.py` | `python scripts/contract.py check` on your tree tells you what differs from `contract/`; the guarantee of the support policy covers the project's releases, not your changes |
| Upgrade | [upgrading.md](upgrading.md); CI migrates a database written by the last release (`scripts/check_migration_from.py`) | the same steps for the project's code. A fork's own migrations, or a fork that changes the schema: not qualified, no page describes it |
| Qualification (clean install, OpenCTI import, failure recipe) | run on the project's image ([1.0-readiness.md](releases/1.0-readiness.md)) | not run on a fork: not qualified |

A fork that adds or changes a variable or a property follows
[the procedure above](#changing-a-recorded-surface-forks-and-contributors). A
fork that changes the schema of the API, the stages' output or the migrations
is outside what the support policy covers.
