# ADR-0100: A local vLLM is the qualified LLM configuration of 1.0

**Status:** Accepted (2026-11-13). Amends ADR-0094 decision 13 (the default
provider gets a recorded run before 1.0). ADR-0094's status line is left as
written.
**Date:** 2026-11-13
**Deciders:** maintainer
**Amends:** ADR-0094 decision 13 and item 11
**Relates to:** ADR-0094 (decisions 13 and 14, items 11 and 12), ADR-0097 (the
TLP egress policy), ADR-0099 (Stage 2d off by default), the
[in-house measurement](../eval/inhouse-bundle-2026-11.md) of 2026-11-08 to
2026-11-10

## Context

ADR-0094 decision 13 named `anthropic` the default `LLM_PROVIDER` and required
one recorded run of it before 1.0 (item 11: twice at `LLM_TEMPERATURE=0`, on
AnnoCTR test and on the in-house set, with figure reading on). That run has not
been started. Its only evidence is the fake-client tests
(`tests/test_stage3_calls.py`, `tests/test_stage3_providers.py`).

What the repository holds on 2026-11-13:

- Every evaluation run recorded in `docs/eval/` that calls an LLM used vLLM
  serving `Inferact/Qwen3.8-27B-NVFP4`, thinking off. The in-house measurement
  of 2026-11-08 to 2026-11-10 (the candidate `fe0b0f3` and `5aa3e32`, 8 reports)
  ran on that server at `LLM_TEMPERATURE=0`, `LLM_SEED=13`, with figure reading
  off (`VISION_PROVIDER=none`). Figure reading has not been measured with this
  model.
- The shipped `.env.example` sets `STIX_TLP=amber`. ADR-0097 sends text and
  figures to an external provider only for TLP:CLEAR and TLP:GREEN. Under the
  shipped setting, `anthropic` is refused for every report, so the default
  provider cannot run on a default install's AMBER reports at all.
- A local vLLM is a local provider when its base URL is a private or loopback
  address, or a name in `LLM_LOCAL_HOSTS` (`docs/configuration.md`, egress
  policy). Its text and figures then pass the TLP check for every level.

On 2026-11-13 the maintainer decided the qualified configuration for 1.0.

## Decision

**1. The qualified LLM configuration of 1.0 is a local vLLM serving
`Inferact/Qwen3.8-27B-NVFP4`, for the text and for the figures.** Its settings
are those of the recorded runs and of the maintainer's configuration:

| Setting | Value |
|---|---|
| `LLM_PROVIDER` | `vllm` |
| `VLLM_BASE_URL`, `VLLM_MODEL` | the server's address; `Inferact/Qwen3.8-27B-NVFP4` |
| `VLLM_ENABLE_THINKING` | `false` |
| `LLM_TIMEOUT` | `600` |
| `LLM_TEMPERATURE`, `LLM_SEED` | `0`, `13` (the sampling of the recorded runs; the seed reaches vLLM only) |
| `VISION_PROVIDER` | `vllm` (figures read by the same server) |
| `WORKER_JOB_TIMEOUT` | `3600` (added 2026-11-14, see below) |

`LLM_TEMPERATURE` and `LLM_SEED` are not in the maintainer's list of 2026-11-13.
They are added here because the recorded runs used them and
`docs/support-policy.md` requires them for repeatable runs.

`WORKER_JOB_TIMEOUT=3600` was added by the maintainer on 2026-11-14. On the 1.0
candidate `ee7847f`, the model journey's PDF ([1.0-model-journey.md](../releases/1.0-model-journey.md))
was stopped at 1,932 s by the default limit of 1,800 s, in the last chunk of Stage 3. Reading its
21 figures took 408 s of that time. The journey of 2026-11-09 passed with figures off.
The default stays 1,800 s: a hosted model rarely needs more.

**2. Anthropic stays supported as an option, not qualified.** Its code path,
its settings and its tests stay. Its recorded run (item 11) is no longer a gate
of 1.0.

**3. The gate `default_provider_measured` now means a recorded run of the
qualified configuration with figure reading on**: vLLM serving
`Inferact/Qwen3.8-27B-NVFP4` under the settings of decision 1, figures on, the
extraction measured on the exported bundle with its spread published. The gate's
key in `docs/releases/1.0-readiness.md` is kept.

**4. `.env.example` does not ship the qualified configuration.** It names the
maintainer's LAN address, which no other install has. The shipped file keeps
`LLM_PROVIDER=anthropic` with no key, and `STIX_TLP=amber`: as shipped, Stage 3
is skipped and the pipeline still produces a bundle from the offline stages.
The configuration is written in `docs/configuration.md` instead.

## Alternatives rejected

- **(a) Keep `anthropic` as the qualified default.** It needs a billed run of
  two rounds on two sets, and the shipped `STIX_TLP=amber` refuses it, so the
  default journey would not use it anyway.
- **(b) Ship the qualified configuration in `.env.example`.** The address would
  be the maintainer's, and a `.env` written from the example would point at a
  server that does not exist elsewhere.
- **(c) Qualify two providers for 1.0.** Each needs its own runs and its own
  gate; the maintainer chose one.

## Consequences

- **Gates.** `default_provider_measured` is `not_run` until a figures-on run of
  the qualified configuration is recorded. The in-house runs of 2026-11-08 to
  2026-11-10 do not satisfy it: they used the same server and sampling but
  `VISION_PROVIDER=none`. `figure_reading_default` keeps its meaning (figures on
  by default, skipped without a provider able to see); the qualified
  configuration reads figures through the same server.
- **Which runs count.** The readiness record keeps item 11's form for the gate
  (two runs at temperature 0, the spread published) until the maintainer
  changes it. Whether AnnoCTR test is read again for this gate is a new decision
  under ADR-0060, which allows one reading of test per decision; the October runs
  already read it with this server. The maintainer decides.
- **Measurement tooling.** `scripts/measure_default_provider.py` defaults to this
  configuration (`--provider vllm`), and keeps the billed anthropic option as
  `--provider anthropic`. Its runs are named `qualified-vllm-*`.
- **Egress.** A vLLM server on a private address is local: its text and figures
  may go to it for an AMBER, AMBER+STRICT or RED report. A server named by a
  host name must be listed in `LLM_LOCAL_HOSTS`, or it is external and refused.
- **Dependency on one server.** The qualification covers one model, one
  quantisation (NVFP4) and one server on the local network. A different model,
  server or hardware is not qualified by it.
- **Anthropic.** Its documentation says `supported`, not `qualified`. The
  shipped default `LLM_PROVIDER` does not change, so the default install and the
  contract snapshot (`contract/config.json`) are unchanged.
- **Support policy.** The capability rows of vLLM and of figure reading with the
  qualified configuration are `partly` until the figures-on run is recorded.
  `docs/support-policy.md` and `docs/releases/1.0-readiness.md` carry the detail.

## What would reverse it

- A figures-on run of the qualified configuration whose extraction on the
  in-house set falls below the figures-off runs of 2026-11-08 to 2026-11-10. Then
  figure reading is changed or left off by default, as a decision of its own.
- The maintainer's choice of another provider for 1.0.

## Limits

The in-house set holds 8 reports, annotated with AI assistance and arbitrated by
one maintainer. Every recorded run used one server and one model, with thinking
off. Figure reading has no run with this model.
