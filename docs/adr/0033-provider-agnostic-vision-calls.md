# ADR-0033: One vision call, three providers — capability-gated, schema-constrained

**Status:** Proposed
**Date:** 2026-08-28
**Deciders:** maintainer
**Amends:** ADR-0032 §3, which said Stage 1f's model "comes from `LLM_PROVIDER`,
exactly as Stage 3's does". That is wrong; this ADR says why and what replaces it.

## Context

### Stage 1f cannot reuse Stage 3's provider config

Three reasons, all measurable.

**The Stage-3 defaults have no vision.** `OLLAMA_MODEL` defaults to `llama3.2` in
`stage3_llm.py`, and `mistral` in `.env.example`. Neither is multimodal, and
neither is even pulled on the station — `/api/tags` lists exactly one model,
`qwen3.8:latest`. Point Stage 1f at the documented default and it reads nothing.

**Even the correct default is the wrong model.** `ANTHROPIC_MODEL` defaults to
`claude-sonnet-4-6`, which does have vision. But ADR-0032's comparison puts
Haiku 4.5 ahead of Opus 5 on triage (3/3 against 2/3) at **$0.0027 per figure
against $0.028**. Coupling Stage 1f to Stage 3's model buys a worse triage at ten
times the price. The best model for enriching a chunk of prose and the best model
for transcribing a console screenshot are not the same model, and there is no
reason the config should pretend otherwise.

**A text-only model handed an image does not raise.** It answers. That is the
failure this design exists to make impossible.

### The three transports are two

| provider | image transport | structured output | measured |
|---|---|---|---|
| anthropic | `image` block, base64 + `media_type` | `output_config.format` json_schema | 4.7 s ✓ |
| ollama | `/v1/chat/completions`, `image_url` data URI | `response_format` json_schema | 11.7 s ✓ |
| mistral | same shape as ollama | same | **unverified — no key on this host** |

Ollama's OpenAI-compatible route accepts images. **Mistral and Ollama are
therefore one code path**, and only Anthropic needs its own.

### Schema, not prose, is what keeps the keys stable

Same image, same question, three routes on the station:

| call | what came back | latency |
|---|---|---|
| `/v1` + `response_format: json_object` | invented the key **`first_2_text_lines`** | 17.3 s |
| `/v1` + `response_format: json_schema` | returned the requested **`lines`** | 11.7 s |
| `/api/chat` + `format: <schema>` | returned **`lines`** | 8.6 s |

Key drift is not hypothetical in this codebase: `stage3_llm.py:673-680` exists
purely to rename an `evidence_text` key the model spelled differently. A schema
deletes that whole class of repair code.

`/api/chat` is the fastest, and it is Ollama-only. `/v1` is what Mistral also
speaks. Three seconds a figure is the price of one code path instead of two.

### Every provider will say whether the model can see

- **anthropic** — `models.retrieve(m).capabilities["image_input"]["supported"]`;
  verified `True` for `claude-opus-5`, `claude-haiku-4-5`, `claude-sonnet-4-6`.
- **ollama** — `/api/tags` → the model's `capabilities` list contains `"vision"`;
  verified on `qwen3.8:latest`.
- **mistral** — `/v1/models/{m}` → `capabilities.vision`; documented, unverified.

So the guard is not a hardcoded model list that goes stale. It is a question each
provider already answers.

Two caveats found while checking Mistral. Its documented vision models moved —
**Pixtral 12B and Pixtral Large are retired**, and the current vision-capable
names are `mistral-large-latest` and `ministral-14b-latest`. And its published
API reference does not show the `/v1/models` response schema, so whether
`capabilities.vision` exists on that object is documented nowhere I could reach.
Both facts argue for the same thing: no invented default, and a probe whose
failure is safe.

### The crop rule is not an Anthropic rule

ADR-0032 concluded "send the crop, never the page" from a 1:15 web capture that
qwen3.8 read as blank and the Anthropic API rejected at 8000 px. Mistral
publishes the same class of limit — 10 MB per file, an error above 10000 × 10000,
and silent downscaling to the model's maximum resolution below that.

Three providers, three ceilings, one conclusion. The rule is a property of how
VLMs ingest images, not of any one vendor, and it does not need re-deciding per
backend.

## Decision

### 1. Stage 1f gets its own provider and model

```
VISION_PROVIDER        none (default) | anthropic | mistral | ollama
VISION_MODEL           per-provider default; REQUIRED for mistral
VISION_TIMEOUT_S       120
VISION_ASSUME_CAPABLE  unset; waives the capability probe (see §3)
```

`python -m pipeline.vlm [figure.png]` answers "will Stage 1f run, and if not,
why" without starting the pipeline. Every refusal names its cause — a missing
Ollama model prints the ones that *are* pulled:

```
WARNING Ollama model llama3.2 not found at http://192.168.0.29:11434
        — pulled models: ['qwen3.8:latest']
RESULT: no usable vision backend — Stage 1f would be skipped.
```

`none` by default, because ADR-0032 makes Stage 1f opt-in per job.
`OLLAMA_BASE_URL` and `MISTRAL_API_KEY` are shared with Stage 3 — the endpoint
and the credential are the same, only the model differs.

**`mistral` has no default model on purpose.** The vision-capable Mistral model
names were not verified against a live account, and CLAUDE.md's own lesson is
that an invented constant table produces perfect code doing the wrong thing.
An unset `VISION_MODEL` under `mistral` fails with a message that says so,
instead of a capability probe failing on a model name nobody chose.

### 2. Two backends behind one Protocol

```python
class VisionBackend(Protocol):
    name: str
    model: str
    max_concurrency: int
    def available(self) -> bool: ...
    def read_figure(self, png: bytes, prompt: str = PROMPT) -> FigureRead: ...
```

`AnthropicVisionBackend` and `OpenAICompatVisionBackend(name, base_url, model,
api_key)` — the second serves both Mistral and Ollama. `get_backend()` reads the
env, builds one, probes it, and returns `None` if it cannot see.

### 3. A failed capability probe disables the stage, it never degrades it

`available()` mirrors `BaseExtractionStage.available()` — the contract
`StageRegistry` already uses to skip an extractor whose model will not load.
Probe says no, or the probe itself fails: log a warning naming the
provider/model, return `None`, and Stage 1f does not run.

The alternative — send the image and hope — is the one outcome that must be
impossible, because its failure is a confident invented transcription injected
into `report_text` as `observed` evidence.

`VISION_ASSUME_CAPABLE=1` waives the probe. It exists because Mistral's
`/v1/models` schema is undocumented and a provider we cannot interrogate should
not be unusable to an operator who knows their model sees. It is one env var
with no default and no per-provider variant, and it logs a warning every time it
fires: waiving the guard is a decision made once, knowingly, for a deployment.

**This gate earned its keep during its own validation.** The first
implementation read `capabilities["image_input"]["supported"]` — a spec defect,
mine: the SDK returns a Pydantic `ModelCapabilities`, which is not subscriptable,
and the earlier manual probe had only looked like a dict because it went through
`.model_dump()`. Every Anthropic probe raised `TypeError`. The stage disabled
itself and no image was ever sent. Failing closed is what turned a wrong
assumption into a log line instead of a corpus of invented evidence.

### 4. Every call carries `FIGURE_SCHEMA`

One schema, passed through each provider's own structured-output mechanism.
`PROMPT_VERSION` is bumped whenever the prompt or schema changes, and is part of
the cache key, so a stored read is never served against a contract it did not
answer.

The prompt carries one instruction earned by measurement: *"Never infer an edge
from two elements merely being adjacent."* Both qwen3.8 and Opus 5 produced the
identical three invented UI-flow edges on a screenshot montage (ADR-0032), so
this is a shared failure mode, not a model weakness — a prompt is the only place
to address it.

### 5. Concurrency belongs to the backend

Ollama is `max_concurrency = 1`: one GPU, and that GPU is also the delegation
target this project's whole workflow depends on. API backends get 4. The caller
reads the number off the backend rather than holding a policy of its own.

### 6. A read that fails is `kind="unread"`, and the job continues

Every error path — HTTP, timeout, unparseable payload, wrong types — returns a
`FigureRead` with `kind="unread"` and `error` set, never an exception. The figure
gets its marker block in `report_text` with empty content, so `char_start` and
`char_end` stay well-defined and nothing downstream shifts.

Retries happen **inside** ingestion. There is no post-hoc patching of an unread
figure, because inserting content later would move every offset after it — the
one thing ADR-0032's whole design depends on not happening.

### 7. Nothing the model returns is trusted

`_to_read` validates every field: an unknown `figure_kind` becomes `none`,
non-string entries are dropped from the string lists, a `verbatim_text` that
is not a list becomes `[]`, an edge missing `src` or `dst` is discarded, a
non-string `label` becomes `""`. This is the defect family CLAUDE.md lists first
— *garde de type manquante sur entrée non fiable* — and the input here is a
language model's JSON, which is exactly as untrusted as a YAML key.

## Consequences

- **A second provider matrix to keep working.** Stage 3 has one, Stage 1f now has
  another, and they can drift. Mitigated by sharing the endpoint and credential
  env vars, so only the model differs.
- **Mistral is designed for and unverified.** The code path is the one Ollama
  proved; the capability probe shape is documented, not measured. First run
  against a real key is a test, not a deployment.
- **Structured output is assumed available.** Verified on Anthropic (the
  capability endpoint reports `structured_outputs.supported: True`) and on
  Ollama. A provider that silently ignores `response_format` falls back to
  `_parse_payload`'s fence-stripping, which is why that function stays.
- **The `/v1` route ignores `think: false`.** A thinking model spends its token
  budget on reasoning before writing any JSON, so `_MAX_TOKENS` is 4000 rather
  than the few hundred the schema needs. This is already in CLAUDE.md's
  troubleshooting table; it is now also a documented constant.
- **What gets harder.** Changing `PROMPT` or `FIGURE_SCHEMA` invalidates the read
  cache for every stored figure, and comparing two models now means comparing two
  cache generations. That is the correct behaviour and it is still a cost.

## Validation

Same figure — the FortiGate console page from ADR-0032 — through one interface,
`python -m pipeline.vlm <png>`:

| backend | kind | text runs | observables | latency |
|---|---|---|---|---|
| `ollama/qwen3.8` | `screenshot` | 54 | 3 | 45.0 s |
| `anthropic/claude-haiku-4-5` | `screenshot` | 55 | **1** | 12.3 s |

The observable counts differ and neither has been checked against ground truth;
that is a measurement ADR-0032's crop work should make, not a claim this one
makes.

The gate was exercised on all four refusal paths — provider unset, model not
pulled, Mistral without a model, and the Pydantic bug above — and each names its
own cause. 16 unit tests, and the three that guard the critical behaviours
(capability probe, type filtering, unknown `figure_kind`) were verified by
reintroducing each defect and confirming the matching test, and only that test,
fails.

## Still open

- **The read cache is specified but not designed here.** Keyed on
  `(sha256, model, PROMPT_VERSION)`; whether it lives beside `report_figures` or
  in its own table is an ADR-0032 question, not this one.
- **No provider is benchmarked on crops.** Every latency above is a full page.
  ADR-0032's first open measurement — crop against page — has to run before any
  of these numbers become a budget.
- **`ANTHROPIC_MODEL` still defaults to `claude-sonnet-4-6` for Stage 3.** That is
  out of scope here, but it is an older default than the account can reach.
