# REST API

Every route the FastAPI server exposes. The interactive OpenAPI docs are served
by the running app at `http://localhost:8000/docs`.

## Jobs

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/upload` | Upload a file (multipart `file=`) and queue it. Returns `{ job_id, filename, status }`, `status` being `queued` or `processing`; 503 when the queue is full. Optional `baseline_stix` (a file) and `baseline_report_id` (a form field): a STIX 2.1 bundle to enrich (below) |
| `POST` | `/api/ingest/text` | Ingest pasted text (JSON `text`, optional `title`). Stored `.html`, `.md` or `.txt` by content — pasted markup is stripped, not ingested raw. 20 chars min, 2 MB max. Optional `baseline_bundle` (the TEXT of the STIX file) and `baseline_report_id` |
| `POST` | `/api/ingest/url` | Render a URL with headless Chromium (JSON `url`, optional `enable_js`). Writes `{job_id}.pdf` (archive, shown in Review) and `{job_id}.txt` (rendered DOM text, ingested). 400 policy refusal · 502 unreachable or blank render · 503 Playwright absent · 504 timeout. Optional `baseline_bundle` and `baseline_report_id`, checked before the capture |
| `GET` | `/api/jobs` | List all jobs (with `pipeline_mode`) |
| `GET` | `/api/jobs/{id}` | Get a single job (includes entity/relationship counts, `pipeline_mode`, and for an `enrich` job an `enrichment` block, below) |
| `GET` | `/api/jobs/{id}/baseline` | The STIX bundle the job was created from, as received, as a JSON download. 404 for a job with none |
| `GET` | `/api/jobs/{id}/baseline/intake` | What the intake made of that bundle, whole: every object left out and why. 404 for a job with none |
| `PATCH` | `/api/jobs/{id}` | Update status. 409 for `completed` while the stored bundle is one Stage 5 refused (below) |
| `DELETE` | `/api/jobs/{id}` | Delete job, all DB rows, and all associated files |
| `POST` | `/api/jobs/{id}/finalize` | Re-run Stages 4–5 on the accepted rows and store the bundle; sets status `completed`. `?quick=true` rebuilds the bundle and leaves the status alone (the rebuild the UI schedules after each edit). Returns `{ status, bundle_size, validation }`, `validation` being `validated`, `unverified` or `unknown` (Stage 5 did not run). 409 when Stage 5 refuses the rebuilt bundle (below). Two finalizes of one job can overlap: a build never replaces a bundle built from newer rows (below) |
| `GET` | `/api/jobs/{id}/bundle` | Download the STIX 2.1 bundle JSON. The header `X-Bundle-Validation` carries Stage 5's verdict: `validated`, `unverified` (the JSON schemas were missing) or `unknown` (built before the verdict was stored). 409 when Stage 5 refused the bundle (below) |
| `GET` | `/api/jobs/{id}/bundle/ledger` | What Stage 4 did with each entity and relationship row when it built the stored bundle (ADR-0061): what each became, what was rewritten or dropped and why, why each generated object exists. 404 when the bundle predates the ledger — a quick finalize writes one |
| `GET` | `/api/jobs/{id}/source` | Stream the original uploaded file |

Job status lifecycle: `uploaded` → `queued` → `processing` → `for_review` → `reviewing` → `completed` / `failed`. A job whose worker stops heartbeating goes back to `queued` (ADR-0046).

### A bundle Stage 5 refuses (ADR-0084)

Stage 5's verdict is stored with the bundle (`jobs.bundle_validation`,
`jobs.bundle_validation_errors`). When it is `invalid`, three routes answer
**409** with the same body, and no route completes the job:

```json
{ "detail": { "validation": "invalid", "errors": ["…", "…"] } }
```

`errors` are the validator's first 20 messages, each cut to 500 characters. The
code is 409 and not 422, which FastAPI keeps for a request that fails
validation, with a list as `detail`.

| Route | On an invalid bundle |
|---|---|
| `GET /api/jobs/{id}/bundle` | 409: the bundle is not served, by the graph view or the download |
| `POST /api/jobs/{id}/finalize` (`quick` or not) | 409. The rebuilt bundle is stored with its verdict, and the job is not completed: a `completed` job goes back to `for_review`, any other status stays |
| `PATCH /api/jobs/{id}` with `{"status": "completed"}` | 409. Every other status is accepted |

`GET /api/jobs/{id}/bundle/ledger` ignores the verdict. A finalize whose
bundle Stage 5 accepts replaces it. A bundle built before the verdict was
stored (or when Stage 5 did not run) has none: it is served as before, with
`X-Bundle-Validation: unknown`.

### Two finalizes of one job (ADR-0086)

The review page schedules a quick finalize 4 s after each edit, and the
Finalize button runs another, so two can overlap. Each reads the job's rows in
one snapshot, with the job's `review_revision` (a counter bumped by every write
to its entities and relationships), and publishes its bundle, ledger, verdict
and build record in one conditional `UPDATE`. A build whose rows are older than
the stored bundle's is refused:

- nothing is published, and the response describes the **stored** bundle
  (`bundle_size`, `status`, `validation`);
- a full finalize completes the job with that stored bundle, unless its verdict
  is `invalid`; in that case the 409 above carries the **stored** errors;
- the refused build's own verdict acts on nothing.

The status codes and the shape of the response do not change. Each stored
bundle names the build that made it in `jobs.bundle_build_json` (kind `run`,
`finalize` or `quick`, time, `git_rev`, policy, the captured environment
variables, manifest).

### Enriching a STIX bundle the analyst already holds (ADR-0090)

The three ingestion routes accept, besides the report, a STIX 2.1 bundle (the
*baseline*), and the job starts in `enrich` mode (`jobs.pipeline_mode`). The
mode is on by default; `STIX_ENRICHMENT_ENABLED=false` turns it off
(`docs/configuration.md`). With it off, a request that carries a baseline answers **400**
`STIX enrichment is not enabled on this server`, without reading it, and a
request without one is unchanged. An `enrich` job already created keeps
running and serving its baseline when the flag is turned off: the mode is
stored on the job, and only new requests are refused. The pipeline uses the
baseline: Stage 3r reconciles the extractions with it, and Stage 4 merges it
into the bundle (ADR-0090).

- `baseline_stix` (`/api/upload`, multipart) or `baseline_bundle`
  (`/api/ingest/*`, JSON string): the bundle. `baseline_bundle` is the **text**
  of the file, since the `sha256` kept is of the bytes received. An empty or
  blank bundle (and an empty `baseline_report_id`) is no baseline. The cheap
  checks on the report come first (its length for pasted text, its size for an
  upload, the URL), then the baseline is read; for a URL it is read before the
  capture, and for an upload a refused baseline removes the report file it
  came with. Nothing is stored for a request that is refused.
- `baseline_report_id`: which Report of the bundle to enrich. Required when the
  bundle holds several (**400** listing them); **400** when the bundle does not
  hold it, and when it is sent without a baseline. A bundle with no Report is
  taken whole.
- **400** when the bundle cannot be used: not UTF-8, not JSON, not a STIX 2.1
  bundle (a 2.0 one, or objects without `spec_version`), more than 10 000
  objects, a `baseline_report_id` the bundle lacks, or a chosen Report that
  stix2 refuses. **413** over 20 MB. **503** when two other bundles are being
  read already (at most two at a time per server process, whichever route they
  come by; a request waits up to 30 s for a slot): retry. An invalid *object*
  does not refuse the bundle: it is left out, with a `WARNING` log line
  (`[baseline] job <id>: dropped invalid STIX object …`, the first 200 of them,
  then one line counting the rest) and an entry in the job's intake.
- **400** when the job's `tlp_level` (or `pap_level`) is lower than the most
  restrictive marking the baseline carries. With no `tlp_level` the job gets the
  more restrictive of that minimum and the server's default `STIX_TLP` (AMBER
  when unset), so a baseline never makes a job less restricted than a job
  without one; with no `pap_level` it gets the baseline's minimum, PAP having no
  default.
- The request checks the bundle against the stix2 library only; it does not
  run the JSON schemas, so an object only they refuse is still imported at
  that point. The worker runs them (seconds per thousand objects) when the job
  starts, once, and leaves out the objects they refuse; if they refuse the
  chosen Report itself, **the job fails** with that reason (a `WARNING` in the
  log, no traceback). `enrichment.validated` says whether the worker has done it.

`GET /api/jobs/{id}` of an `enrich` job adds:

```json
"enrichment": {
  "intake": { "sha256": "…", "counts": {"malware": 3, "out_of_scope": 0}, "excluded": [{"id": "…", "type": "…", "reason": "baseline_invalid", "detail": "…"}], "excluded_total": 1, "warnings": [], "reports": [], "scope_report_id": "report--…", "min_tlp": "AMBER", "min_pap": null },
  "validated": false,
  "counts": { "entities": {"baseline_only": 2}, "relationships": {} }
}
```

`excluded` holds the first 200 objects left out and `excluded_total` how many
there are; `GET /api/jobs/{id}/baseline/intake` returns the whole stored intake
(404 for a job with no baseline). `counts` is the number of rows by
`enrichment_status` (`new`, `matched`, `baseline_in_text`, `baseline_only`); it
is empty until Stage 3r writes them. The bundle itself is not in the response.

### Baselines

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/baselines/status` | `{ "enabled": bool, "max_bytes": int, "max_objects": int }`: whether `STIX_ENRICHMENT_ENABLED` is on, and the limits |
| `POST` | `/api/baselines/inspect` | What a job would make of a bundle, without creating one. Multipart `file`, optional form field `report_id`; 10 requests a minute. Returns the intake: `sha256`, `bundle_id`, `counts` by STIX type (plus `out_of_scope`, `dangling_refs`), `excluded` (`{id, type, reason, detail}`), `warnings`, `reports` (`{id, name, published, refs}`), `scope_report_id`, `needs_report_choice` (several Reports and no `report_id`: they are in `reports`), `min_tlp`, `min_pap`. 400 when the mode is off or the bundle cannot be used, 413 over 20 MB, 503 when other bundles are being read. Stores and logs nothing; runs the stix2 checks, not the JSON schemas |

## Entities

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/entities` | List all entities |
| `POST` | `/api/jobs/{id}/entities` | Create an entity manually |
| `PATCH` | `/api/jobs/{id}/entities/{eid}` | Update (`accepted`, `entity_type`, `value`, `mitre_id`). 409 when it changes `entity_type`, `value` or `mitre_id` of a row imported from the analyst's STIX bundle (`enrichment_status` `baseline_in_text` or `baseline_only`): accept or reject it |
| `DELETE` | `/api/jobs/{id}/entities/{eid}` | Remove. 409 for a row imported from the analyst's STIX bundle: reject it instead |
| `POST` | `/api/jobs/{id}/entities/accept-pending` | Accept all NULL-state entities in one query |
| `POST` | `/api/jobs/{id}/entities/bulk` | Bulk accept / reject / reset entities by type (see below) |

### Bulk entity update

```json
{ "entity_type": "malware", "action": "accept", "scope": "pending" }
```

- `action`: `"accept"` · `"reject"` · `"reset"` (back to pending)
- `scope`: `"pending"` (default, only NULL-state rows) · `"all"` (every row of that type)
- Returns `{ "updated": N, "entity_type", "action", "scope" }`

## Relationships

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/relationships` | List all relationships |
| `POST` | `/api/jobs/{id}/relationships` | Create a relationship |
| `PATCH` | `/api/jobs/{id}/relationships/{rid}` | Update (`accepted`, `source_value`, `relationship_type`, `target_value`, `evidence_text`). 409 when it changes an endpoint or the verb of a row imported from the analyst's STIX bundle, or sends a `start_time` or `stop_time` for it: accept or reject it |
| `DELETE` | `/api/jobs/{id}/relationships/{rid}` | Remove. 409 for a row imported from the analyst's STIX bundle: reject it instead |
| `GET` | `/api/jobs/{id}/relationships/valid-types` | List valid STIX relationship type strings |
| `POST` | `/api/jobs/{id}/relationships/bulk` | Accept, reject or reset several relationships in one call: `{ "ids": [...], "action": "accept" \| "reject" \| "reset" }`, at most 500 ids. Journaled as `human_bulk` (ADR-0058), which threshold calibration does not read. Returns `{ updated, action }` |

### Relationship object

```json
{
  "id": "uuid",
  "job_id": "uuid",
  "source_value": "APT29",
  "relationship_type": "uses",
  "target_value": "Cobalt Strike",
  "confidence": 0.92,
  "accepted": true,
  "evidence_text": "APT29 was observed deploying Cobalt Strike Beacon…",
  "evidence_label": "observed"
}
```

Valid `relationship_type` values: `uses`, `attributed-to`, `targets`, `indicates`, `mitigates`, `remediates`, `delivers`, `drops`, `downloads`, `exploits`, `originates-from`, `compromises`, `beacons-to`, `communicates-with`, `exfiltrates-to`, `controls`, `has`, `hosts`, `owns`, `authored-by`, `impersonates`, `located-at`, `resolves-to`, `belongs-to`, `variant-of`, `duplicate-of`, `derived-from`, `related-to`.

## Relationship policy

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/relationship-policy` | Return the current policy (or factory default) |
| `PUT` | `/api/relationship-policy` | Replace the policy (full replacement) |
| `GET` | `/api/relationship-policy/last-run` | Synthesis accounting of the newest bundle — per-rule `candidates / emitted / truncated` (ADR-0026) |

```json
{
  "version": 1,
  "global": "enforce",
  "rules": [
    { "src": "threat-actor", "verb": "uses", "tgt": "malware", "mode": "pin", "enabled": true }
  ],
  "max_pinned_edges": 200,
  "pin_budget_mode": "fair-share",
  "pin_evidence": { "mode": "cooccurrence", "window": 3 },
  "completion": {
    "alias": false,
    "reference": true,
    "transitive": true,
    "long_distance": false,
    "fuzzy_alias": false,
    "semantic_alias": false,
    "max_new_edges": 200
  }
}
```

- `global`: `"enforce"` (apply rules) · `"auto"` (ignore rules)
- `mode`: `"pin"` (lock relationship type) · `"auto"` (allow free editing)

**Factory default.** Until a policy is saved, `GET` returns
`{"version": 1, "global": "enforce", "rules": []}` and Stage 4 runs with **no
pinned rules** — only the LLM-extracted edges, the mapping helpers and Stage 4b
completion. The 27-rule model the Policy page shows on first visit is a
frontend template; it is not applied until you click Save. An `"auto"` rule
never adds an edge either — it declares the pair, nothing more. ADR-0038 moves
the default into the backend so what the page shows is what runs.

**Pin budget** (ADR-0026). A `"pin"` rule materialises every pair of its two
object types, so a single rule can generate thousands of edges;
`max_pinned_edges` bounds the total. `pin_budget_mode` decides how that budget
is split:

| Mode | Behaviour |
|---|---|
| `"fair-share"` *(default)* | max-min fair share — rules served in ascending demand order, each taking at most an equal share of the remainder, so a small rule is always satisfied in full |
| `"sequential"` | legacy first-come-first-served — the first rules in the array take everything, later ones can emit nothing |

Measured over the four bundles stored when ADR-0026 was written, switching to fair share takes
the number of rules that actually emit an edge from **20 to 46**. Every
materialised edge carries `x_evidence_label="assessed"` and `x_policy_rule`, and
the Report SDO carries `x_synthesis_stats` with the per-rule
`candidates / emitted / truncated / blocked` breakdown.

`max_pinned_edges` is a policy field but is **not offered in the Policy UI**: an
analyst cannot know the right total before reading the report, and the number
scales with report size rather than with anything they can judge. It stays as a
safety ceiling; the evidence window below is the knob the interface exposes.

**Evidence gate** (ADR-0027). `pin_evidence` decides whether a pair has to be
supported by the text at all:

| Setting | Behaviour |
|---|---|
| `"mode": "cooccurrence"` *(default)* | emit only when both objects appear within `window` sentences of each other |
| `"mode": "cartesian"` | legacy — emit every pair |
| `"window": 3` | sentence distance; reused from the ADR-0024 Phase C measurement |

The gate is **applied only to types that actually appear in prose**. Measured
over the stored bundles: SCOs, `malware`, `tool` and `threat-actor` are 91–100%
verbatim, but `attack-pattern` is 24.3% and `course-of-action` 0/344 — they come
from ATT&CK mapping, not the report — so pairs touching them always pass. An
Indicator is anchored on the values inside its `pattern` (96.3%), never on its
`name` (0%). Each emitted edge records which applied, in `x_pin_evidence`:
`cosentence`, `window:N`, `unanchorable`, or `unchecked`.

Measured effect: **18,426 → 10,278 candidate pairs**, and the share of shipped
pin edges carrying a real textual anchor goes from **0% to 32.7%**.

**`completion`** (optional) controls Stage 4b graph completion — *the analyst
specifies the link, or lets the tool decide*. A `"pin"` rule always wins over
anything inference produces, so completion never contradicts an explicit choice.

| Flag | Default | What it does |
|---|---|---|
| `alias` | `false` | **Fallback** post-hoc merge of same-object SDOs, rewiring their edges onto one node. Off because [`pipeline/aliases.py`](../pipeline/aliases.py) (ADR-0012) already canonicalises MITRE-known aliases at SDO-creation time — this only adds value for names *absent from the gazetteer*, and it is the one destructive engine. Never merges IOC-shaped names. |
| `reference` | `true` | Add MITRE-curated ATT&CK edges when both endpoints resolve to ATT&CK IDs. Labelled `reported` — expert fact, not inference. |
| `transitive` | `true` | Compose two verified edges via a fixed rule table; a composition that is not a *suggested* STIX relationship is skipped. |
| `long_distance` | `false` | Stage 4c — LLM predicts links between disconnected sub-graphs. Needs a ready LLM provider; the model must quote a supporting sentence. |
| `fuzzy_alias` | `false` | Extend the alias merge with rapidfuzz name matching (ratio ≥ 93). |
| `semantic_alias` | `false` | Extend the alias merge with embedding cosine ≥ 0.6, catching aliases with no character overlap ("the Dukes" ↔ "APT29"). No-ops under `SKIP_HEAVY_MODELS=1`. |
| `max_new_edges` | `200` | Safety cap on edges added by grounding + inference. |

Set `reference: false` for strictly report-scoped bundles: grounding asserts
*global* ATT&CK knowledge ("APT29 has used Mimikatz"), not what this report says.

## Progress (SSE)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/progress` | SSE stream. Events: `connected`, `stage`, `done`. |

```
event: stage
data: {"stage":3,"label":"LLM enrichment","chunk":7,"total":22,"malware":3,"actors":2,"relationships":8}

event: done
data: {"status":"for_review"}
```

## Coverage (detection)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/jobs/{id}/coverage` | Per-report coverage matrix: each technique's 0–3 score + contributing corpora. Scores come from the rules' ATT&CK tags; score 1 (telemetry only) is never produced, no data-source mapping is wired in |
| `GET` | `/api/jobs/{id}/coverage/rules` | Rules **backed by a value the report contains**, grouped by technique; rules carrying no ATT&CK tag (all YARA) arrive under `(untagged)`. Carries `tag_total` — what the unfiltered tag join would have returned (ADR-0030) |
| `GET` | `/api/jobs/{id}/coverage/{technique}/rules` | License-aware drill-down: which rules cover a technique |
| `GET` | `/api/jobs/{id}/detections/proposals` | Rules **ranked** on the report's observables + platform, with match evidence (ADR-0014) |
| `GET` | `/api/jobs/{id}/coverage/artifacts` | Indexed coverage on evidence (ADR-0025), scoring the report's technical content (hashes, addresses, paths, tool/malware identities) by whether a rule actually holds that value, staged by Pyramid of Pain, with the ATT&CK band carried un-scored to locate the intrusion in the kill chain. Not displayed by the UI yet |
| `GET` | `/api/jobs/{id}/detections/export` | Downloads the report's detection rules as a ZIP, filterable by repeatable `format`, `corpus`, `license`, `severity` query parameters (ADR-0020), where "detected" means canonical rules attachable to the report's accepted ATT&CK techniques, sharing the same archive constructor as the POST form |
| `GET` | `/api/jobs/{id}/detections/export/facets` | Rule counts and byte volumes per axis for the filter UI (ADR-0020), allowing operators to see volume and license distribution before downloading (e.g., 18,196 rules / 268 MB, 1,642 all-rights-reserved), returning `total: 0` rather than 404 for jobs without rules |
| `POST` | `/api/jobs/{id}/detections/export` | ZIP of exactly the rules in `{"rule_ids": [...]}` — the granular selection the axis filters cannot express (ADR-0022) |
| `POST` | `/api/rules/lookup` | Metadata for arbitrary canonical rule ids, bodies on demand (`include_body`, ≤ 500 ids). Not job-scoped — the proposals panel shows rules outside the report's tag join by construction |
| `GET` | `/api/detection-corpora` | Per-corpus rule counts in the store |

```json
// GET /api/jobs/{id}/coverage
{ "techniques_total": 12, "validated": false,
  "by_score": { "0": 4, "1": 0, "2": 5, "3": 3 },
  "cells": [ { "technique_id": "T1059.001", "score": 3, "corpora": ["sigmahq","team"], "rule_count": 4,
               "by_format": { "sigma":    { "rule_count": 3, "corpora": ["sigmahq","team"] },
                              "suricata": { "rule_count": 1, "corpora": ["et-open"] },
                              "yara":     { "rule_count": 0, "corpora": [] } } } ] }
```

`by_format` always carries all three format keys, so a format with no rule is an
explicit zero rather than a missing lane (ADR-0022). The `score` is deliberately
*not* per-format — corroboration is a property of the technique, not of one tool's
rule language. Drill-down rules (`/coverage/{technique}/rules`) each carry
`format` alongside `severity` and `license`.

```jsonc
// POST /api/jobs/{id}/detections/export      → 200 application/zip
{ "rule_ids": ["sigmahq:1a2b3c", "et-open:2010935"] }
// 400 if the list is empty · 404 if no requested id belongs to this report.
// Ids are intersected with the report's linkable rules, so this can never be
// used to dump arbitrary rules from the store.
```

The GET form (axis filters) and this POST form share one archive builder, so both
produce the same layout — `rules/{format}/{corpus}__{slug}.{ext}`, `MANIFEST.json`
(licence + source per rule, plus what was excluded) and `README.txt`.

```json
// GET /api/jobs/{id}/detections/proposals?limit=200
{ "platform": "linux", "atom_index_built": true,
  "observables_total": 44, "candidate_total": 2691,
  "counts": { "direct": 17, "behavioural": 812, "weak": 1862 },
  "proposals": [
    { "id": "mthcht:…", "title": "MeshAgent Remote Access Tool", "corpus": "mthcht",
      "score": 0.94, "tier": "direct", "platform": "", "techniques": ["T1219"],
      "matches": [ { "obs_class": "image", "field": "image", "exact": true,
                     "value": "meshagent64-v2.exe", "display": "meshagent64-v2.exe",
                     "weight": 0.68 } ] } ] }
```

## ATT&CK index

The index the interface reads technique names and tactics from (ADR-0087,
amendment of 2026-10-19).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/attack/index` | The `mitre_index.json` of the ATT&CK track the API runs (`ATTACK_RELEASE`), byte for byte: `{"techniques": [...], "tactics": [...]}`. `X-Attack-Release` names the release (`19.2`, `20.0`). The ETag is the file's sha256 and `Cache-Control` is `no-cache`, so a matching `If-None-Match` gets a 304. A track without the file answers 404; the default track's file is never served in its place |

## Queue

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/queue/status` | Backlog and worker liveness (ADR-0048): job counts by status, oldest-queued age, and per-worker heartbeat freshness against `WORKER_LEASE_TIMEOUT_S`. Unauthenticated, like every other GET route (SECURITY.md). |
| `GET` | `/api/health` | Liveness and readiness of the API: `{"status": "ok"}` with 200, or `{"status": "degraded", "detail": "job store unreachable"}` with **503** when the job store does not answer. The image's `HEALTHCHECK` calls it, and a host monitor should check the status code, not the body. It says nothing about the workers: `/api/queue/status` does. Unauthenticated. |

```json
// GET /api/queue/status
{ "role": "api", "backend": "postgresql",
  "counts": { "queued": 2, "processing": 1, "failed": 0, "for_review": 12, "completed": 40 },
  "queue": { "depth": 2, "max_depth": 50,
             "oldest_queued_job_id": "3f2a...", "oldest_queued_seconds": 42.5 },
  "workers": [ { "worker_id": "worker-1:7:a1b2c3", "running_jobs": 1,
                 "oldest_heartbeat_seconds_ago": 3.2, "stale": false } ] }
```

## Settings (corpora)

Manages the gitignored local overlay only — the committed registry is never edited by the app.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/settings/corpora` | List configured corpora (committed + overlay) with rule counts |
| `GET` | `/api/settings/formats` | Lists known formats (union of compiled adapters and configured corpora) with `available`, corpus count, and rule count for each, ensuring corpora of uncompiled formats remain visible in the UI instead of disappearing |
| `POST` | `/api/settings/corpora` | Add a corpus to the local overlay, accepting an `adapter` field (`sigma`, `suricata`, or `yara`); corpora with uncompiled adapters are accepted but marked `adapter_available: false` and contribute no rules until landed (ADR-0019) |
| `DELETE` | `/api/settings/corpora/{name}` | Remove (or disable, if committed) a corpus |
| `PATCH` | `/api/settings/corpora/{name}` | Enable or disable a corpus without losing its configuration (body: `{"enabled": bool}`), existing because deletion writes a disable for committed registry corpora with no UI reactivation path, as ADR-0015 delivered seven disabled corpora inaccessible without this endpoint; returns 404 if the corpus is unknown |
| `POST` | `/api/settings/corpora/{name}/sync` | Clone/pull the git repository of a single public corpus and re-ingest the store, exposing the same network step as `scripts/sync_corpora.py` for the "Redownload" button, restricted to PUBLIC corpora so private git credentials never transit the application (ADR-0006), blocking until the git operation completes |
| `POST` | `/api/settings/corpora/rebuild` | Re-ingest all enabled corpora from their local clones |

## NER thresholds and entity overrides

The confidence cutoffs and the deny / promote lists that grow from the analysts'
decisions (ADR-0051, ADR-0052).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/thresholds` | The NER confidence cutoffs in force (ADR-0051): each stage's default, the worker's auto-accept level and control-sample rate, `auto_accept_audit` (per source and type, the share of control-sample entities analysts confirmed — ADR-0058), and every stored per-(source, entity_type) override with its provenance |
| `POST` | `/api/thresholds/recalibrate` | Fit P(accepted \| score) per (source, entity_type) from the analysts' decisions and propose the cutoff at which it reaches `target_precision` (default 0.90, needs `min_samples` = 200 decisions); a dry run unless `"apply": true`. Reads only one-at-a-time analyst decisions unless `include_bulk` / `include_legacy` (ADR-0058), and returns `excluded_by_origin` |
| `PUT` | `/api/thresholds/{source}/{entity_type}` | Hand-set one cutoff (`origin: manual`) |
| `DELETE` | `/api/thresholds/{source}/{entity_type}` | Remove an override; the stage default applies again |
| `GET` | `/api/overrides` | The deny / promote rows grown from analyst decisions (ADR-0052), filterable by `status` (`candidate` \| `active` \| `ignored`) and `action` (`deny` \| `promote`); only `active` rows act |
| `POST` | `/api/overrides/promote` | Propose rows from the decisions: `deny` for a value rejected ≥ `min_rejections` times in ≥ `min_jobs` reports in ≥ `share` of its reviews, `promote` for a gazetteer-type name accepted as often and unknown to the gazetteer; a dry run unless `"apply": true`, and even then stored as candidates — never activated |
| `POST` | `/api/overrides` | A hand-written rule (`term`, `entity_type`, `action`, optional `display`/`note`), active at once |
| `PATCH` | `/api/overrides/{id}` | Set a row's `status` — activate a candidate, or ignore it so the next promotion run leaves it alone |
| `DELETE` | `/api/overrides/{id}` | Remove a row |
