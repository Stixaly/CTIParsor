# API permissions inventory

Date: 2026-11-08. Source: `contract/openapi.json` at commit `537054f` (60 entries, `GET /api/health` included), with the route functions in `api/routes/*.py` and `api/main.py`.

Status: enforced since ADR-0097 work items 14 and 15, part A, when `AUTH_MODE` is not `off`; the table lives in `api/auth/permissions.py` and `tests/test_auth_permissions.py` fails for an operation without a role. With `AUTH_MODE=off` (the default) the API has no authentication and no role check. The inventory below is the 2026-11-08 one (60 operations); the operations added since are `POST /api/auth/login`, `GET /api/auth/methods`, `GET /api/auth/oidc/login` and `GET /api/auth/oidc/callback` (open), `POST /api/auth/logout` and `GET /api/auth/me` (reader), `GET`/`POST /api/auth/tokens` and `DELETE /api/auth/tokens/{token_id}` (reader, the caller's own tokens), and `GET`/`POST /api/admin/users`, `PATCH /api/admin/users/{user_id}`, `POST /api/admin/users/{user_id}/password`, `GET`/`POST /api/admin/tokens` and `DELETE /api/admin/tokens/{token_id}` (admin). The write guard `refuse_cross_site_writes` in `api/main.py` refuses browser cross-site requests; it is not an authorization control.

Roles, from ADR-0097 (Roles): `reader` < `analyst` < `admin`, each containing the one before. The minimal role in each row is the proposal, not the current state. Where a route mixes reads and writes, the stricter one applies.

Count by proposed minimal role:

- `reader`: 26 operations
- `analyst`: 22 operations (route 11 counts here: an analyst deletes own imports; admin deletes any)
- `admin`: 11 operations
- open (no role): 1 (`GET /api/health`)
- total: 60

Columns and effect labels:

- "Writes" names the tables and files changed. "journal" is `review_decisions`, written through `pipeline/decisions.record`.
- "Effects" uses these labels: DELETE (rows or files removed), EXPORT (a ZIP of rule bodies), LLM (starts a pipeline run that calls the configured LLM provider), EXT (the server fetches an external address), OUT (report content or a bundle leaves the server as a response or download).
- Open questions are numbered in the last section.

| # | Method | Path | Code (file:function) | Reads | Writes | Effects | Minimal role | Reason |
|---|---|---|---|---|---|---|---|---|
| 1 | GET | /api/health | api/main.py:health | job store (`SELECT 1`) | none | none | open | Liveness and readiness probe; ADR-0097 keeps it open. |
| 2 | GET | /api/attack/index | api/routes/attack.py:attack_index | the selected ATT&CK track's `mitre_index.json` | none | none | reader | Reference data. |
| 3 | GET | /api/baselines/status | api/routes/baselines.py:baselines_status | `STIX_ENRICHMENT_ENABLED` and the size limits | none | none | reader | Configuration only. |
| 4 | POST | /api/baselines/inspect | api/routes/baselines.py:inspect_baseline | the uploaded STIX bundle | none (nothing stored or logged) | parses an uploaded file | analyst | Takes a file, as the upload routes do. See question 6. |
| 5 | GET | /api/jobs | api/routes/jobs.py:list_jobs | `jobs` (metadata) | none | none | reader | ADR-0097: every user sees every report. |
| 6 | GET | /api/jobs/{job_id} | api/routes/jobs.py:get_job | `jobs` row, including `report_text`; counts; enrichment summary | none | OUT (report text) | reader | ADR-0097: every user sees every report. See question 8. |
| 7 | GET | /api/jobs/{job_id}/baseline | api/routes/jobs.py:get_baseline | `job_baselines.bundle_json` | none | OUT (baseline bundle as a download) | reader | Read of a stored input. See question 8. |
| 8 | GET | /api/jobs/{job_id}/baseline/intake | api/routes/jobs.py:get_baseline_intake | `job_baselines.intake_json` | none | none | reader | Read. |
| 9 | PATCH | /api/jobs/{job_id} | api/routes/jobs.py:update_job_status | `jobs` | `jobs.status`; 409 while the job is processing | none | analyst | Changes review state. Setting `completed` is the sign-off. See question 2. |
| 10 | POST | /api/jobs/{job_id}/finalize | api/routes/jobs.py:finalize_job (calls api/worker.py:re_run_final_stages) | stored extraction results, entities, relationships, policy | `jobs.bundle_json`, bundle validation, bundle ledger, export file in `output/`; `jobs.status` = `completed` when `quick=false` | LLM (Stage 4c long-distance inference) only when the policy enables `completion.long_distance` (default off) and the TLP check passes. See question 12. | analyst | Rebuilds the bundle and, in full mode, completes the report: a review decision. |
| 11 | DELETE | /api/jobs/{job_id} | api/routes/jobs.py:delete_job (calls `_delete_job`) | `jobs` row | deletes rows in `entities`, `relationships`, `progress_events`, `job_baselines`, `jobs`; deletes `uploads/{id}.*` and the bundle and checkpoint files in `output/` | DELETE (not recoverable) | analyst for own imports, admin for any | ADR-0097 rule. The owner is `jobs.imported_by` (migration 18). See question 1. |
| 12 | GET | /api/jobs/{job_id}/source | api/routes/jobs.py:get_source_file | `uploads/{job_id}.*` | none | OUT (original document, with a restrictive CSP) | reader | The report itself, as for route 6. See question 8. |
| 13 | GET | /api/jobs/{job_id}/bundle | api/routes/jobs.py:get_bundle | `jobs.bundle_json`, `bundle_validation` | none | OUT (bundle) | reader | Read. |
| 14 | GET | /api/jobs/{job_id}/bundle/ledger | api/routes/jobs.py:get_bundle_ledger | `jobs.bundle_ledger_json` | none | none | reader | Read. |
| 15 | GET | /api/jobs/{job_id}/entities | api/routes/entities.py:list_entities | `entities` | none | none | reader | Read. |
| 16 | POST | /api/jobs/{job_id}/entities | api/routes/entities.py:create_entity | the request | `entities` row (source `manual`) | none | analyst | Adds analyst data to a job. |
| 17 | PATCH | /api/jobs/{job_id}/entities/{entity_id} | api/routes/entities.py:update_entity | `entities` | `entities` row; journal when `accepted` is set | none | analyst | Review decision and edit. |
| 18 | POST | /api/jobs/{job_id}/entities/accept-pending | api/routes/entities.py:accept_all_pending | `entities` with `accepted` NULL | `entities.accepted`; journal (`human_bulk`) | none | analyst | Decides every pending row of the job at once. See question 5. |
| 19 | POST | /api/jobs/{job_id}/entities/bulk | api/routes/entities.py:bulk_update_entities | `entities` of one type | `entities.accepted`; journal (`human_bulk`) | none | analyst | Scope `all` overrides earlier decisions. See question 5. |
| 20 | DELETE | /api/jobs/{job_id}/entities/{entity_id} | api/routes/entities.py:delete_entity | `entities` | deletes an `entities` row | DELETE | analyst | Removes a row. To check whether a deleted row can be restored. |
| 21 | GET | /api/jobs/{job_id}/relationships | api/routes/relationships.py:list_relationships | `relationships` | none | none | reader | Read. |
| 22 | GET | /api/jobs/{job_id}/relationships/valid-types | api/routes/relationships.py:get_valid_types | a constant list | none | none | reader | Read. |
| 23 | POST | /api/jobs/{job_id}/relationships | api/routes/relationships.py:create_relationship | the request | `relationships` row; journal | none | analyst | The analyst draws an accepted edge. |
| 24 | POST | /api/jobs/{job_id}/relationships/bulk | api/routes/relationships.py:bulk_update_relationships | `relationships` by id (at most 500) | `relationships.accepted`; journal (`human_bulk`) | none | analyst | Group decision. |
| 25 | PATCH | /api/jobs/{job_id}/relationships/{rel_id} | api/routes/relationships.py:update_relationship | `relationships` | `relationships` row (ends, verb, dates, evidence, `accepted`); journal | none | analyst | Review decision and edit. |
| 26 | DELETE | /api/jobs/{job_id}/relationships/{rel_id} | api/routes/relationships.py:delete_relationship | `relationships` | deletes a `relationships` row | DELETE | analyst | Removes a row. |
| 27 | GET | /api/jobs/{job_id}/progress | api/routes/progress.py:progress_stream | `progress_events`, `jobs.status` | none | SSE; polls every 0.5 s for at most 45 min | reader | Progress of a job. |
| 28 | GET | /api/overrides | api/routes/overrides.py:get_overrides | `entity_overrides` | none | none | reader | Read. |
| 29 | POST | /api/overrides/promote | api/routes/overrides.py:promote (calls `pipeline/promotion.py:propose`) | analyst decisions | `entity_overrides` candidate rows, only with `apply=true` | none | analyst | Proposes candidates. It never activates one. |
| 30 | POST | /api/overrides | api/routes/overrides.py:create_override (calls `add_manual`) | the request | `entity_overrides` row, active at once; the NER rules reload in this process | none | analyst | Changes extraction for every job. See question 3. |
| 31 | PATCH | /api/overrides/{override_id} | api/routes/overrides.py:patch_override (calls `set_status`) | `entity_overrides` | `entity_overrides.status` (`active`, `candidate`, `ignored`) | none | analyst | Same as route 30. See question 3. |
| 32 | DELETE | /api/overrides/{override_id} | api/routes/overrides.py:remove_override (calls `delete_override`) | `entity_overrides` | deletes an `entity_overrides` row | DELETE | analyst | Same as route 30. See question 3. |
| 33 | GET | /api/relationship-policy | api/routes/policy.py:get_policy | `relationship_policy` | none | none | reader | Read. |
| 34 | GET | /api/relationship-policy/last-run | api/routes/policy.py:get_last_run | `jobs.bundle_json` of the newest job | none | none | reader | Read. |
| 35 | PUT | /api/relationship-policy | api/routes/policy.py:put_policy | the request body | `relationship_policy` (full replacement) | none | admin | Policy is admin (ADR-0097). |
| 36 | GET | /api/queue/status | api/routes/queue.py:get_queue_status | `jobs` counts, `worker_heartbeats` | none | none | reader | Exposes worker ids, app versions and the oldest queued job id. See question 9. |
| 37 | GET | /api/detection-corpora | api/routes/coverage.py:get_detection_corpora | rule store counts | none | none | reader | Read. |
| 38 | GET | /api/jobs/{job_id}/coverage | api/routes/coverage.py:get_coverage (calls `compute_for_job`) | job, rule store | none | none | reader | Read. |
| 39 | GET | /api/jobs/{job_id}/coverage/rules | api/routes/coverage.py:get_coverage_report_rules (calls `rules_for_job`) | job, rule store | none | none | reader | Read, metadata only. |
| 40 | GET | /api/jobs/{job_id}/coverage/artifacts | api/routes/coverage.py:get_artifact_coverage (calls `coverage_with_phases`) | job, rule store | none | none | reader | Read. |
| 41 | GET | /api/jobs/{job_id}/coverage/{technique_id}/rules | api/routes/coverage.py:get_coverage_rules (calls `rules_for_technique`) | rule store | none | none | reader | Read, metadata only. |
| 42 | GET | /api/jobs/{job_id}/detections/proposals | api/routes/coverage.py:get_detection_proposals (calls `propose_for_job`) | job, rule store | none | none | reader | Read, metadata only. |
| 43 | GET | /api/jobs/{job_id}/detections/export/facets | api/routes/coverage.py:export_facets (calls `rule_facets_for_job`) | job, rule store | none | none | reader | Read: counts and sizes before an export. |
| 44 | GET | /api/jobs/{job_id}/detections/export | api/routes/coverage.py:export_detections | job, rule store | none | EXPORT (ZIP of rule bodies with their licences) | analyst | ADR-0097: rule export is analyst. See question 7. |
| 45 | POST | /api/jobs/{job_id}/detections/export | api/routes/coverage.py:export_detections_selection | job, rule store (ids in the body) | none | EXPORT (ZIP, promoted rules included) | analyst | As route 44. See question 7. |
| 46 | POST | /api/rules/lookup | api/routes/coverage.py:post_rule_lookup | rule store | none | OUT (rule bodies, at most 500 ids, when `include_body`) | reader | A read sent as POST. See question 7. |
| 47 | GET | /api/settings/corpora | api/routes/settings.py:list_corpora (calls `_with_counts`) | `detection_corpora.yaml`, local overlay, rule counts | none | none | admin | ADR-0097: settings reads are admin. |
| 48 | GET | /api/settings/formats | api/routes/settings.py:list_formats | as route 47 | none | none | admin | As route 47. |
| 49 | POST | /api/settings/corpora | api/routes/settings.py:create_corpus (calls `add_corpus`) | the request | `detection_corpora.local.yaml` (overlay) | none (no fetch) | admin | Settings write. |
| 50 | PATCH | /api/settings/corpora/{name} | api/routes/settings.py:patch_corpus | overlay | overlay (`enabled`) | none | admin | Settings write. |
| 51 | DELETE | /api/settings/corpora/{name} | api/routes/settings.py:delete_corpus (calls `remove_corpus`) | overlay | removes the overlay entry | DELETE (configuration). To check whether the clone on disk is removed. See question 11. | admin | Settings write. |
| 52 | POST | /api/settings/corpora/{name}/sync | api/routes/settings.py:sync_one_corpus (calls `sync_corpus`, `rebuild_store`) | corpus configuration | `corpora/` clone or extracted tarball; rule store | EXT (git clone or tarball download from the configured public https remote); a tarball sync can remove its target directory (code comment in `_validate_corpus_path`) | admin | Fetches from the network and rewrites the store. |
| 53 | POST | /api/settings/corpora/rebuild | api/routes/settings.py:rebuild_corpora (calls `rebuild_store`) | local clones, configuration | rule store (all enabled corpora) | none | admin | Rewrites the whole store. |
| 54 | GET | /api/thresholds | api/routes/thresholds.py:get_thresholds | threshold overrides, auto-accept audit, defaults | none | none | reader | Read. |
| 55 | POST | /api/thresholds/recalibrate | api/routes/thresholds.py:recalibrate (calls `calibrate`) | analyst decisions | with `apply=true`: threshold overrides | none | admin | Changes cutoffs for every job when applied. See question 4. |
| 56 | PUT | /api/thresholds/{source}/{entity_type} | api/routes/thresholds.py:put_threshold | threshold overrides | override row, live for every job | none | admin | Thresholds are admin (ADR-0097). |
| 57 | DELETE | /api/thresholds/{source}/{entity_type} | api/routes/thresholds.py:delete_threshold | overrides | deletes an override | DELETE | admin | As route 56. |
| 58 | POST | /api/upload | api/routes/upload.py:upload_file (calls `start_job`) | the multipart form: report, optional baseline | `uploads/{job_id}.*`, `jobs` row, queue | LLM: the Stage 3 provider set by `LLM_PROVIDER`. TLP egress is checked in the pipeline (`text_egress` in `pipeline/orchestrator.py`): a refused Stage 3 is skipped, the job runs on. See question 10 | analyst | Creates a job that spends LLM time. Rate limit 10 per minute. |
| 59 | POST | /api/ingest/text | api/routes/ingest.py:ingest_text (calls `start_job`) | the request text | `uploads/{job_id}.html`, `.md` or `.txt`; `jobs` row; queue | LLM: as route 58 | analyst | As route 58. Rate limit 20 per minute. |
| 60 | POST | /api/ingest/url | api/routes/ingest.py:ingest_url (calls `web_capture.capture_url_to_pdf`, `start_job`) | the external URL, chosen by the caller | `uploads/{job_id}.pdf` and `.txt`, capture metadata, `jobs` row, queue | EXT (headless browser fetches the URL); LLM: as route 58 | analyst | Fetches an external page and creates a job. Rate limit 5 per minute. |
| 61 | GET | /api/llm/egress | api/routes/llm.py:get_egress (calls `pipeline.egress.decide`) | the `tlp` query, the provider settings | none | none | reader | Added after the snapshot (#602): whether a TLP would be sent to the configured providers; shows their host, never a key. |
| 62 | GET | /api/audit | api/routes/audit.py:list_audit | `audit_events` | none | none | admin | Added with the audit trail (ADR-0097 item 17): who changed what, and whether it was done. Admin only, as the records name every user and client. |
| 63 | GET | /metrics | api/routes/metrics.py:get_metrics (mounted outside `/api`, in `_OWN_RULE_ROUTERS` in `api/main.py`) | job, queue and worker counts, backup status file | none | none | own rule: loopback clients, or the `METRICS_TOKEN` bearer when it is set | Prometheus text. Outside `/api`, so the sign-in gate does not apply. Not in the OpenAPI schema, so not in the 60 operations counted above. With `METRICS_TOKEN` set, a bearer that does not match is refused even from loopback; any other client gets 403. |

## Questions to settle

1. Deleting another analyst's report (route 11). **Answered:** the owner is `jobs.imported_by` (migration 18, `api/migrations/v0018_auth.py`), set by the upload and ingest routes to the user who imported the report. An analyst deletes a report whose `imported_by` is their own id; an admin deletes any (`may_delete` in `api/routes/jobs.py`). Open point: a report stored before migration 18 has no owner, so only an admin deletes it.
2. Completing a report (routes 9 and 10 with `quick=false`). Should an analyst complete a report another analyst reviewed, or should completion need a second person?
3. Override rules (routes 30 to 32). They change extraction for every job as soon as they are written. ADR-0052 says activating a rule is a person's decision. Analyst, as proposed, or admin?
4. Recalibration (route 55). Without `apply` it writes nothing; with `apply=true` it changes cutoffs for every job. Keep it admin for both, or allow a reader a dry run?
5. Bulk decisions (routes 18 and 19). They overwrite decisions made one by one; scope `all` overwrites every row of a type. Analyst, or admin for scope `all`?
6. Baseline inspection (route 4) stores nothing. Reader, or analyst as proposed because it takes a file?
7. Exports and rule bodies (routes 44 to 46). The POST lookup returns rule bodies to any reader, while the ZIP exports need analyst. Confirm that a GET export is an export (analyst), not a read, and that reading rule bodies is a reader right.
8. Report content for readers (routes 6, 7, 12, 13). ADR-0097 says every user sees every report. **Answered:** yes. The read routes do not filter on `tlp_level` (`api/routes/jobs.py`, `entities.py`, `relationships.py`, `coverage.py`); a report marked TLP:RED is visible to every reader, as every other report is.
9. Queue status (route 36) exposes worker ids, versions and the oldest queued job id. Reader, as proposed, or open as a health signal?
10. TLP egress for LLM calls (routes 58 to 60). ADR-0097 decision 4 is not a role question. **Answered:** the gate is in the pipeline, not in the routes, which accept the job whatever its TLP. `pipeline/orchestrator.py` takes `text_egress(tlp_level)` (`pipeline/egress.py`, `decide`) before Stage 3: a refused Stage 3 is recorded as skipped with the egress reason, and Stages 3d, 3f, 3e and 3doc are skipped with it. The Stage 1f figures and the second consensus call are gated the same way. The provider is the one `LLM_PROVIDER` names (`pipeline/stage3_llm.py`).
11. Corpus deletion (route 51). Whether the clone on disk is removed is to check in `pipeline/detection/registry.py`.
12. Finalize and long-distance inference (route 10). **Answered:** Stage 4c runs in a finalize only when the policy enables `completion.long_distance` (default off) and the TLP check passes. `re_run_final_stages` (`api/worker.py`) passes no flag: `build_bundle` (`pipeline/orchestrator.py`) checks `text_egress`, and `default_long_distance_inferer` (`pipeline/stage4c_long_distance.py`) returns no inferer unless the policy enables it.
