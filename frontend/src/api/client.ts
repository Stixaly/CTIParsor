import type { Job, Entity, Relationship, StixBundle, CoverageResult, CoverageRule, CoverageReportRules, DetectionProposals, DetectionCorpus, CorpusConfig, FormatInfo, ExportFacets, ExportSelection, ExportAxis, LastRun } from '../types'

const BASE = '/api'

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const msg = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status}: ${msg}`)
  }
  return res.json()
}

// Jobs
export const fetchJobs = () => req<Job[]>('/jobs')
export const fetchJob = (id: string) => req<Job>(`/jobs/${id}`)
export const updateJobStatus = (id: string, status: string) =>
  req<{ status: string }>(`/jobs/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) })
/** Full finalize — runs lexicon re-scan + Stages 4-5.  Used by the manual Finalize button. */
export const finalizeJob = (id: string) =>
  req<{ status: string; bundle_size: number }>(`/jobs/${id}/finalize`, { method: 'POST' })

/** Quick finalize — skips lexicon re-scan, used by the debounced auto-finalize.
 *  Keeps the bundle up-to-date after every entity/relationship change without
 *  the extra latency of the full re-scan. */
export const finalizeJobQuick = (id: string) =>
  req<{ status: string; bundle_size: number }>(`/jobs/${id}/finalize?quick=true`, { method: 'POST' })
export const deleteJob = (id: string) =>
  req<{ deleted: string }>(`/jobs/${id}`, { method: 'DELETE' })
export const fetchBundle = (id: string) => req<StixBundle>(`/jobs/${id}/bundle`)
/** Returns the URL to stream the original uploaded file (PDF, DOCX, …). */
export const sourceUrl  = (id: string) => `/api/jobs/${id}/source`

// Upload
export interface UploadOptions {
  tlpLevel?: string
  papLevel?: string
}

export async function uploadFile(file: File, options?: UploadOptions): Promise<{ job_id: string; filename: string }> {
  const form = new FormData()
  form.append('file', file)
  if (options?.tlpLevel) form.append('tlp_level', options.tlpLevel)
  if (options?.papLevel) form.append('pap_level', options.papLevel)
  const res = await fetch(`${BASE}/upload`, { method: 'POST', body: form })
  if (!res.ok) throw new Error(`Upload failed: ${res.statusText}`)
  return res.json()
}

// Entities
export const fetchEntities = (jobId: string) =>
  req<Entity[]>(`/jobs/${jobId}/entities`)
export const updateEntity = (jobId: string, entityId: string, patch: object) =>
  req<Entity>(`/jobs/${jobId}/entities/${entityId}`, {
    method: 'PATCH', body: JSON.stringify(patch),
  })
export const deleteEntity = (jobId: string, entityId: string) =>
  req<{ deleted: string }>(`/jobs/${jobId}/entities/${entityId}`, { method: 'DELETE' })
export const createEntity = (jobId: string, body: {
  value: string; entity_type: string; context?: string; confidence?: number; source?: string; mitre_id?: string | null
}) =>
  req<Entity>(`/jobs/${jobId}/entities`, { method: 'POST', body: JSON.stringify(body) })
export const acceptAllPendingEntities = (jobId: string) =>
  req<{ accepted: number }>(`/jobs/${jobId}/entities/accept-pending`, { method: 'POST' })

/**
 * Bulk accept / reject / reset all entities of a given type in one request.
 *
 * action : 'accept' | 'reject' | 'reset'
 * scope  : 'pending' (default — only NULL rows) | 'all' (every row of that type)
 */
export const bulkUpdateEntities = (
  jobId: string,
  entity_type: string,
  action: 'accept' | 'reject' | 'reset',
  scope: 'pending' | 'all' = 'pending',
) =>
  req<{ updated: number; entity_type: string; action: string; scope: string }>(
    `/jobs/${jobId}/entities/bulk`,
    { method: 'POST', body: JSON.stringify({ entity_type, action, scope }) },
  )

// Relationships
export const fetchRelationships = (jobId: string) =>
  req<Relationship[]>(`/jobs/${jobId}/relationships`)
export const createRelationship = (jobId: string, body: {
  source_value: string; relationship_type: string; target_value: string; confidence?: number; evidence_text?: string | null
  evidence_label?: 'observed' | 'reported' | 'assessed' | 'inferred' | 'gap'
}) =>
  req<Relationship>(`/jobs/${jobId}/relationships`, { method: 'POST', body: JSON.stringify(body) })
export const updateRelationship = (jobId: string, relId: string, patch: object) =>
  req<Relationship>(`/jobs/${jobId}/relationships/${relId}`, {
    method: 'PATCH', body: JSON.stringify(patch),
  })
export const deleteRelationship = (jobId: string, relId: string) =>
  req<{ deleted: string }>(`/jobs/${jobId}/relationships/${relId}`, { method: 'DELETE' })

// Detection coverage (ADR-0006)
export const fetchCoverage = (jobId: string) =>
  req<CoverageResult>(`/jobs/${jobId}/coverage`)
export const fetchCoverageRules = (jobId: string, techniqueId: string) =>
  req<{ technique_id: string; rules: CoverageRule[] }>(`/jobs/${jobId}/coverage/${techniqueId}/rules`)
/** Every rule linkable to a report, in every format, grouped by technique — the
 *  unranked tag join. Backs the coverage page's selection set (ADR-0022). */
export const fetchCoverageReportRules = (jobId: string) =>
  req<CoverageReportRules>(`/jobs/${jobId}/coverage/rules`)
/** Rules ranked by the report's own observables, with match evidence (ADR-0014) —
 *  backs the Review "Detections" tab. */
export const fetchDetectionProposals = (jobId: string, limit = 200) =>
  req<DetectionProposals>(`/jobs/${jobId}/detections/proposals?limit=${limit}`)
/** URL that streams a ZIP of every detected rule (bodies) for a report, in every
 *  format. For an arbitrary subset use `downloadExportSelection` (ADR-0022). */
export const detectionsExportUrl = (jobId: string) =>
  `/api/jobs/${jobId}/detections/export`
export const fetchDetectionCorpora = () =>
  req<{ corpora: DetectionCorpus[] }>(`/detection-corpora`)

// Settings — detection-corpora management (ADR-0007)
export const fetchCorpora = () =>
  req<{ corpora: CorpusConfig[] }>('/settings/corpora')
export const fetchFormats = () =>
  req<{ formats: FormatInfo[] }>('/settings/formats')
export const addCorpus = (body: { name: string; adapter: string; git?: string; tarball?: string; subdir?: string; license?: string; priority?: number; private?: boolean }) =>
  req<{ ok: boolean; warning: string | null; corpora: CorpusConfig[] }>('/settings/corpora', { method: 'POST', body: JSON.stringify(body) })
export const setCorpusEnabled = (name: string, enabled: boolean) =>
  req<{ ok: boolean; corpora: CorpusConfig[] }>(`/settings/corpora/${encodeURIComponent(name)}`, { method: 'PATCH', body: JSON.stringify({ enabled }) })
export const removeCorpus = (name: string) =>
  req<{ ok: boolean; corpora: CorpusConfig[] }>(`/settings/corpora/${encodeURIComponent(name)}`, { method: 'DELETE' })
export const syncCorpus = (name: string) =>
  req<{ ok: boolean; detail: string; corpora: CorpusConfig[] }>(`/settings/corpora/${encodeURIComponent(name)}/sync`, { method: 'POST' })
export const rebuildCorpora = () =>
  req<{ total: number; written: Record<string, number>; skipped: string[] }>('/settings/corpora/rebuild', { method: 'POST' })

// ── Relationship Policy ───────────────────────────────────────────────────────
export const getRelationshipPolicy = () =>
  req<Record<string, unknown>>('/relationship-policy')

export const putRelationshipPolicy = (policy: Record<string, unknown>) =>
  req<Record<string, unknown>>('/relationship-policy', {
    method: 'PUT',
    body: JSON.stringify(policy),
  })

// Per-rule synthesis accounting from the most recent bundle (ADR-0026) — what
// each pinned rule actually produced on the last run.
export const getPolicyLastRun = () =>
  req<LastRun>('/relationship-policy/last-run')


export function fetchExportFacets(jobId: string): Promise<ExportFacets> {
  return req<ExportFacets>(`/jobs/${encodeURIComponent(jobId)}/detections/export/facets`)
}

// Returns a full URL rather than calling req() because the browser must handle
// the ZIP download natively (via <a download>), not parse a JSON response.
export function buildExportUrl(jobId: string, sel: ExportSelection): string {
  const params = new URLSearchParams()
  for (const axis of Object.keys(sel) as ExportAxis[]) {
    for (const value of sel[axis]) {
      params.append(axis, value)
    }
  }
  const qs = params.toString()
  return `${BASE}/jobs/${encodeURIComponent(jobId)}/detections/export${qs ? `?${qs}` : ''}`
}

/** POST the selected rule ids and hand back the ZIP as a blob.
 *  Unlike the axis-filtered GET (buildExportUrl), an arbitrary rule set cannot
 *  ride on <a href> query params — 9k ids exceed any URL limit — so the caller
 *  triggers the download itself from the returned blob (ADR-0022). */
export async function downloadExportSelection(
  jobId: string,
  ruleIds: string[],
): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch(`${BASE}/jobs/${encodeURIComponent(jobId)}/detections/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule_ids: ruleIds }),
  })
  if (!res.ok) {
    throw new Error(await res.text().catch(() => res.statusText))
  }
  const disposition = res.headers.get('content-disposition') ?? ''
  const match = disposition.match(/filename="([^"]+)"/)
  const filename = match ? match[1] : 'detection_rules.zip'
  return { blob: await res.blob(), filename }
}

// Alternative ingestion — pasted text and captured web pages (ADR-0029).
// Both land in the same job queue as an uploaded file.

export interface IngestResponse {
  job_id: string
  filename: string
  status: string
}

export interface UrlIngestResponse extends IngestResponse {
  source_url: string
  blocked_requests: number
}

export const ingestText = (body: {
  text: string
  title?: string | null
  tlp_level?: string | null
  pap_level?: string | null
}) => req<IngestResponse>('/ingest/text', { method: 'POST', body: JSON.stringify(body) })

export const ingestUrl = (body: {
  url: string
  enable_js?: boolean
  tlp_level?: string | null
  pap_level?: string | null
}) => req<UrlIngestResponse>('/ingest/url', { method: 'POST', body: JSON.stringify(body) })

/**
 * Pull the human-readable message out of an Error thrown by `req`.
 *
 * `req` throws `Error("<status>: <raw body>")` and FastAPI's body is
 * `{"detail": "..."}`, so a raw message reaches the user as
 * `400: {"detail":"Port 11434 is not allowed."}`.  This unwraps both layers and
 * falls back to the original message when the body is not FastAPI JSON.
 */
export function errorDetail(err: unknown): string {
  if (!(err instanceof Error)) {
    return String(err)
  }
  const idx = err.message.indexOf(': ')
  if (idx === -1) {
    return err.message
  }
  const body = err.message.slice(idx + 2)
  try {
    const parsed: unknown = JSON.parse(body)
    if (
      parsed !== null &&
      typeof parsed === 'object' &&
      'detail' in parsed &&
      typeof (parsed as { detail: unknown }).detail === 'string' &&
      (parsed as { detail: string }).detail.length > 0
    ) {
      return (parsed as { detail: string }).detail
    }
  } catch {
    // Not JSON — fall through to raw body
  }
  return body.length > 0 ? body : err.message
}
