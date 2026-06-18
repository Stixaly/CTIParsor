import type { Job, Entity, Relationship, StixBundle } from '../types'

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
export async function uploadFile(file: File): Promise<{ job_id: string; filename: string }> {
  const form = new FormData()
  form.append('file', file)
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

// ── Relationship Policy ───────────────────────────────────────────────────────
export const getRelationshipPolicy = () =>
  req<Record<string, unknown>>('/relationship-policy')

export const putRelationshipPolicy = (policy: Record<string, unknown>) =>
  req<Record<string, unknown>>('/relationship-policy', {
    method: 'PUT',
    body: JSON.stringify(policy),
  })
