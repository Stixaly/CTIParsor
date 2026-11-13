// #707 — a reader opens a report read-only. The page shows no control that
// changes the report, and no key press sends a write: a reader's session is
// refused by the server (403) for every one of them.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Entity, Job, Relationship } from '../types'
import { ThemeProvider } from '../context/ThemeContext'
import { AuthContext, type AuthState } from '../context/AuthContext'
import Review from './Review'

const entity = (over: Partial<Entity>): Entity => ({
  id: 'e1', job_id: 'job-1', value: 'WellMess', entity_type: 'malware',
  context: '', confidence: 0.95, mitre_id: null, accepted: null, source: 'gliner',
  decision_origin: null, control_sample: false,
  ...over,
})

const ENTITIES = (): Entity[] => [
  entity({ id: 'e-high', value: 'WellMess', confidence: 0.97 }),
  entity({ id: 'e-auto', value: 'APT29', entity_type: 'threat_actor', confidence: 0.92,
           accepted: true, decision_origin: 'auto_policy' }),
]

const RELS = (): Relationship[] => [{
  id: 'r1', job_id: 'job-1', source_value: 'APT29', relationship_type: 'uses',
  target_value: 'WellMess', confidence: 0.95, accepted: null, evidence_text: null,
  evidence_label: 'observed',
}]

const NO_BASE_RULES = {
  job_id: 'job-1', techniques: [], technique_total: 0, rule_total: 0,
  tag_total: 0, evidence_total: 0, evidence_only: false,
}

const JOB: Job = {
  id: 'job-1', original_filename: 'r.txt', status: 'for_review',
  report_text: 'APT29 used WellMess.', created_at: '', updated_at: '',
}

const READER: AuthState = {
  status: 'signed-in',
  me: { auth_mode: 'local', username: 'reader', display_name: 'Reader', role: 'reader', auth_source: 'local', csrf_token: 'c' },
  can: minimum => minimum === 'reader',
  setMe: () => undefined, signOut: () => Promise.resolve(), refresh: () => Promise.resolve(),
}

const api = vi.hoisted(() => ({
  updateEntity: vi.fn(),
  updateRelationship: vi.fn(),
  bulkUpdateEntities: vi.fn(),
  bulkUpdateRelationships: vi.fn(),
  createEntity: vi.fn(),
  createRelationship: vi.fn(),
  finalizeJob: vi.fn(),
  fetchJob: vi.fn(),
  fetchEntities: vi.fn(),
  fetchRelationships: vi.fn(),
  fetchCoverageReportRules: vi.fn(),
}))

const WRITES = ['updateEntity', 'updateRelationship', 'bulkUpdateEntities', 'bulkUpdateRelationships',
  'createEntity', 'createRelationship', 'finalizeJob'] as const

vi.mock('../api/client', async () => ({
  BundleRefusedError: (await vi.importActual<typeof import('../api/client')>('../api/client')).BundleRefusedError,
  fetchJob: api.fetchJob,
  fetchEntities: api.fetchEntities,
  fetchRelationships: api.fetchRelationships,
  fetchThresholds: () => Promise.resolve({ enabled: true, auto_accept_level: 0.9, control_sample_rate: 0.1 }),
  fetchCoverageReportRules: api.fetchCoverageReportRules,
  updateEntity: api.updateEntity,
  updateRelationship: api.updateRelationship,
  bulkUpdateEntities: api.bulkUpdateEntities,
  bulkUpdateRelationships: api.bulkUpdateRelationships,
  createEntity: api.createEntity,
  createRelationship: api.createRelationship,
  finalizeJob: api.finalizeJob,
  finalizeJobQuick: vi.fn(() => Promise.resolve({})),
  sourceUrl: (id: string) => `/api/jobs/${id}/source`,
  detectionsExportUrl: (id: string) => `/api/jobs/${id}/detections/export`,
  errorDetail: (e: unknown) => String(e),
  apiFetch: (input: string, init?: RequestInit) => globalThis.fetch(input, { ...init, credentials: 'same-origin' }),
}))

vi.mock('../components/SourceViewer', () => ({ default: () => null }))

function renderAsReader() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <AuthContext.Provider value={READER}>
          <MemoryRouter initialEntries={['/review/job-1']}>
            <Routes>
              <Route path="/review/:jobId" element={<Review />} />
              <Route path="/dashboard" element={<p>dashboard page</p>} />
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

const card = (id: string) => document.querySelector(`[data-marg-id="${id}"]`) as HTMLElement

beforeEach(() => {
  for (const name of WRITES) api[name].mockReset().mockResolvedValue({})
  api.fetchJob.mockReset().mockResolvedValue(JOB)
  api.fetchEntities.mockReset().mockImplementation(() => Promise.resolve(ENTITIES()))
  api.fetchRelationships.mockReset().mockImplementation(() => Promise.resolve(RELS()))
  api.fetchCoverageReportRules.mockReset().mockResolvedValue(NO_BASE_RULES)
  localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Review — a reader sees the report and nothing that changes it (#707)', () => {
  it('shows no decision, bulk, finalize or export control', async () => {
    renderAsReader()
    await screen.findAllByText('WellMess', {}, { timeout: 10_000 })

    expect(screen.queryByRole('button', { name: 'Undo all' })).not.toBeInTheDocument()
    expect(screen.queryAllByTitle('Accept (A)')).toHaveLength(0)
    expect(screen.queryAllByTitle('Reject (R)')).toHaveLength(0)
    expect(screen.queryAllByTitle(/^Accept all/)).toHaveLength(0)
    expect(screen.queryAllByTitle(/^Reject all/)).toHaveLength(0)
    expect(screen.queryByRole('button', { name: /Complete Review/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Detection rules/ })).not.toBeInTheDocument()
    expect(screen.queryAllByTitle('Change type')).toHaveLength(0)
  })

  it('shows no accept or reject control on a relationship', async () => {
    renderAsReader()
    await screen.findAllByText('WellMess', {}, { timeout: 10_000 })

    expect(screen.queryByTitle('Accept')).not.toBeInTheDocument()
    expect(screen.queryByTitle('Reject')).not.toBeInTheDocument()
    expect(screen.queryByTitle(/^Confirm \(accepted by default/)).not.toBeInTheDocument()
  })

  it('sends no write for any shortcut, with an entity focused', async () => {
    renderAsReader()
    await screen.findAllByText('WellMess', {}, { timeout: 10_000 })

    fireEvent.click(card('e-high'))
    for (const key of ['a', 'A', 'r', 'R', 'u', 'U', 'f']) fireEvent.keyDown(window, { key })
    await new Promise(resolve => setTimeout(resolve, 20))

    for (const name of WRITES) expect(api[name]).not.toHaveBeenCalled()
  })

  it('still reads the report: the Text view and the Graph link stay', async () => {
    renderAsReader()
    expect(await screen.findByRole('button', { name: /^Entities/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Graph' })).toBeInTheDocument()
    await waitFor(() => expect(api.fetchEntities).toHaveBeenCalled())
  })
})
