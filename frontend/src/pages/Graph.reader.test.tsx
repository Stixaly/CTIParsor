// #807 — a reader opens the graph read-only: the Graph page shows no control that
// edits the links or rebuilds the bundle, and no handler sends such a write.
// The reader role is the one `useCanWrite()` refuses (api/auth.ts `WRITE_ROLE`).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Graph from './Graph'
import type { Entity, Job, Relationship, StixBundle } from '../types'
import { ThemeProvider } from '../context/ThemeContext'
import { AuthContext, type AuthState } from '../context/AuthContext'
import { BundleRefusedError } from '../api/client'

const api = vi.hoisted(() => ({
  fetchJob: vi.fn(),
  fetchEntities: vi.fn(),
  fetchRelationships: vi.fn(),
  fetchBundle: vi.fn(),
  fetchBundleLedger: vi.fn(),
  updateRelationship: vi.fn(),
  deleteRelationship: vi.fn(),
  createRelationship: vi.fn(),
  createEntity: vi.fn(),
  finalizeJobQuick: vi.fn(),
}))

const WRITES = ['updateRelationship', 'deleteRelationship', 'createRelationship', 'createEntity',
  'finalizeJobQuick'] as const

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchJob: api.fetchJob,
  fetchEntities: api.fetchEntities,
  fetchRelationships: api.fetchRelationships,
  fetchBundle: api.fetchBundle,
  fetchBundleLedger: api.fetchBundleLedger,
  updateRelationship: api.updateRelationship,
  deleteRelationship: api.deleteRelationship,
  createRelationship: api.createRelationship,
  createEntity: api.createEntity,
  finalizeJobQuick: api.finalizeJobQuick,
}))

const ENTITIES: Entity[] = [
  { id: 'e-apt', job_id: 'job-1', value: 'APT29', entity_type: 'threat_actor', context: '',
    confidence: 0.95, mitre_id: null, accepted: true, source: 'gliner',
    decision_origin: null, control_sample: false },
  { id: 'e-mal', job_id: 'job-1', value: 'WINELOADER', entity_type: 'malware', context: '',
    confidence: 0.9, mitre_id: null, accepted: true, source: 'gliner',
    decision_origin: null, control_sample: false },
]

const RELATIONSHIPS: Relationship[] = [{
  id: 'rel-1', job_id: 'job-1', source_value: 'APT29', relationship_type: 'uses',
  target_value: 'WINELOADER', confidence: 0.8, accepted: null, evidence_text: null,
  evidence_label: 'observed',
}]

const JOB: Job = {
  id: 'job-1', original_filename: 'r.txt', status: 'completed',
  report_text: 'APT29 used WINELOADER.', created_at: '', updated_at: '',
}

const BUNDLE: StixBundle = { id: 'bundle--1', type: 'bundle', objects: [
  { id: 'threat-actor--a', type: 'threat-actor', name: 'APT29' },
] }

const auth = (role: 'reader' | 'analyst'): AuthState => ({
  status: 'signed-in',
  me: { auth_mode: 'local', username: role, display_name: role, role, auth_source: 'local', csrf_token: 'c' },
  can: () => true,
  setMe: () => undefined, signOut: () => Promise.resolve(), refresh: () => Promise.resolve(),
})

function renderGraph(role: 'reader' | 'analyst') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <AuthContext.Provider value={auth(role)}>
          <MemoryRouter initialEntries={['/graph/job-1']}>
            <Routes>
              <Route path="/graph/:jobId" element={<Graph />} />
              <Route path="/review/:jobId" element={<p>review page</p>} />
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

// The page's write controls, by their visible text or title (see Graph.tsx).
const EDIT_LINKS = 'Edit links'
const REBUILD = /Rebuild|Build it now/

beforeEach(() => {
  for (const name of WRITES) api[name].mockReset().mockResolvedValue({})
  api.fetchJob.mockReset().mockResolvedValue(JOB)
  api.fetchEntities.mockReset().mockResolvedValue(ENTITIES)
  api.fetchRelationships.mockReset().mockResolvedValue(RELATIONSHIPS)
  // No bundle yet: the page offers to build one.
  api.fetchBundle.mockReset().mockRejectedValue(new Error('404: no bundle yet'))
  api.fetchBundleLedger.mockReset().mockResolvedValue(null)
  localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Graph — a reader sees the graph and nothing that changes it (#807)', () => {
  it('shows no Edit links control on the review rows', async () => {
    renderGraph('reader')
    await screen.findByRole('button', { name: 'Review rows' })

    expect(screen.queryByTitle(EDIT_LINKS)).not.toBeInTheDocument()
  })

  it('shows no Edit links control on the bundle view either', async () => {
    api.fetchBundle.mockResolvedValue(BUNDLE)
    api.fetchBundleLedger.mockResolvedValue({ version: 1, objects: {}, entities: [], relationships: [], removed: [] })
    renderGraph('reader')
    await screen.findByRole('button', { name: 'STIX bundle' })

    expect(screen.queryByTitle(EDIT_LINKS)).not.toBeInTheDocument()
  })

  it('offers no Build it now control when no bundle has been built', async () => {
    renderGraph('reader')
    await screen.findByText('No STIX bundle has been built for this report yet')

    expect(screen.queryByRole('button', { name: REBUILD })).not.toBeInTheDocument()
  })

  it('offers no rebuild control when the stored bundle was refused', async () => {
    api.fetchBundle.mockRejectedValue(new BundleRefusedError(422, ['bad object']))
    renderGraph('reader')
    await screen.findByRole('alert')

    expect(screen.queryByRole('button', { name: REBUILD })).not.toBeInTheDocument()
  })

  it('offers no rebuild control on a bundle built before provenance tracking', async () => {
    api.fetchBundle.mockResolvedValue(BUNDLE)
    renderGraph('reader')
    await screen.findByText(/built before provenance tracking/)

    expect(screen.queryByRole('button', { name: /Rebuild/ })).not.toBeInTheDocument()
  })

  it('sends no write while the read-only page loads and is used', async () => {
    renderGraph('reader')
    fireEvent.click(await screen.findByRole('button', { name: 'Review rows' }))
    fireEvent.click(await screen.findByRole('button', { name: 'STIX bundle' }))
    await waitFor(() => expect(api.fetchEntities).toHaveBeenCalled())

    for (const name of WRITES) expect(api[name]).not.toHaveBeenCalled()
  })
})

describe('Graph — an analyst keeps the link editor and the rebuild controls (#807)', () => {
  it('shows Edit links and opens the editor', async () => {
    renderGraph('analyst')
    fireEvent.click(await screen.findByTitle(EDIT_LINKS))

    expect(await screen.findByText('Edit relationships')).toBeInTheDocument()
  })

  it('offers Build it now when no bundle has been built', async () => {
    renderGraph('analyst')
    expect(await screen.findByRole('button', { name: 'Build it now' })).toBeInTheDocument()
  })
})
