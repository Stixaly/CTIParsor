// #706 — the page keeps the server's decisions and the analyst's writes apart:
// a failed write is undone on screen and says so, a refresh shows what another
// session decided, and an older answer never overwrites a newer decision.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Entity, Job, Relationship } from '../types'
import { ThemeProvider } from '../context/ThemeContext'
import Review from './Review'

const entity = (over: Partial<Entity>): Entity => ({
  id: 'e1', job_id: 'job-1', value: 'WellMess', entity_type: 'malware',
  context: '', confidence: 0.95, mitre_id: null, accepted: null, source: 'gliner',
  decision_origin: null, control_sample: false,
  ...over,
})

const INITIAL_ENTITIES = (): Entity[] => [
  entity({ id: 'e-high', value: 'WellMess', confidence: 0.97 }),
  entity({ id: 'e-auto', value: 'APT29', entity_type: 'threat_actor', confidence: 0.92,
           accepted: true, decision_origin: 'auto_policy' }),
  entity({ id: 'e-control', value: 'WellMail', confidence: 0.95, control_sample: true }),
]

const AUTO_ROWS = (): Entity[] => [
  entity({ id: 'a1', value: 'APT29', entity_type: 'threat_actor', confidence: 0.95,
           accepted: true, decision_origin: 'auto_policy' }),
  entity({ id: 'a2', value: 'WellMess', confidence: 0.96,
           accepted: true, decision_origin: 'auto_policy' }),
  entity({ id: 'a3', value: 'WellMail', confidence: 0.93,
           accepted: true, decision_origin: 'auto_policy' }),
]

const INITIAL_RELS = (): Relationship[] => [{
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
  report_text: 'APT29 used WellMess and WellMail.', created_at: '', updated_at: '',
}

// The fake server: what the API would answer to the next GET.
let store: { entities: Entity[]; rels: Relationship[] }

const applyEntity = (id: string, patch: Partial<Entity>) => {
  store.entities = store.entities.map(e => e.id === id ? { ...e, ...patch } : e)
}
const applyRel = (id: string, patch: Partial<Relationship>) => {
  store.rels = store.rels.map(r => r.id === id ? { ...r, ...patch } : r)
}

const api = vi.hoisted(() => ({
  updateEntity: vi.fn(),
  updateRelationship: vi.fn(),
  bulkUpdateEntities: vi.fn(),
  bulkUpdateRelationships: vi.fn(),
  fetchJob: vi.fn(),
  fetchEntities: vi.fn(),
  fetchRelationships: vi.fn(),
  finalizeJob: vi.fn(),
  fetchCoverageReportRules: vi.fn(),
}))

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
  createEntity: vi.fn(), createRelationship: vi.fn(),
  finalizeJob: api.finalizeJob, finalizeJobQuick: vi.fn(() => Promise.resolve({})),
  sourceUrl: (id: string) => `/api/jobs/${id}/source`,
  detectionsExportUrl: (id: string) => `/api/jobs/${id}/detections/export`,
  errorDetail: (e: unknown) => String(e),
  apiFetch: (input: string, init?: RequestInit) => globalThis.fetch(input, { ...init, credentials: 'same-origin' }),
}))

vi.mock('../api/auth', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/auth')>()),
  fetchMe: () => Promise.resolve({
    auth_mode: 'off', username: null, display_name: null, role: null, auth_source: null, csrf_token: null,
  }),
}))

vi.mock('../components/SourceViewer', () => ({ default: () => null }))

function renderReview() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const utils = render(
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/review/job-1']}>
          <Routes>
            <Route path="/review/:jobId" element={<Review />} />
            <Route path="/dashboard" element={<p>dashboard page</p>} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>
    </ThemeProvider>,
  )
  return { qc, ...utils }
}

const opened = () => screen.findAllByText('WellMess', {}, { timeout: 10_000 })
const card = (id: string) => document.querySelector(`[data-marg-id="${id}"]`) as HTMLElement

beforeEach(() => {
  store = { entities: INITIAL_ENTITIES(), rels: INITIAL_RELS() }
  api.updateEntity.mockReset().mockImplementation((_j: string, id: string, patch: Partial<Entity>) => {
    applyEntity(id, patch)
    return Promise.resolve({})
  })
  api.updateRelationship.mockReset().mockImplementation((_j: string, id: string, patch: Partial<Relationship>) => {
    applyRel(id, patch)
    return Promise.resolve({})
  })
  api.bulkUpdateEntities.mockReset().mockImplementation((_j: string, type: string, action: string) => {
    store.entities = store.entities.map(e => e.entity_type === type && e.accepted === null
      ? { ...e, accepted: action === 'accept' } : e)
    return Promise.resolve({ updated: 1, entity_type: type, action, scope: 'pending' })
  })
  api.bulkUpdateRelationships.mockReset()
  api.fetchJob.mockReset().mockImplementation(() => Promise.resolve(JOB))
  api.fetchEntities.mockReset().mockImplementation(() => Promise.resolve(store.entities.map(e => ({ ...e }))))
  api.fetchRelationships.mockReset().mockImplementation(() => Promise.resolve(store.rels.map(r => ({ ...r }))))
  api.fetchCoverageReportRules.mockReset().mockImplementation(() => Promise.resolve(NO_BASE_RULES))
  api.finalizeJob.mockReset()
  localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Review — a failed Undo of the auto-accept (#706)', () => {
  it('keeps an acceptance the server still holds, and says so', async () => {
    store.entities = AUTO_ROWS()
    api.updateEntity.mockImplementation((_j: string, id: string, patch: Partial<Entity>) =>
      id === 'a2'
        ? Promise.reject(new Error('500: database unavailable'))
        : (applyEntity(id, patch), Promise.resolve({})))
    renderReview()
    await opened()

    fireEvent.click(screen.getByRole('button', { name: 'Undo all' }))
    const alertBox = await screen.findByRole('alert')
    expect(alertBox).toHaveTextContent(/could not be undone/)

    // The screen agrees with the server: a2 is still accepted, a1 and a3 are not.
    expect(card('a2')).toHaveClass('accepted')
    expect(card('a1')).not.toHaveClass('accepted')
    expect(card('a3')).not.toHaveClass('accepted')
    expect(screen.getByText(/1 high-confidence entities/)).toBeInTheDocument()
    expect(store.entities.find(e => e.id === 'a2')?.accepted).toBe(true)
  }, 20_000)
})

describe('Review — a refresh shows what the server holds (#706)', () => {
  it('shows a decision another session made on the same entity', async () => {
    const { qc } = renderReview()
    await opened()
    // Session B rejects WellMess; session A only refreshes the data.
    applyEntity('e-high', { accepted: false, decision_origin: 'human' })
    await act(() => qc.invalidateQueries({ queryKey: ['entities', 'job-1'] }))
    await waitFor(() => expect(card('e-high')).toHaveClass('rejected'))
  }, 20_000)
})

describe('Review — a failed relationship decision (#706)', () => {
  it('puts the relationship back to the server state, and says so', async () => {
    vi.spyOn(window, 'alert').mockImplementation(() => {})
    api.updateRelationship.mockRejectedValueOnce(new Error('503: unavailable'))
    renderReview()
    await opened()

    fireEvent.click(screen.getByTitle('Reject'))
    await waitFor(() => expect(api.updateRelationship).toHaveBeenCalledWith(
      'job-1', 'r1', { accepted: false },
    ))
    await screen.findByRole('alert')
    expect(document.querySelector('.mbtn.no')).not.toHaveClass('on')
    expect(store.rels[0].accepted).toBeNull()
  }, 20_000)
})

describe('Review — a refused single decision, whatever the failure (#706)', () => {
  it.each([
    ['403', new Error('403: forbidden')],
    ['500', new Error('500: database unavailable')],
    ['network', new TypeError('Failed to fetch')],
  ])('puts the entity back to the server state on a %s', async (_label, failure) => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {})
    api.updateEntity.mockRejectedValueOnce(failure)
    renderReview()
    await opened()

    fireEvent.click(within(card('e-high')).getByTitle('Reject (R)'))
    await screen.findByRole('alert')
    expect(card('e-high')).not.toHaveClass('rejected')
    expect(store.entities.find(e => e.id === 'e-high')?.accepted).toBeNull()
    expect(alert).toHaveBeenCalledWith(expect.stringContaining('was not saved'))
  }, 20_000)
})

describe('Review — a failed "accept all" of one type (#706)', () => {
  it('puts the rows back to the server state, with a retry', async () => {
    api.bulkUpdateEntities.mockRejectedValueOnce(new Error('500: boom'))
    renderReview()
    await opened()

    fireEvent.click(screen.getByTitle(/^Accept all/))
    const alertBox = await screen.findByRole('alert')
    expect(card('e-high')).not.toHaveClass('accepted')
    expect(card('e-control')).not.toHaveClass('accepted')

    fireEvent.click(within(alertBox).getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(api.bulkUpdateEntities).toHaveBeenCalledTimes(2))
  }, 20_000)
})

describe('Review — answers that arrive out of order (#706)', () => {
  it('does not let an older answer overwrite a newer decision on the same entity', async () => {
    const answers: Array<{ ok: () => void }> = []
    api.updateEntity.mockImplementation((_j: string, id: string, patch: Partial<Entity>) => {
      applyEntity(id, patch)   // the store follows the order the requests were sent
      return new Promise(resolve => answers.push({ ok: () => resolve({}) }))
    })
    renderReview()
    await opened()

    fireEvent.click(within(card('e-high')).getByTitle('Accept (A)'))
    fireEvent.click(within(card('e-high')).getByTitle('Reject (R)'))
    await waitFor(() => expect(answers).toHaveLength(2))

    // The newer answer arrives first, then the older one.
    await act(async () => { answers[1].ok() })
    await waitFor(() => expect(card('e-high')).toHaveClass('rejected'))
    await act(async () => { answers[0].ok() })
    await act(async () => { await new Promise(r => setTimeout(r, 30)) })
    expect(card('e-high')).toHaveClass('rejected')
    expect(card('e-high')).not.toHaveClass('accepted')
  }, 20_000)
})
