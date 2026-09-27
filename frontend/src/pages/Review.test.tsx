import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Entity, Relationship } from '../types'
import Review from './Review'

// ADR-0058 — opening the review page used to write accepted=true for every
// entity at or above 90 %, through the same PATCH an analyst's click uses.
// The server applies auto-accept now; the page must only read.

const entity = (over: Partial<Entity>): Entity => ({
  id: 'e1', job_id: 'job-1', value: 'WellMess', entity_type: 'malware',
  context: '', confidence: 0.95, mitre_id: null, accepted: null, source: 'gliner',
  decision_origin: null, control_sample: false,
  ...over,
})

const ENTITIES: Entity[] = [
  entity({ id: 'e-high', value: 'WellMess', confidence: 0.97 }),
  entity({ id: 'e-auto', value: 'APT29', entity_type: 'threat_actor', confidence: 0.92,
           accepted: true, decision_origin: 'auto_policy' }),
  entity({ id: 'e-control', value: 'WellMail', confidence: 0.95, control_sample: true }),
]

const RELS: Relationship[] = [{
  id: 'r1', job_id: 'job-1', source_value: 'APT29', relationship_type: 'uses',
  target_value: 'WellMess', confidence: 0.95, accepted: null, evidence_text: null,
  evidence_label: 'observed',
}]

const api = vi.hoisted(() => ({
  updateEntity: vi.fn(() => Promise.resolve({})),
  updateRelationship: vi.fn(() => Promise.resolve({})),
}))

vi.mock('../api/client', () => ({
  fetchJob: () => Promise.resolve({
    id: 'job-1', original_filename: 'r.txt', status: 'for_review',
    report_text: 'APT29 used WellMess and WellMail.', created_at: '', updated_at: '',
  }),
  fetchEntities: () => Promise.resolve(ENTITIES),
  fetchRelationships: () => Promise.resolve(RELS),
  fetchThresholds: () => Promise.resolve({ enabled: true, auto_accept_level: 0.9, control_sample_rate: 0.1 }),
  fetchCoverageReportRules: () => Promise.resolve({ rules: [] }),
  updateEntity: api.updateEntity,
  updateRelationship: api.updateRelationship,
  createEntity: vi.fn(), createRelationship: vi.fn(),
  finalizeJob: vi.fn(), finalizeJobQuick: vi.fn(() => Promise.resolve({})),
  bulkUpdateEntities: vi.fn(),
  sourceUrl: (id: string) => `/api/jobs/${id}/source`,
  detectionsExportUrl: (id: string) => `/api/jobs/${id}/detections/export`,
  errorDetail: (e: unknown) => String(e),
}))

// The source tab pulls in pdf.js, which needs canvas APIs jsdom does not have.
vi.mock('../components/SourceViewer', () => ({ default: () => null }))

function renderReview() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/review/job-1']}>
        <Routes>
          <Route path="/review/:jobId" element={<Review />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Review — decisions come from the server (ADR-0058)', () => {
  beforeEach(() => {
    api.updateEntity.mockClear()
    api.updateRelationship.mockClear()
  })

  it('writes nothing when the page opens, whatever the confidence', async () => {
    renderReview()
    await screen.findAllByText('WellMess', {}, { timeout: 10_000 })
    // Give any bootstrap effect time to fire its requests.
    await new Promise(r => setTimeout(r, 50))
    expect(api.updateEntity).not.toHaveBeenCalled()
    expect(api.updateRelationship).not.toHaveBeenCalled()
  }, 20_000)

  it('shows the server auto-accept in the banner and flags the control row', async () => {
    renderReview()
    await waitFor(() => expect(screen.getByText(/1 high-confidence entities/)).toBeInTheDocument(),
                  { timeout: 10_000 })
    expect(screen.getByText(/≥ 90% confidence/)).toBeInTheDocument()
    expect(screen.getAllByText('auto').length).toBeGreaterThan(0)
    expect(screen.getAllByText('confirm').length).toBeGreaterThan(0)
  }, 20_000)
})
