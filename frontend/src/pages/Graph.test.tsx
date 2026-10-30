import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Graph, { RelEditor } from './Graph'
import type { GraphEdge, GraphNode } from '../components/graph/graphLayout'
import type { Entity, Job, Relationship, StixBundle } from '../types'

const api = vi.hoisted(() => ({
  fetchJob: vi.fn(),
  fetchEntities: vi.fn(),
  fetchRelationships: vi.fn(),
  fetchBundle: vi.fn(),
  fetchBundleLedger: vi.fn(),
  deleteRelationship: vi.fn(),
  finalizeJobQuick: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchJob: api.fetchJob,
  fetchEntities: api.fetchEntities,
  fetchRelationships: api.fetchRelationships,
  fetchBundle: api.fetchBundle,
  fetchBundleLedger: api.fetchBundleLedger,
  deleteRelationship: api.deleteRelationship,
  finalizeJobQuick: api.finalizeJobQuick,
}))

// The relationship editor's Delete (ADR-0090): the server refuses to delete a row of the
// analyst's STIX bundle, so the button is off for it, says why, and a refusal is shown inline.

const node = (id: string, name: string, type: string): GraphNode => ({
  id, type, name, confidence: 1, source: 'llm', mitre_id: null, context: '', accepted: true,
})
const NODES = [node('a', 'APT29', 'threat_actor'), node('b', 'WINELOADER', 'malware')]
const BY_ID = new Map(NODES.map(n => [n.id, n]))

const edge = (id: string, accepted: boolean | null): GraphEdge => ({
  id, source: 'a', target: 'b', rel: 'uses', confidence: 0.8, accepted, evidence: '',
})

const BUNDLE_TITLE = 'From your STIX bundle: reject it in the review instead'

function renderEditor(over: Partial<Parameters<typeof RelEditor>[0]> = {}) {
  const props = {
    jobId: 'job-1', nodes: NODES, edges: [edge('rel-bundle', true), edge('rel-new', null)], byId: BY_ID,
    imported: new Set(['rel-bundle']), deleteError: null, labelOf: (id: string) => id,
    onClose: vi.fn(), onPick: vi.fn(), onAccept: vi.fn(), onReject: vi.fn(), onReset: vi.fn(),
    onDelete: vi.fn(), onCreate: vi.fn(), onAddEntity: vi.fn(() => Promise.resolve()),
    ...over,
  }
  render(<RelEditor {...props} />)
  return props
}

describe('RelEditor — Delete (ADR-0090)', () => {
  it('turns Delete off for a row of the analyst’s bundle, and says why', () => {
    renderEditor()

    expect(screen.getByTitle(BUNDLE_TITLE)).toBeDisabled()
  })

  it('keeps Delete on for a row the review made, and deletes that row', () => {
    const props = renderEditor()

    expect(screen.getAllByTitle('Delete')).toHaveLength(1)
    fireEvent.click(screen.getByTitle('Delete'))

    expect(props.onDelete).toHaveBeenCalledWith('rel-new')
  })

  it('shows the server’s reason inline when a delete is refused', () => {
    renderEditor({ deleteError: 'this row is from your STIX bundle' })

    expect(screen.getByRole('alert')).toHaveTextContent('Not deleted: this row is from your STIX bundle')
  })

  it('shows no refusal line before a delete fails', () => {
    renderEditor()

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

const JOB: Job = {
  id: 'job-1', original_filename: 'apt29.pdf', status: 'for_review',
  created_at: '2026-09-28T08:00:00Z', updated_at: '2026-09-28T08:00:00Z',
  entity_count: 2, relationship_count: 1,
}
const ENTITIES: Entity[] = [
  { id: 'ent-a', job_id: 'job-1', value: 'APT29', entity_type: 'threat_actor', context: '', confidence: 1, mitre_id: null, accepted: true, source: 'llm' },
  { id: 'ent-b', job_id: 'job-1', value: 'WINELOADER', entity_type: 'malware', context: '', confidence: 1, mitre_id: null, accepted: true, source: 'llm' },
]
const RELATIONS: Relationship[] = [
  { id: 'rel-1', job_id: 'job-1', source_value: 'APT29', relationship_type: 'uses', target_value: 'WINELOADER',
    confidence: 0.9, accepted: null, evidence_text: null },
]

function renderGraph() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/graph/job-1']}>
        <Routes><Route path="/graph/:jobId" element={<Graph />} /></Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Graph page — a refused delete is reported where it happened (ADR-0090)', () => {
  beforeEach(() => {
    api.fetchJob.mockResolvedValue(JOB)
    api.fetchEntities.mockResolvedValue(ENTITIES)
    api.fetchRelationships.mockResolvedValue(RELATIONS)
    api.fetchBundle.mockRejectedValue(new Error('404: no bundle yet'))
    api.fetchBundleLedger.mockResolvedValue(null)
    api.finalizeJobQuick.mockResolvedValue(undefined)
    api.deleteRelationship.mockReset()
    api.deleteRelationship.mockRejectedValue(new Error('this row is from your STIX bundle'))
  })

  // The review view: an endpoint of a row is a node there, so picking it selects it.
  it('drops the refusal once the analyst picks another object in the editor', async () => {
    renderGraph()
    fireEvent.click(await screen.findByRole('button', { name: 'Review rows' }))
    fireEvent.click(await screen.findByTitle('Edit links'))
    fireEvent.click(await screen.findByTitle('Delete'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Not deleted: this row is from your STIX bundle')

    fireEvent.click(screen.getByRole('button', { name: 'WINELOADER' }))

    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  })

  it('drops the refusal when the editor closes', async () => {
    renderGraph()
    fireEvent.click(await screen.findByRole('button', { name: 'Review rows' }))
    fireEvent.click(await screen.findByTitle('Edit links'))
    fireEvent.click(await screen.findByTitle('Delete'))
    expect(await screen.findByRole('alert')).toBeInTheDocument()

    fireEvent.click(screen.getByTitle('Edit links'))

    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
    fireEvent.click(screen.getByTitle('Edit links'))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

describe('Graph page — a node’s context is Markdown only from the bundle (ADR-0093)', () => {
  const BUNDLE: StixBundle = { id: 'bundle--1', type: 'bundle', objects: [
    { id: 'threat-actor--a', type: 'threat-actor', name: 'APT29', description: 'Mentioned in *R*:\n\n> A sentence.' },
  ] }

  beforeEach(() => {
    api.fetchJob.mockResolvedValue(JOB)
    api.fetchEntities.mockResolvedValue([{ ...ENTITIES[0], context: '*a* and http://x.test' }, ENTITIES[1]])
    api.fetchRelationships.mockResolvedValue([])
    api.fetchBundle.mockRejectedValue(new Error('404: no bundle yet'))
    api.fetchBundleLedger.mockResolvedValue(null)
  })

  // The LLM's context of a review row is plain text: no emphasis, no link.
  it('keeps the context of a review row plain text', async () => {
    renderGraph()
    fireEvent.click(await screen.findByRole('button', { name: 'Review rows' }))
    fireEvent.change(await screen.findByPlaceholderText('Search nodes…'), { target: { value: 'APT29' } })
    fireEvent.mouseDown(await screen.findByRole('button', { name: /APT29/ }))

    const context = await screen.findByText('*a* and http://x.test')
    expect(context.tagName).toBe('DD')
    expect(context.querySelector('em, a')).toBeNull()
  })

  it('draws a bundle object’s description as Markdown in its detail panel', async () => {
    api.fetchBundle.mockResolvedValue(BUNDLE)
    renderGraph()
    fireEvent.click(await screen.findByRole('button', { name: 'STIX bundle' }))
    fireEvent.change(await screen.findByPlaceholderText('Search nodes…'), { target: { value: 'APT29' } })
    fireEvent.mouseDown(await screen.findByRole('button', { name: /APT29/ }))

    const section = (await screen.findByText('Description')).parentElement!
    expect(section.querySelector('blockquote')?.textContent?.trim()).toBe('A sentence.')
    expect(section.querySelector('em')?.textContent).toBe('R')
  })
})
