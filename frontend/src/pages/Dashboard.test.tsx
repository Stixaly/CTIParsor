import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { BaselineIntake, Job } from '../types'
import Dashboard from './Dashboard'

// A server that does not answer must not look like an empty Dashboard, and a
// report that cannot be opened must say so.

const JOB: Job = {
  id: 'job-1', original_filename: 'apt29.pdf', status: 'for_review',
  created_at: '2026-09-28T08:00:00Z', updated_at: '2026-09-28T08:00:00Z',
  entity_count: 12, relationship_count: 3,
}

const BUNDLE_TEXT = JSON.stringify({ type: 'bundle', id: 'bundle--1', objects: [] })
// One report, nothing to choose: what the server answers for a usable bundle.
const INTAKE: BaselineIntake = {
  sha256: 'abc', bundle_id: 'bundle--1', counts: {}, excluded: [], warnings: [],
  reports: [{ id: 'report--a', name: 'APT29 report', published: null, refs: 0 }],
  scope_report_id: 'report--a', needs_report_choice: false, min_tlp: null, min_pap: null,
}

const api = vi.hoisted(() => ({
  fetchJobs: vi.fn(),
  updateJobStatus: vi.fn(),
  fetchBaselineStatus: vi.fn(),
  inspectBaseline: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchJobs: api.fetchJobs,
  updateJobStatus: api.updateJobStatus,
  fetchBaselineStatus: api.fetchBaselineStatus,
  inspectBaseline: api.inspectBaseline,
}))

function renderDashboard() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/review/:jobId" element={<p>review page</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return qc
}

beforeEach(() => {
  api.fetchJobs.mockReset()
  api.updateJobStatus.mockReset()
  api.fetchBaselineStatus.mockReset()
  api.fetchBaselineStatus.mockResolvedValue({ enabled: false, max_bytes: 0, max_objects: 0 })
  api.inspectBaseline.mockReset()
})

describe('Dashboard — a failed load is not an empty list', () => {
  it('says the reports could not be loaded, with no zero counters', async () => {
    api.fetchJobs.mockRejectedValue(new Error('503: Service Unavailable'))
    renderDashboard()

    expect(await screen.findByText('Could not load the reports')).toBeInTheDocument()
    expect(screen.queryByText('Nothing here')).not.toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(4)
    expect(screen.getByText('reports unavailable')).toBeInTheDocument()

    api.fetchJobs.mockResolvedValue([JOB])
    fireEvent.click(screen.getByRole('button', { name: /Retry/ }))
    expect(await screen.findByText('apt29.pdf')).toBeInTheDocument()
    expect(screen.queryByText('Could not load the reports')).not.toBeInTheDocument()
  })

  it('keeps the last list on a failed refresh, and says it is not current', async () => {
    api.fetchJobs.mockResolvedValueOnce([JOB])
    const qc = renderDashboard()
    expect(await screen.findByText('apt29.pdf')).toBeInTheDocument()

    api.fetchJobs.mockRejectedValue(new Error('503: Service Unavailable'))
    await qc.refetchQueries({ queryKey: ['jobs'] })

    expect(await screen.findByText(/Could not refresh the reports/)).toBeInTheDocument()
    expect(screen.getByText('apt29.pdf')).toBeInTheDocument()
  })
})

describe('Dashboard — opening a report', () => {
  it('moves a report to Reviewing, then opens it', async () => {
    api.fetchJobs.mockResolvedValue([JOB])
    api.updateJobStatus.mockResolvedValue({ status: 'reviewing' })
    renderDashboard()

    fireEvent.click(await screen.findByRole('button', { name: 'Analyse' }))
    expect(await screen.findByText('review page')).toBeInTheDocument()
    expect(api.updateJobStatus).toHaveBeenCalledWith('job-1', 'reviewing')
  })

  it('says why it did not open, and can open it anyway', async () => {
    api.fetchJobs.mockResolvedValue([JOB])
    api.updateJobStatus.mockRejectedValue(new Error('500: Internal Server Error'))
    renderDashboard()

    fireEvent.click(await screen.findByRole('button', { name: 'Analyse' }))
    expect(await screen.findByText(/Could not open “apt29.pdf”/)).toBeInTheDocument()
    expect(screen.queryByText('review page')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Open anyway' }))
    expect(await screen.findByText('review page')).toBeInTheDocument()
  })
})

describe('Dashboard — a drop on the page (ADR-0090)', () => {
  it('opens the modal with a dropped .json that is not a bundle, and names it as not used', async () => {
    api.fetchJobs.mockResolvedValue([JOB])
    renderDashboard()
    await screen.findByText('apt29.pdf')
    const config = new File(['{"type":"settings"}'], 'config.json', { type: 'application/json' })

    fireEvent.drop(screen.getByText('Dashboard', { selector: 'span' }), { dataTransfer: { files: [config] } })

    expect(await screen.findByText('config.json is not a STIX 2.1 bundle: not used')).toBeInTheDocument()
  })

  it('opens the modal in enrich mode with a dropped report and bundle, both taken', async () => {
    api.fetchJobs.mockResolvedValue([JOB])
    api.fetchBaselineStatus.mockResolvedValue({ enabled: true, max_bytes: 20 * 1048576, max_objects: 50000 })
    api.inspectBaseline.mockResolvedValue(INTAKE)
    renderDashboard()
    await screen.findByText('apt29.pdf')
    const report = new File(['report'], 'lazarus.pdf', { type: 'application/pdf' })
    const bundle = new File([BUNDLE_TEXT], 'apt29-bundle.json', { type: 'application/json' })

    fireEvent.drop(screen.getByText('Dashboard', { selector: 'span' }), { dataTransfer: { files: [report, bundle] } })

    await waitFor(() => expect(screen.getByRole('radio', { name: /Enrich an existing STIX 2.1 bundle/ })).toHaveAttribute('aria-checked', 'true'))
    expect(await screen.findByText('lazarus.pdf')).toBeInTheDocument()
    expect(await screen.findByText('apt29-bundle.json')).toBeInTheDocument()
    await waitFor(() => expect(api.inspectBaseline).toHaveBeenCalledWith(bundle, undefined))
  })
})

describe('Dashboard — enrich jobs (ADR-0090)', () => {
  it('marks an enrich job with a badge, and a full job with none', async () => {
    api.fetchJobs.mockResolvedValue([JOB, { ...JOB, id: 'job-2', original_filename: 'lazarus.pdf', pipeline_mode: 'enrich' }])
    renderDashboard()

    expect(await screen.findByText('lazarus.pdf')).toBeInTheDocument()
    expect(screen.getByTitle('Enriches an existing STIX 2.1 bundle (ADR-0090)')).toHaveTextContent('Enrich')
    expect(screen.getAllByText('Enrich')).toHaveLength(1)
  })
})
