import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Job } from '../types'
import Dashboard from './Dashboard'

// A server that does not answer must not look like an empty Dashboard, and a
// report that cannot be opened must say so.

const JOB: Job = {
  id: 'job-1', original_filename: 'apt29.pdf', status: 'for_review',
  created_at: '2026-09-28T08:00:00Z', updated_at: '2026-09-28T08:00:00Z',
  entity_count: 12, relationship_count: 3,
}

const api = vi.hoisted(() => ({
  fetchJobs: vi.fn(),
  updateJobStatus: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchJobs: api.fetchJobs,
  updateJobStatus: api.updateJobStatus,
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
