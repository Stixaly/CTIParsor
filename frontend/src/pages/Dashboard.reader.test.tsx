// #707 — a reader opens a report read-only: the Dashboard does not send the
// analyst's status change before it opens a report "for review".

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Job } from '../types'
import Dashboard from './Dashboard'
import { AuthContext, type AuthState } from '../context/AuthContext'

const JOB: Job = {
  id: 'job-1', original_filename: 'apt29.pdf', status: 'for_review',
  created_at: '2026-09-28T08:00:00Z', updated_at: '2026-09-28T08:00:00Z',
  entity_count: 12, relationship_count: 3,
}

const api = vi.hoisted(() => ({
  fetchJobs: vi.fn(),
  updateJobStatus: vi.fn(),
  fetchBaselineStatus: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchJobs: api.fetchJobs,
  updateJobStatus: api.updateJobStatus,
  fetchBaselineStatus: api.fetchBaselineStatus,
}))

const signedIn = (role: 'reader' | 'analyst'): AuthState => ({
  status: 'signed-in',
  me: { auth_mode: 'local', username: 'u', display_name: 'U', role, auth_source: 'local', csrf_token: 'c' },
  can: minimum => minimum === 'reader' || role === 'analyst',
  setMe: () => undefined, signOut: () => Promise.resolve(), refresh: () => Promise.resolve(),
})

function renderAs(role: 'reader' | 'analyst') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <AuthContext.Provider value={signedIn(role)}>
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/review/:jobId" element={<p>review page</p>} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  api.fetchJobs.mockReset().mockResolvedValue([JOB])
  api.updateJobStatus.mockReset()
  api.fetchBaselineStatus.mockReset().mockResolvedValue({ enabled: false, max_bytes: 0, max_objects: 0 })
})

describe('Dashboard — a reader opens a report (#707)', () => {
  it('opens a for_review report without sending a status change', async () => {
    renderAs('reader')

    fireEvent.click(await screen.findByRole('button', { name: 'Analyse' }))

    expect(await screen.findByText('review page')).toBeInTheDocument()
    expect(api.updateJobStatus).not.toHaveBeenCalled()
  })

  it('an analyst still moves the report to Reviewing before it opens', async () => {
    api.updateJobStatus.mockResolvedValue({ status: 'reviewing' })
    renderAs('analyst')

    fireEvent.click(await screen.findByRole('button', { name: 'Analyse' }))

    expect(await screen.findByText('review page')).toBeInTheDocument()
    expect(api.updateJobStatus).toHaveBeenCalledWith('job-1', 'reviewing')
  })
})
