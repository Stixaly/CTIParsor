import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Coverage from './Coverage'

const api = vi.hoisted(() => ({
  fetchJob: vi.fn(),
  fetchCoverage: vi.fn(),
  fetchAttackIndex: vi.fn(),
  fetchCoverageReportRules: vi.fn(),
  fetchDetectionProposals: vi.fn(),
  lookupRules: vi.fn(),
  downloadExportSelection: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  ...api,
}))

const RULE = {
  id: 'r1', format: 'sigma', corpus: 'corpus-a', license: 'MIT', severity: 'high',
  title: 'Suspicious PowerShell', bytes: 120, evidence_count: 0, title_count: 0, matches: [],
}

// Promoted from the Proposed-detections panel: outside the coverage set, so its
// metadata has to come from /rules/lookup.
const PROMOTED = {
  id: 'promoted-1', format: 'sigma', corpus: 'corpus-b', license: 'MIT', severity: 'medium',
  title: 'Promoted rule', bytes: 90, description: '', source_ref: '', platform: '', techniques: [], raw: '',
}

const COVERAGE = {
  job_id: 'job-1', techniques_total: 1, by_score: {}, validated: false,
  cells: [{
    technique_id: 'T1059', score: 2, corpora: ['corpus-a'], rule_count: 1,
    by_format: {
      sigma: { rule_count: 1, corpora: ['corpus-a'] },
      suricata: { rule_count: 0, corpora: [] },
      yara: { rule_count: 0, corpora: [] },
    },
  }],
}

const REPORT_RULES = {
  job_id: 'job-1', techniques: [{ technique_id: 'T1059', rules: [RULE] }],
  technique_total: 1, rule_total: 1, tag_total: 1, evidence_total: 0, evidence_only: false,
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/coverage/job-1']}>
        <Routes>
          <Route path="/coverage/:jobId" element={<Coverage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  localStorage.clear()
  localStorage.setItem('coverage.promoted.job-1', JSON.stringify(['promoted-1']))
  api.fetchJob.mockResolvedValue({ job_id: 'job-1', original_filename: 'report.pdf' })
  api.fetchCoverage.mockResolvedValue(COVERAGE)
  api.fetchAttackIndex.mockResolvedValue({ release: '19.2', techniques: [], tactics: [] })
  api.fetchCoverageReportRules.mockResolvedValue(REPORT_RULES)
  api.fetchDetectionProposals.mockResolvedValue({ job_id: 'job-1', proposals: [] })
  api.lookupRules.mockReset()
  api.downloadExportSelection.mockResolvedValue({
    blob: new Blob(['zip'], { type: 'application/zip' }),
    filename: 'report_detection_rules.zip',
  })
  URL.createObjectURL = vi.fn(() => 'blob:zip')
  URL.revokeObjectURL = vi.fn()
})

// #486 — while a promoted rule's metadata is still loading, the page must not offer the
// plain GET ZIP: that link does not carry the promotion, so the archive silently lacked it.
describe('Coverage — ZIP while promoted rule metadata loads (#486)', () => {
  it('offers no GET link, and waits, until the promoted rule metadata has arrived', async () => {
    api.lookupRules.mockReturnValue(new Promise(() => {}))
    renderPage()
    await screen.findByText('Export detection rules')
    expect(document.querySelector('a[download]')).toBeNull()
    expect(screen.getByRole('button', { name: 'Loading promoted rules…' })).toBeDisabled()
  })

  it('includes the promoted rule in the ZIP once its metadata has arrived', async () => {
    api.lookupRules.mockResolvedValue({ rules: [PROMOTED], requested: 1 })
    renderPage()
    const button = await screen.findByRole('button', { name: 'Download ZIP · 2 rules' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() =>
      expect(api.downloadExportSelection).toHaveBeenCalledWith('job-1', ['r1', 'promoted-1']),
    )
  })
})
