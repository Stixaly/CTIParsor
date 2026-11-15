import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import App from '../App'
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

// The whole App is rendered in one test (#879): authentication is off, as it is by default.
vi.mock('../api/auth', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/auth')>()),
  fetchMe: () => Promise.resolve({
    auth_mode: 'off', username: null, display_name: null, role: null, auth_source: null, csrf_token: null,
  }),
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

// #877 — the report's rules did not load: no figure, no export, and a way to ask again.
describe('Coverage — the report rules did not load (#877)', () => {
  it('says so, offers Retry, and draws neither the gate figures nor the export', async () => {
    api.fetchCoverageReportRules.mockRejectedValueOnce(new Error('503: Service Unavailable'))
    renderPage()

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the rules of this report')
    expect(screen.queryByText(/No public rule holds anything/)).not.toBeInTheDocument()
    expect(screen.queryByText('Export detection rules')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Export detection rules')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

// #878 — the promoted ids are looked up once the report's rules are in, 500 at a time.
describe('Coverage — promoted rules looked up in batches (#878)', () => {
  it('does not look promoted ids up while the report rules are still loading', async () => {
    api.fetchCoverageReportRules.mockReturnValue(new Promise(() => {}))
    renderPage()

    expect(await screen.findByText('Loading rules…')).toBeInTheDocument()
    expect(api.lookupRules).not.toHaveBeenCalled()
  })

  it('splits more than 500 promoted ids over lookups, and merges their rules', async () => {
    const ids = Array.from({ length: 501 }, (_, i) => `promoted-${i}`)
    localStorage.setItem('coverage.promoted.job-1', JSON.stringify(ids))
    api.lookupRules.mockImplementation((batch: string[]) => Promise.resolve({
      rules: batch.map(id => ({ ...PROMOTED, id })), requested: batch.length,
    }))
    renderPage()

    const button = await screen.findByRole('button', { name: 'Download ZIP · 502 rules' })
    await waitFor(() => expect(button).toBeEnabled())
    expect(api.lookupRules.mock.calls.map(([batch]) => (batch as string[]).length)).toEqual([500, 1])
  })
})

// #879 — the page is keyed by job in App.tsx: the drill-in of one report must not carry over to the next.
describe('Coverage — changing job (#879)', () => {
  const TWO_CELLS = {
    ...COVERAGE,
    techniques_total: 2,
    cells: [
      COVERAGE.cells[0],
      { ...COVERAGE.cells[0], technique_id: 'T1566', score: 1 },
    ],
  }

  function NextJob() {
    const navigate = useNavigate()
    return <button onClick={() => navigate('/coverage/job-2')}>Next job</button>
  }

  // The matrix cell that is drilled into carries the accent outline.
  const drilledCell = () =>
    [...document.querySelectorAll<HTMLElement>('div')].find(d => d.style.outline.includes('solid'))

  it('drills into the default technique of the new job, not the one picked on the last', async () => {
    api.fetchCoverage.mockResolvedValue(TWO_CELLS)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={['/coverage/job-1']}>
          <NextJob />
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    fireEvent.click((await screen.findAllByText('T1566'))[0])
    await waitFor(() => expect(drilledCell()?.textContent).toContain('T1566'))

    fireEvent.click(screen.getByRole('button', { name: 'Next job' }))
    await waitFor(() => expect(drilledCell()?.textContent).toContain('T1059'))
  })
})
