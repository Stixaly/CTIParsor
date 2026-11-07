import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Entity, Job, Relationship } from '../types'
import { finalizeJobQuick } from '../api/client'
import { ThemeProvider } from '../context/ThemeContext'
import App from '../App'
import Review from './Review'
import { IMPORTED_TITLE } from '../components/review/MarginaliaCard'

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

const NO_BASE_RULES = {
  job_id: 'job-1', techniques: [], technique_total: 0, rule_total: 0,
  tag_total: 0, evidence_total: 0, evidence_only: false,
}

const JOB: Job = {
  id: 'job-1', original_filename: 'r.txt', status: 'for_review',
  report_text: 'APT29 used WellMess and WellMail.', created_at: '', updated_at: '',
}

const api = vi.hoisted(() => ({
  updateEntity: vi.fn(() => Promise.resolve({})),
  updateRelationship: vi.fn(() => Promise.resolve({})),
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
  createEntity: vi.fn(), createRelationship: vi.fn(),
  finalizeJob: api.finalizeJob, finalizeJobQuick: vi.fn(() => Promise.resolve({})),
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
}

beforeEach(() => {
  api.updateEntity.mockClear()
  api.updateRelationship.mockClear()
  api.finalizeJob.mockReset()
  api.fetchJob.mockReset().mockImplementation(() => Promise.resolve(JOB))
  api.fetchEntities.mockReset().mockImplementation(() => Promise.resolve(ENTITIES))
  api.fetchRelationships.mockReset().mockImplementation(() => Promise.resolve(RELS))
  api.fetchCoverageReportRules.mockReset().mockImplementation(() => Promise.resolve(NO_BASE_RULES))
  localStorage.clear()
})

const opened = () => screen.findAllByText('WellMess', {}, { timeout: 10_000 })

describe('Review — decisions come from the server (ADR-0058)', () => {

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

describe('Review — a decision the store refused (#286)', () => {
  it('restores the accepted entity when its rejection fails, and says so', async () => {
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {})
    api.updateEntity.mockRejectedValueOnce(new Error('503: unavailable'))
    const { container } = renderReview()
    await opened()
    const card = container.querySelector('[data-marg-id="e-auto"]')!
    expect(card).toHaveClass('accepted')
    fireEvent.click(within(card as HTMLElement).getByTitle('Reject (R)'))
    await waitFor(() => expect(api.updateEntity).toHaveBeenCalledWith(
      'job-1', 'e-auto', { accepted: false, decision_origin: 'human' },
    ))
    await waitFor(() => expect(card).toHaveClass('accepted'))
    expect(alert).toHaveBeenCalledWith(expect.stringContaining('was not saved'))
    alert.mockRestore()
  }, 20_000)
})

// #449 — undoing the auto-accept is a decision like any other: the bundle on the
// server no longer matches the page, so it is marked outdated and rebuilt.
describe('Review — undoing the auto-accept (#449)', () => {
  it('marks the bundle outdated and schedules the rebuild when "Undo all" is clicked', async () => {
    vi.mocked(finalizeJobQuick).mockClear()
    renderReview()
    await opened()
    expect(screen.queryByText(/Bundle outdated/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Undo all' }))
    expect(api.updateEntity).toHaveBeenCalledWith(
      'job-1', 'e-auto', { accepted: null, decision_origin: 'human_bulk' },
    )
    await screen.findByText(/Bundle outdated/)
    expect(finalizeJobQuick).not.toHaveBeenCalled()   // debounced, like any edit

    await waitFor(() => expect(finalizeJobQuick).toHaveBeenCalledWith('job-1'), { timeout: 6_000 })
    await screen.findByText(/Bundle current/)   // let the rebuild's state update land in the test
  }, 20_000)
})

describe('Review — a bundle the STIX schemas refused', () => {
  it('says so and why when Finalize is refused, instead of "check server logs"', async () => {
    const { BundleRefusedError } = await vi.importActual<typeof import('../api/client')>('../api/client')
    api.finalizeJob.mockImplementation(() =>
      Promise.reject(new BundleRefusedError(409, ['bad id', 'bad ref', 'bad type', 'bad date'])))
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {})
    renderReview()
    await opened()

    fireEvent.click(screen.getByRole('button', { name: /^Complete Review/ }))

    await waitFor(() => expect(alert).toHaveBeenCalledTimes(1))
    const said = alert.mock.calls[0][0]
    expect(said).toContain('Report not completed.')
    expect(said).toContain('The STIX 2.1 schemas refused this bundle')
    expect(said).toContain('• bad id')
    expect(said).toContain('… and 1 more')
    expect(said).not.toContain('server logs')
    alert.mockRestore()
  }, 20_000)

  it('keeps "check server logs" for a failure that is not a refusal', async () => {
    api.finalizeJob.mockImplementation(() => Promise.reject(new Error('500: boom')))
    const alert = vi.spyOn(window, 'alert').mockImplementation(() => {})
    renderReview()
    await opened()

    fireEvent.click(screen.getByRole('button', { name: /^Complete Review/ }))

    await waitFor(() => expect(alert).toHaveBeenCalledWith('Finalize failed — check server logs'))
    alert.mockRestore()
  }, 20_000)
})

describe('Review — what the page says about itself', () => {
  it('says the first load failed instead of showing an empty report', async () => {
    api.fetchEntities.mockImplementation(() => Promise.reject(new Error('503: Service Unavailable')))
    renderReview()
    expect(await screen.findByText('Could not load this report', {}, { timeout: 10_000 }))
      .toBeInTheDocument()
    expect(screen.queryByText(/Margin notes/)).not.toBeInTheDocument()

    api.fetchEntities.mockImplementation(() => Promise.resolve(ENTITIES))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await opened()
  }, 20_000)

  it('shows the report status in the breadcrumb, not a fixed "For review"', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve({ ...JOB, status: 'reviewing' }))
    renderReview()
    await opened()
    const crumbs = screen.getByRole('navigation', { name: 'Breadcrumb' })
    expect(crumbs).toHaveTextContent('Reviewing')
    expect(crumbs).not.toHaveTextContent('For review')
  }, 20_000)

  it('labels the theme actually applied and returns to the last light theme', async () => {
    localStorage.setItem('review.theme', JSON.stringify('cool'))
    localStorage.setItem('review.accent', JSON.stringify('indigo'))
    renderReview()
    await opened()
    const toggle = screen.getByRole('button', { name: 'Toggle theme' })
    expect(toggle).toHaveTextContent('Cool · indigo')

    fireEvent.click(toggle)
    expect(toggle).toHaveTextContent('Dark · indigo')
    expect(document.documentElement.dataset.theme).toBe('dark')

    fireEvent.click(toggle)   // used to come back Warm
    expect(toggle).toHaveTextContent('Cool · indigo')
    expect(document.documentElement.dataset.theme).toBe('cool')
  }, 20_000)

  it('says when a type filter hides entities, and clears it', async () => {
    renderReview()
    await opened()
    fireEvent.click(screen.getByTitle('Malware'))
    const note = screen.getByRole('status')
    expect(note).toHaveTextContent('Showing 2 of 3 · Malware')

    fireEvent.click(screen.getByRole('button', { name: 'Clear filter' }))
    expect(screen.queryByText(/Showing 2 of 3/)).not.toBeInTheDocument()
  }, 20_000)

  it('opens a folded side panel as a drawer, and Escape closes it', async () => {
    const { container } = renderReview()
    await opened()
    const stage = container.querySelector('.stage')!
    expect(stage).not.toHaveAttribute('data-drawer')

    fireEvent.click(screen.getByRole('button', { name: /^Entities/ }))
    expect(stage).toHaveAttribute('data-drawer', 'entities')
    fireEvent.click(screen.getByRole('button', { name: /^Filters/ }))
    expect(stage).toHaveAttribute('data-drawer', 'filters')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(stage).not.toHaveAttribute('data-drawer')
  }, 20_000)

  it('ignores Ctrl and Meta shortcuts: Ctrl+F does not finalize the report', async () => {
    renderReview()
    await opened()
    fireEvent.keyDown(window, { key: 'f', ctrlKey: true })
    fireEvent.keyDown(window, { key: 'f', metaKey: true })
    expect(api.finalizeJob).not.toHaveBeenCalled()

    fireEvent.keyDown(window, { key: 'f' })
    expect(api.finalizeJob).toHaveBeenCalledWith('job-1')
  }, 20_000)

  it('does not act on a letter typed into a contenteditable element', async () => {
    renderReview()
    await opened()
    const editor = document.createElement('div')
    // jsdom has no layout, so isContentEditable is not computed for us.
    Object.defineProperty(editor, 'isContentEditable', { value: true })
    document.body.appendChild(editor)
    fireEvent.keyDown(editor, { key: 'f' })
    expect(api.finalizeJob).not.toHaveBeenCalled()
    editor.remove()
  }, 20_000)
})

describe('Review — leaving the page with an edit waiting', () => {
  it('rebuilds the bundle on the way out instead of dropping the pending auto-finalize', async () => {
    vi.mocked(finalizeJobQuick).mockClear()
    const { unmount } = renderReview()
    await opened()
    fireEvent.click(screen.getAllByTitle('Accept (A)')[0])
    await screen.findByText(/Bundle outdated/)
    expect(finalizeJobQuick).not.toHaveBeenCalled()

    unmount()
    expect(finalizeJobQuick).toHaveBeenCalledWith('job-1')
  }, 20_000)
})

// ADR-0090 — a job enriched from the analyst's own STIX 2.1 bundle.
describe('Review — a job enriched from the STIX bundle (ADR-0090)', () => {
  const ENRICH_JOB: Job = {
    ...JOB, pipeline_mode: 'enrich',
    enrichment: {
      intake: null, validated: true,
      counts: {
        entities: { matched: 1, baseline_only: 1 },
        relationships: { baseline_in_text: 1 },
      },
    },
  }
  const MATCHED = entity({ id: 'e-match', value: 'WellMess', enrichment_status: 'matched' })
  // Named by the bundle, and not in the report text.
  const STIX_ONLY = entity({ id: 'e-stix', value: 'Emotet', entity_type: 'malware', accepted: true,
                             decision_origin: 'baseline_stix', enrichment_status: 'baseline_only' })
  const COVERED = 'The supplied STIX bundle already covers everything CTIParsor found in this report.'

  it('says the bundle already covers the report when no row is new', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MATCHED, STIX_ONLY]))
    api.fetchRelationships.mockImplementation(() => Promise.resolve([
      { ...RELS[0], enrichment_status: 'baseline_in_text', accepted: true, decision_origin: 'baseline_stix' },
    ]))
    renderReview()
    await opened()
    expect(screen.getByText(COVERED)).toBeInTheDocument()
  }, 20_000)

  it('does not say so while a row is new, nor on a full job', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MATCHED, STIX_ONLY,
      entity({ id: 'e-new', value: 'WellMail', enrichment_status: 'new' })]))
    renderReview()
    await opened()
    expect(screen.queryByText(COVERED)).not.toBeInTheDocument()
  }, 20_000)

  it('does not say so on a full job', async () => {
    renderReview()
    await opened()
    expect(screen.queryByText(COVERED)).not.toBeInTheDocument()
  }, 20_000)

  it('says a bundle-only entity is not in the text when the margin focuses it', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MATCHED, STIX_ONLY]))
    api.fetchRelationships.mockImplementation(() => Promise.resolve([]))
    renderReview()
    await opened()
    fireEvent.click(screen.getByRole('button', { name: 'Emotet' }))
    expect(await screen.findByText('"Emotet" comes from your STIX bundle; it is not in the report text'))
      .toBeInTheDocument()
    expect(screen.queryByText(/not found verbatim in document text/)).not.toBeInTheDocument()
  }, 20_000)

  // A row the analyst added by hand comes back with no bundle status.  It is new
  // to the bundle, so it counts as new and keeps the banner off.
  it('reads a row added by hand as new: no banner, and it is on the "+ New" segment', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MATCHED,
      entity({ id: 'e-hand', value: 'WellMail', enrichment_status: null })]))
    api.fetchRelationships.mockImplementation(() => Promise.resolve([
      { ...RELS[0], enrichment_status: 'baseline_in_text', accepted: true, decision_origin: 'baseline_stix' },
    ]))
    renderReview()
    await opened()
    expect(screen.queryByText(COVERED)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '+ New 1' })).toBeInTheDocument()
  }, 20_000)

  it('does not say the bundle covers the report while a relationship is new', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MATCHED, STIX_ONLY]))
    api.fetchRelationships.mockImplementation(() => Promise.resolve([
      { ...RELS[0], enrichment_status: null },
    ]))
    renderReview()
    await opened()
    expect(screen.queryByText(COVERED)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '+ New 1' })).toBeInTheDocument()
  }, 20_000)

  // The type chip on a mark is the one entry point that reaches changeType with
  // an imported row (the margin card and the rail disable it).
  it('turns Change type off on a row from the bundle, says why, and changes nothing', async () => {
    const IMPORTED_ROW = entity({ id: 'e-imp', value: 'WellMess', enrichment_status: 'baseline_in_text',
                                  accepted: true, decision_origin: 'baseline_stix' })
    api.fetchJob.mockImplementation(() => Promise.resolve(ENRICH_JOB))
    api.fetchEntities.mockImplementation(() => Promise.resolve([IMPORTED_ROW]))
    api.fetchRelationships.mockImplementation(() => Promise.resolve([]))
    renderReview()
    await opened()

    fireEvent.mouseEnter(document.querySelector('mark[data-eid="e-imp"]')!)
    const chip = document.querySelector<HTMLElement>('.chip')!
    const changeType = within(chip).getByTitle(IMPORTED_TITLE)
    expect(changeType).toBeDisabled()
    fireEvent.click(changeType)

    expect(api.updateEntity).not.toHaveBeenCalled()
  }, 20_000)
})

// #366 — the Detection rules button and its ZIP follow the promotions made in
// the Detections panel, including when the report has no base rules.
describe('Review — the Detection rules export follows promotions (#366)', () => {
  let fetchSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchSpy = vi.fn(() => Promise.resolve(new Response(new Blob(['zip']), {
      status: 200, headers: { 'content-disposition': 'attachment; filename="r.zip"' },
    })))
    vi.stubGlobal('fetch', fetchSpy)
    URL.createObjectURL = vi.fn(() => 'blob:review')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('enables the button and POSTs the promoted id when the report has no base rules', async () => {
    localStorage.setItem('coverage.promoted.job-1', JSON.stringify(['new-rule']))
    renderReview()
    await opened()
    const button = await screen.findByRole('button', { name: /Detection rules · 1/ })
    expect(button).toBeEnabled()

    fireEvent.click(button)
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    expect(fetchSpy).toHaveBeenCalledWith('/api/jobs/job-1/detections/export', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ rule_ids: ['new-rule'] }),
    }))
  }, 20_000)

  it('keeps the plain GET when nothing is promoted', async () => {
    api.fetchCoverageReportRules.mockImplementation(() => Promise.resolve({
      ...NO_BASE_RULES, rule_total: 3,
    }))
    renderReview()
    await opened()
    fireEvent.click(await screen.findByRole('button', { name: /Detection rules · 3/ }))
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledTimes(1))
    expect(fetchSpy).toHaveBeenCalledWith('/api/jobs/job-1/detections/export')
  }, 20_000)
})

// #450 — the review page is keyed by job in App.tsx: going to another job must
// not keep the first job's "review completed" state.
describe('Review — changing job (#450)', () => {
  function NextJob() {
    const navigate = useNavigate()
    return <button onClick={() => navigate('/review/job-2')}>Next job</button>
  }

  it('shows Complete Review again on another job after this one was completed', async () => {
    api.finalizeJob.mockResolvedValue({})
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/review/job-1']}>
          <NextJob />
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    await opened()
    fireEvent.click(screen.getByRole('button', { name: /^Complete Review/ }))
    expect(await screen.findByRole('button', { name: 'Download STIX' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Next job' }))
    expect(await screen.findByRole('button', { name: /^Complete Review/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Download STIX' })).not.toBeInTheDocument()
  }, 20_000)
})

// #448 — J and K walk the entities on screen, in the order their value first
// appears in the text, whatever the case of the text.
describe('Review — J and K on the entities on screen (#448)', () => {
  // APT29 is the actor, hidden by the Malware filter; WellMess and WellMail are malware.
  const ACTOR = entity({ id: 'e-actor', value: 'APT29', entity_type: 'threat_actor' })
  const MESS  = entity({ id: 'e-mess', value: 'WellMess' })
  const MAIL  = entity({ id: 'e-mail', value: 'WellMail' })

  // Focusing an entity scrolls its mark into view; jsdom has no layout.
  beforeEach(() => {
    Element.prototype.scrollIntoView = vi.fn()
  })

  it('does not focus an entity that a type filter hides', async () => {
    api.fetchEntities.mockImplementation(() => Promise.resolve([ACTOR, MESS, MAIL]))
    const { container } = renderReview()
    await opened()
    fireEvent.click(screen.getByTitle('Malware'))
    fireEvent.keyDown(window, { key: 'j' })
    expect(container.querySelector('[data-marg-id="e-mess"]')).toHaveClass('focused')
    expect(container.querySelector('[data-marg-id="e-actor"]')).toBeNull()
  }, 20_000)

  it('still walks every pending entity when no filter is active (control)', async () => {
    api.fetchEntities.mockImplementation(() => Promise.resolve([ACTOR, MESS, MAIL]))
    const { container } = renderReview()
    await opened()
    fireEvent.keyDown(window, { key: 'j' })
    expect(container.querySelector('[data-marg-id="e-actor"]')).toHaveClass('focused')
    fireEvent.keyDown(window, { key: 'j' })
    expect(container.querySelector('[data-marg-id="e-mess"]')).toHaveClass('focused')
  }, 20_000)

  it('orders the walk by where the value first appears, whatever its case', async () => {
    api.fetchJob.mockImplementation(() => Promise.resolve({ ...JOB, report_text: 'APT29 used wellmess and WellMail.' }))
    api.fetchEntities.mockImplementation(() => Promise.resolve([MAIL, MESS]))
    const { container } = renderReview()
    await opened()
    fireEvent.keyDown(window, { key: 'j' })
    expect(container.querySelector('[data-marg-id="e-mess"]')).toHaveClass('focused')
  }, 20_000)
})
