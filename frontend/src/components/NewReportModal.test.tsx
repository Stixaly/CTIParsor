import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { BaselineIntake, BaselineReport, BaselineStatus } from '../types'
import NewReportModal from './NewReportModal'

// The New report modal in enrich mode (ADR-0090): the analyst's STIX 2.1 bundle
// is read before the job exists, and travels again with the job request.

const api = vi.hoisted(() => ({
  fetchBaselineStatus: vi.fn(),
  inspectBaseline: vi.fn(),
  uploadFile: vi.fn(),
  ingestText: vi.fn(),
  ingestUrl: vi.fn(),
}))

vi.mock('../api/client', async importOriginal => ({
  ...(await importOriginal<typeof import('../api/client')>()),
  fetchBaselineStatus: api.fetchBaselineStatus,
  inspectBaseline: api.inspectBaseline,
  uploadFile: api.uploadFile,
  ingestText: api.ingestText,
  ingestUrl: api.ingestUrl,
}))

const ON: BaselineStatus = { enabled: true, max_bytes: 20 * 1048576, max_objects: 50000 }
const OFF: BaselineStatus = { ...ON, enabled: false }

const TEXT = 'The APT29 report describes a phishing campaign against ministries.'
const BUNDLE_TEXT = JSON.stringify({ type: 'bundle', id: 'bundle--1', objects: [] })

const APT29: BaselineReport = { id: 'report--a', name: 'APT29 report', published: '2026-09-28T00:00:00Z', refs: 5 }
const LAZARUS: BaselineReport = { id: 'report--b', name: 'Lazarus campaign', published: null, refs: 2 }

// One report, nothing to choose: what the server answers for a usable bundle.
const INTAKE: BaselineIntake = {
  sha256: 'abc',
  bundle_id: 'bundle--1',
  counts: { indicator: 3, malware: 1, identity: 1, out_of_scope: 2, dangling_refs: 1 },
  excluded: [
    { id: 'indicator--3c7f9a2e-0000-4000-8000-000000000001', type: 'indicator', reason: 'baseline_invalid', detail: 'pattern does not parse' },
    { id: 'malware--9d1e4b7c-0000-4000-8000-000000000002', type: 'malware', reason: 'baseline_refs_closure', detail: 'refers to an excluded object' },
  ],
  warnings: ['One detection rule was kept as text'],
  reports: [APT29],
  scope_report_id: 'report--a',
  needs_report_choice: false,
  min_tlp: null,
  min_pap: null,
}

// Several reports and none chosen: the scope, counts and minimum wait for a choice.
const CHOICE: BaselineIntake = {
  ...INTAKE,
  counts: {},
  excluded: [],
  warnings: [],
  reports: [APT29, LAZARUS],
  scope_report_id: null,
  needs_report_choice: true,
}

// The same bundle, scoped to the Lazarus report.
const LAZARUS_SCOPE: BaselineIntake = {
  ...INTAKE,
  counts: { indicator: 2 },
  excluded: [],
  warnings: [],
  reports: [APT29, LAZARUS],
  scope_report_id: 'report--b',
}

function bundleFile(name = 'apt29-bundle.json') {
  return new File([BUNDLE_TEXT], name, { type: 'application/json' })
}

function renderModal(props: { initialFile?: File | null } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <NewReportModal open onClose={vi.fn()} onJobCreated={vi.fn()} {...props} />
    </QueryClientProvider>,
  )
  return qc
}

type User = ReturnType<typeof userEvent.setup>

async function enrichWithBundle(user: User, bundle: File) {
  await user.click(await screen.findByRole('radio', { name: /Enrich an existing STIX 2.1 bundle/ }))
  await user.upload(screen.getByLabelText('STIX bundle file'), bundle)
}

async function setMarks(user: User, tlp: string, pap: string) {
  await user.click(within(screen.getByRole('radiogroup', { name: 'TLP marking' })).getByRole('radio', { name: tlp }))
  await user.click(within(screen.getByRole('radiogroup', { name: 'PAP marking' })).getByRole('radio', { name: pap }))
}

beforeEach(() => {
  api.fetchBaselineStatus.mockReset()
  api.fetchBaselineStatus.mockResolvedValue(ON)
  api.inspectBaseline.mockReset()
  api.uploadFile.mockReset()
  api.uploadFile.mockResolvedValue({ job_id: 'job-1', filename: 'report.pdf' })
  api.ingestText.mockReset()
  api.ingestText.mockResolvedValue({ job_id: 'job-2', filename: 'paste.txt' })
  api.ingestUrl.mockReset()
})

describe('New report — enrich mode (ADR-0090)', () => {
  it('hides the mode selector when the flag is off, and full mode sends no bundle', async () => {
    api.fetchBaselineStatus.mockResolvedValue(OFF)
    const user = userEvent.setup()
    const qc = renderModal()
    await waitFor(() => expect(qc.getQueryState(['baselineStatus'])?.status).toBe('success'))

    expect(screen.queryByRole('radiogroup', { name: 'Pipeline mode' })).not.toBeInTheDocument()
    await user.type(screen.getByPlaceholderText(/Paste the report text/), TEXT)
    await setMarks(user, 'GREEN', 'WHITE')
    await user.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(api.ingestText).toHaveBeenCalledTimes(1))
    expect(api.ingestText.mock.calls[0][0]).not.toHaveProperty('baseline_bundle')
    expect(api.inspectBaseline).not.toHaveBeenCalled()
  })

  it('keeps full mode alone when the status cannot be read', async () => {
    api.fetchBaselineStatus.mockRejectedValue(new Error('503: Service Unavailable'))
    const qc = renderModal()
    await waitFor(() => expect(qc.getQueryState(['baselineStatus'])?.status).toBe('error'))

    expect(screen.queryByRole('radiogroup', { name: 'Pipeline mode' })).not.toBeInTheDocument()
  })

  it('blocks submit in enrich mode until a bundle is added', async () => {
    const user = userEvent.setup()
    renderModal()
    await user.click(await screen.findByRole('radio', { name: /Enrich an existing STIX 2.1 bundle/ }))
    await user.type(screen.getByPlaceholderText(/Paste the report text/), TEXT)
    await setMarks(user, 'GREEN', 'WHITE')

    expect(screen.getByRole('button', { name: 'Add the STIX bundle to continue' })).toBeDisabled()
    expect(api.inspectBaseline).not.toHaveBeenCalled()
  })

  it('reads the picked bundle and shows what it keeps, drops and warns about', async () => {
    api.inspectBaseline.mockResolvedValue(INTAKE)
    const user = userEvent.setup()
    renderModal()
    const bundle = bundleFile()
    await enrichWithBundle(user, bundle)

    expect(await screen.findByText('2 invalid objects will be ignored')).toBeInTheDocument()
    expect(api.inspectBaseline).toHaveBeenCalledWith(bundle, undefined)
    expect(screen.getByText('5 objects kept from the bundle')).toBeInTheDocument()
    expect(screen.getByText('indicator 3')).toBeInTheDocument()
    expect(screen.getByText('malware 1')).toBeInTheDocument()
    expect(screen.getByText("2 objects outside the report's scope, left out")).toBeInTheDocument()
    expect(screen.getByText('1 reference points at ids the bundle does not hold')).toBeInTheDocument()
    expect(screen.getByText('One detection rule was kept as text')).toBeInTheDocument()
    expect(screen.getByText('indicator 3c7f9a2e · invalid STIX object')).toHaveAttribute('title', 'pattern does not parse')
  })

  it('preselects the bundle minimum TLP and disables the weaker levels', async () => {
    api.inspectBaseline.mockResolvedValue({ ...INTAKE, min_tlp: 'AMBER' })
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())

    const tlp = await screen.findByRole('radiogroup', { name: 'TLP marking' })
    await waitFor(() => expect(within(tlp).getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true'))
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toBeDisabled()
    expect(within(tlp).getByRole('radio', { name: 'CLEAR' })).toBeDisabled()
    expect(within(tlp).getByRole('radio', { name: 'AMBER+STRICT' })).toBeEnabled()
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toHaveAttribute('title', 'The supplied STIX bundle carries TLP:AMBER; a lower marking would weaken it')
    expect(screen.getByText('at least TLP:AMBER, from the bundle')).toBeInTheDocument()

    // min_pap is null: the PAP row stays as it was, nothing preselected or disabled.
    const pap = screen.getByRole('radiogroup', { name: 'PAP marking' })
    for (const level of ['RED', 'AMBER', 'GREEN', 'WHITE']) {
      expect(within(pap).getByRole('radio', { name: level })).toBeEnabled()
      expect(within(pap).getByRole('radio', { name: level })).toHaveAttribute('aria-checked', 'false')
    }
  })

  it('requires the report choice, then reads the bundle again for the report picked', async () => {
    api.inspectBaseline.mockResolvedValueOnce(CHOICE).mockResolvedValueOnce(LAZARUS_SCOPE)
    const user = userEvent.setup()
    const reportFile = new File(['report'], 'report.pdf', { type: 'application/pdf' })
    renderModal({ initialFile: reportFile })
    const bundle = bundleFile()
    await enrichWithBundle(user, bundle)

    await screen.findByRole('radiogroup', { name: 'Report to enrich' })
    await setMarks(user, 'GREEN', 'RED')
    expect(screen.getByRole('button', { name: 'Choose the report to enrich' })).toBeDisabled()
    expect(screen.queryByText(/kept from the bundle/)).not.toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: /Lazarus campaign/ }))
    await waitFor(() => expect(api.inspectBaseline).toHaveBeenCalledTimes(2))
    expect(api.inspectBaseline).toHaveBeenLastCalledWith(bundle, 'report--b')
    expect(await screen.findByText('2 objects kept from the bundle')).toBeInTheDocument()

    const submit = screen.getByRole('button', { name: 'Create job' })
    await waitFor(() => expect(submit).toBeEnabled())
    await user.click(submit)

    await waitFor(() => expect(api.uploadFile).toHaveBeenCalledTimes(1))
    expect(api.uploadFile).toHaveBeenCalledWith(reportFile, {
      tlpLevel: 'GREEN', papLevel: 'RED', baselineStix: bundle, baselineReportId: 'report--b',
    })
  })

  it('drops the bundle and its minimum when switching back to full mode', async () => {
    api.inspectBaseline.mockResolvedValue({ ...INTAKE, min_tlp: 'AMBER' })
    const user = userEvent.setup()
    const reportFile = new File(['report'], 'report.pdf', { type: 'application/pdf' })
    renderModal({ initialFile: reportFile })
    await enrichWithBundle(user, bundleFile())

    const tlp = await screen.findByRole('radiogroup', { name: 'TLP marking' })
    await waitFor(() => expect(within(tlp).getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true'))

    await user.click(screen.getByRole('radio', { name: /Full extraction/ }))
    expect(screen.queryByLabelText('STIX bundle file')).not.toBeInTheDocument()
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toBeEnabled()

    await setMarks(user, 'GREEN', 'WHITE')
    await user.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(api.uploadFile).toHaveBeenCalledTimes(1))
    expect(api.uploadFile).toHaveBeenCalledWith(reportFile, { tlpLevel: 'GREEN', papLevel: 'WHITE' })
    expect(api.uploadFile.mock.calls[0][1]).not.toHaveProperty('baselineStix')
    expect(api.uploadFile.mock.calls[0][1]).not.toHaveProperty('baselineReportId')
  })

  it('shows an inspect error and blocks submit', async () => {
    api.inspectBaseline.mockRejectedValue(new Error('400: {"detail":"not a STIX 2.1 bundle"}'))
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())

    expect(await screen.findByText('not a STIX 2.1 bundle')).toBeInTheDocument()
    await user.type(screen.getByPlaceholderText(/Paste the report text/), TEXT)
    await setMarks(user, 'GREEN', 'WHITE')
    // The bundle is there, but its read failed: the label says to fix it, not to add it.
    expect(screen.getByRole('button', { name: 'Fix the STIX bundle to continue' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Add the STIX bundle to continue' })).not.toBeInTheDocument()
  })

  it('refuses a bundle over the size limit without reading it', async () => {
    const big = new File(['{}'], 'huge.json', { type: 'application/json' })
    Object.defineProperty(big, 'size', { value: 21 * 1048576 })
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, big)

    expect(await screen.findByText('The STIX bundle is larger than 20 MB')).toBeInTheDocument()
    expect(api.inspectBaseline).not.toHaveBeenCalled()
    // Nothing was kept, so there is no bundle to fix: the label asks for one.
    expect(screen.getByRole('button', { name: 'Add the STIX bundle to continue' })).toBeDisabled()
  })

  it('replaces the server note about the schemas with the plain one', async () => {
    api.inspectBaseline.mockResolvedValue({
      ...INTAKE,
      warnings: ['the STIX schemas were not checked in this preview', 'One detection rule was kept as text'],
    })
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())

    expect(await screen.findByText('One detection rule was kept as text')).toBeInTheDocument()
    expect(screen.queryByText(/the STIX schemas were not checked/)).not.toBeInTheDocument()
    expect(screen.getByText(/The STIX schemas are checked when the job starts/)).toBeInTheDocument()
  })

  it('sends the pasted text with the bundle text in enrich mode', async () => {
    api.inspectBaseline.mockResolvedValue(INTAKE)
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())
    await screen.findByText('2 invalid objects will be ignored')

    await user.type(screen.getByPlaceholderText(/Paste the report text/), TEXT)
    await setMarks(user, 'GREEN', 'WHITE')
    await user.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(api.ingestText).toHaveBeenCalledTimes(1))
    expect(api.ingestText.mock.calls[0][0]).toMatchObject({ text: TEXT, baseline_bundle: BUNDLE_TEXT, baseline_report_id: null })
  })

  it('sends a URL with the bundle text in enrich mode', async () => {
    api.inspectBaseline.mockResolvedValue(INTAKE)
    api.ingestUrl.mockResolvedValue({ job_id: 'job-3', filename: 'page.pdf' })
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())
    await screen.findByText('2 invalid objects will be ignored')

    await user.type(screen.getByPlaceholderText(/Paste the report text/), 'https://example.org/apt29')
    await setMarks(user, 'GREEN', 'WHITE')
    await user.click(screen.getByRole('button', { name: 'Create job' }))

    await waitFor(() => expect(api.ingestUrl).toHaveBeenCalledTimes(1))
    expect(api.ingestUrl.mock.calls[0][0]).toMatchObject({
      url: 'https://example.org/apt29', baseline_bundle: BUNDLE_TEXT, baseline_report_id: null,
    })
  })

  it('starts a reopened modal in full mode, with no bundle', async () => {
    api.inspectBaseline.mockResolvedValue({ ...INTAKE, min_tlp: 'AMBER' })
    const user = userEvent.setup()
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const modal = (open: boolean) => (
      <QueryClientProvider client={qc}>
        <NewReportModal open={open} onClose={vi.fn()} onJobCreated={vi.fn()} />
      </QueryClientProvider>
    )
    const { rerender } = render(modal(true))
    await enrichWithBundle(user, bundleFile())
    await waitFor(() => expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' }))
      .getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true'))

    rerender(modal(false))
    rerender(modal(true))

    expect(await screen.findByRole('radio', { name: /Full extraction/ })).toHaveAttribute('aria-checked', 'true')
    expect(screen.queryByLabelText('STIX bundle file')).not.toBeInTheDocument()
    expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' })).getByRole('radio', { name: 'GREEN' })).toBeEnabled()
  })

  it('drops an inspect that answers after the modal was closed and reopened', async () => {
    let answer!: (intake: BaselineIntake) => void
    api.inspectBaseline.mockReturnValueOnce(new Promise<BaselineIntake>(resolve => { answer = resolve }))
    const user = userEvent.setup()
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const modal = (open: boolean) => (
      <QueryClientProvider client={qc}>
        <NewReportModal open={open} onClose={vi.fn()} onJobCreated={vi.fn()} />
      </QueryClientProvider>
    )
    const { rerender } = render(modal(true))
    await enrichWithBundle(user, bundleFile())
    await waitFor(() => expect(api.inspectBaseline).toHaveBeenCalledTimes(1))

    rerender(modal(false))
    rerender(modal(true))
    await act(async () => { answer({ ...INTAKE, min_tlp: 'AMBER' }) })

    expect(screen.getByRole('radio', { name: /Full extraction/ })).toHaveAttribute('aria-checked', 'true')
    expect(screen.queryByText(/kept from the bundle/)).not.toBeInTheDocument()
    const tlp = screen.getByRole('radiogroup', { name: 'TLP marking' })
    expect(within(tlp).getAllByRole('radio').filter(r => r.getAttribute('aria-checked') === 'true')).toHaveLength(0)
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toBeEnabled()
  })

  it('raises TLP to the bundle minimum when it arrives after the analyst picked GREEN', async () => {
    let answer!: (intake: BaselineIntake) => void
    api.inspectBaseline.mockReturnValueOnce(new Promise<BaselineIntake>(resolve => { answer = resolve }))
    const user = userEvent.setup()
    renderModal()
    await enrichWithBundle(user, bundleFile())
    await setMarks(user, 'GREEN', 'WHITE')

    await act(async () => { answer({ ...INTAKE, min_tlp: 'AMBER' }) })

    const tlp = screen.getByRole('radiogroup', { name: 'TLP marking' })
    expect(within(tlp).getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true')
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toHaveAttribute('aria-checked', 'false')
    expect(within(tlp).getByRole('radio', { name: 'GREEN' })).toBeDisabled()
  })

  it('sets a mark the bundle raised back to null when the mode goes back to full', async () => {
    api.inspectBaseline.mockResolvedValue({ ...INTAKE, min_tlp: 'AMBER' })
    const user = userEvent.setup()
    renderModal({ initialFile: new File(['report'], 'report.pdf', { type: 'application/pdf' }) })
    await enrichWithBundle(user, bundleFile())
    await waitFor(() => expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' }))
      .getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true'))
    await user.click(within(screen.getByRole('radiogroup', { name: 'PAP marking' })).getByRole('radio', { name: 'WHITE' }))

    await user.click(screen.getByRole('radio', { name: /Full extraction/ }))

    expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' })).getByRole('radio', { name: 'AMBER' }))
      .toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('button', { name: 'Set TLP & PAP to continue' })).toBeDisabled()
    await user.click(within(screen.getByRole('radiogroup', { name: 'TLP marking' })).getByRole('radio', { name: 'GREEN' }))
    expect(screen.getByRole('button', { name: 'Create job' })).toBeEnabled()
  })

  it('keeps a mark the analyst picked after the bundle raised it, when the mode goes back to full', async () => {
    api.inspectBaseline.mockResolvedValue({ ...INTAKE, min_tlp: 'AMBER' })
    const user = userEvent.setup()
    renderModal({ initialFile: new File(['report'], 'report.pdf', { type: 'application/pdf' }) })
    await enrichWithBundle(user, bundleFile())
    await waitFor(() => expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' }))
      .getByRole('radio', { name: 'AMBER' })).toHaveAttribute('aria-checked', 'true'))
    await setMarks(user, 'RED', 'WHITE')

    await user.click(screen.getByRole('radio', { name: /Full extraction/ }))

    expect(within(screen.getByRole('radiogroup', { name: 'TLP marking' })).getByRole('radio', { name: 'RED' }))
      .toHaveAttribute('aria-checked', 'true')
  })

  it('lets the report be picked again after its read failed, and hides the last counts meanwhile', async () => {
    const SCOPE_A: BaselineIntake = { ...LAZARUS_SCOPE, scope_report_id: 'report--a' }
    api.inspectBaseline
      .mockResolvedValueOnce(CHOICE)
      .mockResolvedValueOnce(SCOPE_A)
      .mockRejectedValueOnce(new Error('500: {"detail":"the scope could not be read"}'))
      .mockResolvedValueOnce(LAZARUS_SCOPE)
    const user = userEvent.setup()
    const reportFile = new File(['report'], 'report.pdf', { type: 'application/pdf' })
    renderModal({ initialFile: reportFile })
    const bundle = bundleFile()
    await enrichWithBundle(user, bundle)

    await user.click(await screen.findByRole('radio', { name: 'APT29 report' }))
    expect(await screen.findByText('2 objects kept from the bundle')).toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: /Lazarus campaign/ }))
    expect(await screen.findByText('the scope could not be read')).toBeInTheDocument()
    expect(screen.queryByText(/kept from the bundle/)).not.toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: /Lazarus campaign/ }))
    await waitFor(() => expect(api.inspectBaseline).toHaveBeenCalledTimes(4))
    expect(api.inspectBaseline).toHaveBeenLastCalledWith(bundle, 'report--b')
    expect(await screen.findByText('2 objects kept from the bundle')).toBeInTheDocument()

    await setMarks(user, 'GREEN', 'RED')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create job' })).toBeEnabled())
  })
})
