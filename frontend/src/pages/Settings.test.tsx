import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Settings from './Settings'
import type { CorpusConfig } from '../types'

// The Redownload button (#369) is offered for every public corpus that has a
// remote, git or tarball alike. Private corpora and path-only corpora have none.
const api = vi.hoisted(() => ({
  fetchCorpora: vi.fn(),
  fetchFormats: vi.fn(),
  syncCorpus: vi.fn(),
  addCorpus: vi.fn(),
  rebuildCorpora: vi.fn(),
}))
vi.mock('../api/client', async (orig) => ({ ...(await orig<object>()), ...api }))

const CORPORA: CorpusConfig[] = [
  { name: 'public-git', adapter: 'sigma', git: 'https://github.com/org/rules.git', subdir: 'rules', license: 'MIT', enabled: true, rules: 3, adapter_available: true },
  { name: 'et-open', adapter: 'sigma', tarball: 'https://example.com/et-open.tar.gz', license: 'BSD', enabled: true, rules: 5, adapter_available: true },
  { name: 'private-git', adapter: 'sigma', git: 'https://github.com/org/private.git', license: 'proprietary', private: true, enabled: true, rules: 2, adapter_available: true },
  { name: 'local-only', adapter: 'sigma', path: '/data/local-rules', license: 'MIT', enabled: true, rules: 1, adapter_available: true },
]

function renderSettings() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Settings />
    </QueryClientProvider>,
  )
}

// The name sits in a wrapper inside the row; the row holds the action buttons.
async function rowOf(name: string): Promise<HTMLElement> {
  const label = await screen.findByText(name)
  return label.parentElement!.parentElement!
}

beforeEach(() => {
  api.fetchCorpora.mockReset().mockResolvedValue({ corpora: CORPORA })
  api.fetchFormats.mockReset().mockResolvedValue({ formats: [{ format: 'sigma', available: true, corpora: 4, rules: 11 }] })
  api.syncCorpus.mockReset().mockResolvedValue({ ok: true, detail: 'ok', rules: 3, file_errors: [], corpora: CORPORA })
  api.addCorpus.mockReset().mockResolvedValue({ ok: true, warning: null, corpora: CORPORA })
  api.rebuildCorpora.mockReset().mockResolvedValue({ total: 16, written: { sigma: 11 }, skipped: [], skip_reasons: {}, file_errors: {} })
})

describe('Settings — Redownload button (#369)', () => {
  it('shows Redownload on a public tarball corpus', async () => {
    renderSettings()
    expect(await within(await rowOf('et-open')).findByRole('button', { name: 'Redownload' })).toBeTruthy()
  })

  it('still shows Redownload on a public git corpus (control)', async () => {
    renderSettings()
    expect(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' })).toBeTruthy()
  })

  it('hides Redownload on a private corpus and on a path-only corpus', async () => {
    renderSettings()
    await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' })
    expect(within(await rowOf('private-git')).queryByRole('button', { name: 'Redownload' })).toBeNull()
    expect(within(await rowOf('local-only')).queryByRole('button', { name: 'Redownload' })).toBeNull()
  })

  it('sends the tarball corpus name to the sync endpoint', async () => {
    renderSettings()
    fireEvent.click(await within(await rowOf('et-open')).findByRole('button', { name: 'Redownload' }))
    await waitFor(() => expect(api.syncCorpus).toHaveBeenCalledWith('et-open'))
  })
})

// Each failed operation used to end in an error state that nothing rendered (#370).
describe('Settings — errors and stale messages (#370)', () => {
  it('shows the API detail of a rejected Redownload on the corpus row', async () => {
    api.syncCorpus.mockRejectedValueOnce(new Error('502: {"detail":"sync failed: repository not found"}'))
    renderSettings()
    fireEvent.click(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' }))
    const alert = await within(await rowOf('public-git')).findByRole('alert')
    expect(alert).toHaveTextContent('repository not found')
    expect(within(await rowOf('et-open')).queryByRole('alert')).toBeNull()
  })

  it('falls back to the error message when the sync body has no detail', async () => {
    api.syncCorpus.mockRejectedValueOnce(new Error('Failed to fetch'))
    renderSettings()
    fireEvent.click(await within(await rowOf('et-open')).findByRole('button', { name: 'Redownload' }))
    expect(await within(await rowOf('et-open')).findByRole('alert')).toHaveTextContent('Failed to fetch')
  })

  it('shows no alert after a successful Redownload (control)', async () => {
    renderSettings()
    fireEvent.click(await within(await rowOf('et-open')).findByRole('button', { name: 'Redownload' }))
    await waitFor(() => expect(api.syncCorpus).toHaveBeenCalledWith('et-open'))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })

  it('clears the previous row error when another Redownload starts', async () => {
    api.syncCorpus.mockRejectedValueOnce(new Error('502: {"detail":"sync failed: repository not found"}'))
    renderSettings()
    fireEvent.click(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' }))
    await within(await rowOf('public-git')).findByRole('alert')
    const publicRow = await rowOf('public-git')
    fireEvent.click(within(await rowOf('et-open')).getByRole('button', { name: 'Redownload' }))
    await waitFor(() => expect(api.syncCorpus).toHaveBeenCalledWith('et-open'))
    await waitFor(() => expect(within(publicRow).queryByRole('alert')).toBeNull())
  })

  it('keeps the add form open and shows the reason when the API refuses the corpus', async () => {
    api.addCorpus.mockRejectedValueOnce(new Error('400: {"detail":"unknown format \'yara\' — known formats: sigma"}'))
    renderSettings()
    const form = (await screen.findByRole('button', { name: 'Add' })).closest('form')!
    fireEvent.change(form.querySelector('input')!, { target: { value: 'new-corpus' } })
    fireEvent.submit(form)
    expect(await screen.findByRole('alert')).toHaveTextContent('unknown format')
    expect(api.addCorpus).toHaveBeenCalledWith(expect.objectContaining({ name: 'new-corpus' }))
    expect(form.isConnected).toBe(true)
    expect((form.querySelector('input') as HTMLInputElement).value).toBe('new-corpus')
  })

  it('shows the API detail of a failed rebuild', async () => {
    api.rebuildCorpora.mockRejectedValueOnce(new Error('500: {"detail":"rebuild failed: disk full"}'))
    renderSettings()
    fireEvent.click(await screen.findByRole('button', { name: 'Rebuild index' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('disk full')
  })

  it('drops the previous rebuild success message when a rebuild fails', async () => {
    api.rebuildCorpora
      .mockResolvedValueOnce({ total: 16, written: { sigma: 11 }, skipped: [], skip_reasons: {}, file_errors: {} })
      .mockRejectedValueOnce(new Error('500: {"detail":"rebuild failed: disk full"}'))
    renderSettings()
    fireEvent.click(await screen.findByRole('button', { name: 'Rebuild index' }))
    expect(await screen.findByText(/^Rebuilt: 16 total/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Rebuild index' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('disk full')
    expect(screen.queryByText(/^Rebuilt:/)).toBeNull()
  })
})

// A missing subdir is a 422 on the sync (#374); unread files and skipped corpora are warnings.
describe('Settings — sync and rebuild warnings (#374)', () => {
  it('shows the 422 of a Redownload whose subdir is missing, naming it', async () => {
    api.syncCorpus.mockRejectedValueOnce(new Error(
      `422: {"detail":"downloaded, but not re-imported: subdir 'rulez' not found under ./corpora/public-git. The rules indexed before are kept."}`,
    ))
    renderSettings()
    fireEvent.click(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' }))
    const alert = await within(await rowOf('public-git')).findByRole('alert')
    expect(alert).toHaveTextContent('not re-imported')
    expect(alert).toHaveTextContent("subdir 'rulez' not found")
    expect(alert).toHaveTextContent('The rules indexed before are kept.')
  })

  it('warns after a Redownload that left files unread, on that row only', async () => {
    api.syncCorpus.mockResolvedValueOnce({
      ok: true, detail: 'up to date', rules: 2, file_errors: [{ path: 'bad.yml', error: 'not UTF-8' }], corpora: CORPORA,
    })
    renderSettings()
    fireEvent.click(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' }))
    const warning = await within(await rowOf('public-git')).findByRole('status')
    expect(warning).toHaveTextContent('1 file was not fully read: bad.yml')
    expect(within(await rowOf('et-open')).queryByRole('status')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('shows no warning after a Redownload that read every file (control)', async () => {
    renderSettings()
    fireEvent.click(await within(await rowOf('public-git')).findByRole('button', { name: 'Redownload' }))
    await waitFor(() => expect(api.syncCorpus).toHaveBeenCalledWith('public-git'))
    await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
  })

  it('warns after a rebuild that skipped a corpus, with the reason', async () => {
    api.rebuildCorpora.mockResolvedValueOnce({
      total: 11,
      written: { sigma: 11 },
      skipped: ['public-git'],
      skip_reasons: { 'public-git': "subdir 'rulez' not found under ./corpora/public-git" },
      file_errors: {},
    })
    renderSettings()
    fireEvent.click(await screen.findByRole('button', { name: 'Rebuild index' }))
    const warning = await screen.findByRole('status')
    expect(warning).toHaveTextContent("public-git was skipped: subdir 'rulez' not found under ./corpora/public-git.")
    expect(screen.getByText(/^Rebuilt: 11 total/)).toBeTruthy()
  })

  it('warns after a rebuild that left files unread, per corpus', async () => {
    api.rebuildCorpora.mockResolvedValueOnce({
      total: 2,
      written: { sigma: 2 },
      skipped: [],
      skip_reasons: {},
      file_errors: { sigma: [{ path: 'a.yml', error: 'x' }, { path: 'b.yml', error: 'y' }] },
    })
    renderSettings()
    fireEvent.click(await screen.findByRole('button', { name: 'Rebuild index' }))
    expect(await screen.findByRole('status')).toHaveTextContent('sigma: 2 files were not fully read: a.yml, b.yml.')
  })

  it('shows no rebuild warning when nothing was skipped or unread (control)', async () => {
    renderSettings()
    fireEvent.click(await screen.findByRole('button', { name: 'Rebuild index' }))
    await waitFor(() => expect(screen.getByText(/^Rebuilt: 16 total/)).toBeTruthy())
    expect(screen.queryByRole('status')).toBeNull()
  })
})
