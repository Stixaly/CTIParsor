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
  api.syncCorpus.mockReset().mockResolvedValue({ ok: true, detail: 'ok', corpora: CORPORA })
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
