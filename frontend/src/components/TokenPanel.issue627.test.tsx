import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import TokenPanel from './TokenPanel'
import type { TokenCreated, TokenRecord } from '../api/admin'

// Regression for #627: after "Copy" on token A, a second token must not show "Copied."
// while its own secret has never been copied.

const tokenOf = (id: string, token: string): TokenCreated => ({
  id,
  name: `name-${id}`,
  user_id: 'u1',
  username: 'alice',
  created_at: '2026-11-09T10:00:00Z',
  expires_at: '2027-02-07T10:00:00Z',
  revoked_at: null,
  last_used_at: null,
  token,
})

function renderPanel(create: (name: string, days: number, userId: string) => Promise<TokenCreated>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const load = (): Promise<TokenRecord[]> => Promise.resolve([])
  return render(
    <QueryClientProvider client={qc}>
      <TokenPanel
        title="API tokens"
        queryKey={['tokens-627']}
        load={load}
        create={create}
        revoke={() => Promise.resolve(null)}
        showUser={false}
      />
    </QueryClientProvider>,
  )
}

async function createToken(name: string) {
  fireEvent.change(screen.getByLabelText('Token name'), { target: { value: name } })
  fireEvent.click(screen.getByRole('button', { name: 'Create token' }))
}

describe('TokenPanel — the "Copied" state after a second token (#627)', () => {
  let writeText: ReturnType<typeof vi.fn>

  beforeEach(() => {
    writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
  })

  it('does not report "Copied." for token B after token A was copied', async () => {
    const tokens = [tokenOf('t-a', 'secret-A'), tokenOf('t-b', 'secret-B')]
    const create = vi.fn(() => Promise.resolve(tokens.shift()!))
    renderPanel(create)

    // Token A: created, then copied.
    await createToken('Token A')
    const field = await screen.findByLabelText('Token')
    expect(field).toHaveValue('secret-A')
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    await screen.findByText('Copied.')
    expect(writeText).toHaveBeenCalledWith('secret-A')

    // Token B, created without closing the notice: the secret shown is B's and was never copied.
    await createToken('Token B')
    await waitFor(() => expect(screen.getByLabelText('Token')).toHaveValue('secret-B'))
    expect(screen.queryByText('Copied.')).not.toBeInTheDocument()
    expect(screen.queryByText(/The browser refused to copy/)).not.toBeInTheDocument()
  })
})
