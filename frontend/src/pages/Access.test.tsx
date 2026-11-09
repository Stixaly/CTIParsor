import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Access from './Access'
import Account from './Account'
import Layout from '../components/Layout'
import { RequireRole } from '../components/RequireAuth'
import { ThemeProvider } from '../context/ThemeContext'
import { AuthContext, type AuthState } from '../context/AuthContext'
import { roleAtLeast, type Me, type Role } from '../api/auth'
import type { TokenRecord, UserRecord } from '../api/admin'

const api = vi.hoisted(() => ({
  listUsers: vi.fn(), createUser: vi.fn(), patchUser: vi.fn(), setUserPassword: vi.fn(),
  listAdminTokens: vi.fn(), createAdminToken: vi.fn(), revokeAdminToken: vi.fn(),
  listOwnTokens: vi.fn(), createOwnToken: vi.fn(), revokeOwnToken: vi.fn(),
}))
vi.mock('../api/admin', () => api)

const user = (over: Partial<UserRecord>): UserRecord => ({
  id: 'u-x', username: 'x', display_name: 'X', auth_source: 'local', role: 'reader', disabled: false,
  created_at: '2026-11-01T10:00:00+00:00', last_login_at: null, ...over,
})
const ROOT = user({ id: 'u-root', username: 'root', display_name: 'Root', role: 'admin' })
const BOB = user({ id: 'u-bob', username: 'bob', display_name: 'Bob', role: 'analyst' })
const SSO = user({ id: 'u-sso', username: 'sso', auth_source: 'oidc' })

const token = (over: Partial<TokenRecord>): TokenRecord => ({
  id: 't-1', name: 'nightly', user_id: 'u-bob', username: 'bob', created_at: '2026-11-01T10:00:00+00:00',
  expires_at: '2099-01-01T00:00:00+00:00', revoked_at: null, last_used_at: null, ...over,
})

/** A row of the users table (the tokens table lists user names too). */
async function userRow(name: string) {
  const table = await screen.findByRole('table', { name: 'Users' })
  return within(table).getByRole('cell', { name }).closest('tr')!
}

function authState(role: Role, username = 'root'): AuthState {
  const me: Me = { auth_mode: 'local', username, display_name: username, role, auth_source: 'local', csrf_token: 'c' }
  return {
    status: 'signed-in', me, can: m => roleAtLeast(role, m, 'local'),
    setMe: () => undefined, signOut: () => Promise.resolve(), refresh: () => Promise.resolve(),
  }
}

function renderAt(path: string, role: Role = 'admin') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <AuthContext.Provider value={authState(role)}>
          <MemoryRouter initialEntries={[path]}>
            <Routes>
              <Route element={<Layout />}>
                <Route path="/dashboard" element={<p>dashboard page</p>} />
                <Route path="/account" element={<Account />} />
                <Route element={<RequireRole role="admin" />}>
                  <Route path="/access" element={<Access />} />
                </Route>
              </Route>
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

beforeEach(() => {
  for (const fn of Object.values(api)) fn.mockReset()
  api.listUsers.mockResolvedValue([ROOT, BOB, SSO])
  api.listAdminTokens.mockResolvedValue([token({})])
  api.listOwnTokens.mockResolvedValue([])
  Object.assign(navigator, { clipboard: { writeText: vi.fn(() => Promise.resolve()) } })
})

describe('Access page', () => {
  it('is absent for a non-admin: no link, and the address goes to the dashboard', async () => {
    renderAt('/access', 'analyst')
    expect(await screen.findByText('dashboard page')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Access' })).not.toBeInTheDocument()
    expect(api.listUsers).not.toHaveBeenCalled()
  })

  it('lists the users and the tokens for an admin', async () => {
    renderAt('/access')
    expect(await screen.findByRole('cell', { name: 'bob' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Access' })).toBeInTheDocument()
    expect(await screen.findByText('nightly')).toBeInTheDocument()
  })

  it('creates a user and shows an error as the API sent it', async () => {
    api.createUser.mockRejectedValueOnce(new Error('409: {"detail":"the username \'carol\' is taken"}'))
    renderAt('/access')
    await screen.findByRole('cell', { name: 'bob' })
    const form = screen.getByRole('form', { name: 'New user' })
    fireEvent.change(within(form).getByLabelText('Username'), { target: { value: 'carol' } })
    fireEvent.change(within(form).getByLabelText('Role'), { target: { value: 'analyst' } })
    fireEvent.change(within(form).getByLabelText(/Password/), { target: { value: 'a long enough password' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Create user' }))
    expect(await screen.findByText("the username 'carol' is taken")).toBeInTheDocument()

    api.createUser.mockResolvedValueOnce(user({ id: 'u-carol', username: 'carol' }))
    fireEvent.click(within(form).getByRole('button', { name: 'Create user' }))
    await waitFor(() => expect(api.createUser).toHaveBeenLastCalledWith({
      username: 'carol', role: 'analyst', display_name: '', password: 'a long enough password',
    }))
    await waitFor(() => expect(screen.queryByText("the username 'carol' is taken")).not.toBeInTheDocument())
    expect(within(form).getByLabelText('Username')).toHaveValue('')
  })

  it('changes a role at once', async () => {
    api.patchUser.mockResolvedValue({ ...BOB, role: 'admin' })
    renderAt('/access')
    fireEvent.change(await screen.findByLabelText('Role of bob'), { target: { value: 'admin' } })
    await waitFor(() => expect(api.patchUser).toHaveBeenCalledWith('u-bob', { role: 'admin' }))
  })

  it('cannot change or disable the signed-in admin', async () => {
    renderAt('/access')
    expect(await screen.findByLabelText('Role of root')).toBeDisabled()
    const row = await userRow('root')
    expect(within(row).getByRole('button', { name: 'Disable' })).toBeDisabled()
  })

  it('asks before disabling, and does it on the second click', async () => {
    api.patchUser.mockResolvedValue({ ...BOB, disabled: true })
    renderAt('/access')
    const row = await userRow('bob')
    fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
    expect(api.patchUser).not.toHaveBeenCalled()
    fireEvent.click(within(row).getByRole('button', { name: 'Cancel' }))
    expect(api.patchUser).not.toHaveBeenCalled()
    fireEvent.click(within(row).getByRole('button', { name: 'Disable' }))
    fireEvent.click(within(row).getByRole('button', { name: 'Disable bob' }))
    await waitFor(() => expect(api.patchUser).toHaveBeenCalledWith('u-bob', { disabled: true }))
  })

  it('enables a disabled user without asking', async () => {
    api.listUsers.mockResolvedValue([ROOT, { ...BOB, disabled: true }])
    api.patchUser.mockResolvedValue(BOB)
    renderAt('/access')
    fireEvent.click(await screen.findByRole('button', { name: 'Enable' }))
    await waitFor(() => expect(api.patchUser).toHaveBeenCalledWith('u-bob', { disabled: false }))
  })

  it('sets a password for a local user only', async () => {
    api.setUserPassword.mockResolvedValue({ id: 'u-bob', username: 'bob', sessions_ended: true })
    renderAt('/access')
    const sso = await userRow('sso')
    expect(within(sso).queryByRole('button', { name: 'Set password' })).not.toBeInTheDocument()
    const row = await userRow('bob')
    fireEvent.click(within(row).getByRole('button', { name: 'Set password' }))
    fireEvent.change(within(row).getByLabelText('New password for bob'), { target: { value: 'brand new password' } })
    fireEvent.click(within(row).getByRole('button', { name: 'Save password' }))
    await waitFor(() => expect(api.setUserPassword).toHaveBeenCalledWith('u-bob', 'brand new password'))
    expect(await screen.findByText(/Password of bob saved/)).toBeInTheDocument()
  })

  it('shows a created token once, with a copy button and the warning, and never again', async () => {
    api.createAdminToken.mockResolvedValue({ ...token({ id: 't-2', name: 'ci' }), token: 'ctp_secret-value' })
    renderAt('/access')
    await screen.findByText('nightly')
    const panel = screen.getByRole('region', { name: 'Tokens' })
    fireEvent.change(within(panel).getByLabelText('For user'), { target: { value: 'u-bob' } })
    fireEvent.change(within(panel).getByLabelText('Token name'), { target: { value: 'ci' } })
    fireEvent.change(within(panel).getByLabelText(/Days/), { target: { value: '30' } })
    fireEvent.click(within(panel).getByRole('button', { name: 'Create token' }))

    const notice = await screen.findByRole('region', { name: 'New token' })
    expect(within(notice).getByLabelText('Token')).toHaveValue('ctp_secret-value')
    expect(notice).toHaveTextContent('will not be shown again')
    expect(api.createAdminToken).toHaveBeenCalledWith({ user_id: 'u-bob', name: 'ci', days: 30 })
    fireEvent.click(within(notice).getByRole('button', { name: 'Copy' }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ctp_secret-value'))
    expect(await within(notice).findByText('Copied.')).toBeInTheDocument()

    fireEvent.click(within(notice).getByRole('button', { name: 'I have copied it' }))
    expect(screen.queryByDisplayValue('ctp_secret-value')).not.toBeInTheDocument()
    expect(screen.queryByText(/ctp_secret-value/)).not.toBeInTheDocument()
  })

  it('asks before revoking a token', async () => {
    api.revokeAdminToken.mockResolvedValue({ revoked: 't-1' })
    renderAt('/access')
    const row = (await screen.findByText('nightly')).closest('tr')!
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }))
    expect(api.revokeAdminToken).not.toHaveBeenCalled()
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke nightly' }))
    await waitFor(() => expect(api.revokeAdminToken).toHaveBeenCalledWith('t-1'))
  })

  it('offers no revoke for a token that is already revoked or expired', async () => {
    api.listAdminTokens.mockResolvedValue([
      token({ id: 't-r', name: 'old', revoked_at: '2026-11-02T00:00:00+00:00' }),
      token({ id: 't-e', name: 'late', expires_at: '2020-01-01T00:00:00+00:00' }),
    ])
    renderAt('/access')
    expect(await screen.findByText('old')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
    expect(screen.getByText('revoked')).toBeInTheDocument()
    expect(screen.getByText('expired')).toBeInTheDocument()
  })
})

describe('Account page (My tokens)', () => {
  it('is there for every user, with their own tokens only', async () => {
    api.listOwnTokens.mockResolvedValue([token({ id: 't-9', name: 'laptop', username: 'ana' })])
    renderAt('/account', 'reader')
    expect(await screen.findByText('laptop')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'My tokens' })).toBeInTheDocument()
    expect(api.listUsers).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('For user')).not.toBeInTheDocument()
  })

  it('creates a token for the caller, shown once, and revokes it after a confirmation', async () => {
    api.listOwnTokens.mockResolvedValue([token({ id: 't-9', name: 'laptop' })])
    api.createOwnToken.mockResolvedValue({ ...token({ id: 't-10', name: 'phone' }), token: 'ctp_mine' })
    api.revokeOwnToken.mockResolvedValue({ revoked: 't-9' })
    renderAt('/account', 'analyst')
    await screen.findByText('laptop')
    fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'phone' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByLabelText('Token')).toHaveValue('ctp_mine')
    expect(api.createOwnToken).toHaveBeenCalledWith({ name: 'phone', days: 90 })

    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(api.revokeOwnToken).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Revoke laptop' }))
    await waitFor(() => expect(api.revokeOwnToken).toHaveBeenCalledWith('t-9'))
  })

  it('shows the API error of a refused creation', async () => {
    api.createOwnToken.mockRejectedValue(new Error('400: {"detail":"a token needs a name of 1 to 128 characters"}'))
    renderAt('/account', 'reader')
    await screen.findByText('No tokens.')
    fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }))
    expect(await screen.findByText('a token needs a name of 1 to 128 characters')).toBeInTheDocument()
  })
})
