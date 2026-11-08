import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Login from './Login'
import { AuthProvider } from '../context/AuthContext'
import { resetSession } from '../api/session'
import type { Me } from '../api/auth'

const ME: Me = {
  auth_mode: 'local', username: 'alice', display_name: 'Alice', role: 'analyst', auth_source: 'local', csrf_token: 'csrf-1',
}
const METHODS = { auth_mode: 'local', local: true, oidc: false }

interface Answers { login?: Response; methods?: unknown }

function serve({ login, methods = METHODS }: Answers = {}) {
  const fetchSpy = vi.fn((url: string) => {
    if (url === '/api/auth/methods') return Promise.resolve(new Response(JSON.stringify(methods)))
    if (url === '/api/auth/me') return Promise.resolve(new Response('{"detail":"Authentication required"}', { status: 401 }))
    if (url === '/api/auth/login') return Promise.resolve(login ?? new Response(JSON.stringify(ME)))
    return Promise.resolve(new Response('{}', { status: 404 }))
  })
  vi.stubGlobal('fetch', fetchSpy)
  return fetchSpy
}

function Where() {
  const l = useLocation()
  return <p data-testid="where">{l.pathname}</p>
}

function renderLogin(url = '/login') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <AuthProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="*" element={<Where />} />
          </Routes>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function fill(user = 'alice', password = 'correct horse battery') {
  fireEvent.change(await screen.findByLabelText('Username'), { target: { value: user } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: password } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
}

beforeEach(() => resetSession())
afterEach(() => vi.unstubAllGlobals())

describe('Login', () => {
  it('has labelled fields with the right autocomplete hints', async () => {
    serve()
    renderLogin()
    expect(await screen.findByLabelText('Username')).toHaveAttribute('autocomplete', 'username')
    expect(screen.getByLabelText('Password')).toHaveAttribute('autocomplete', 'current-password')
    expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password')
    expect(screen.queryByText('Sign in with your organisation')).not.toBeInTheDocument()
  })

  it('signs in and goes to the dashboard, sending the credentials as JSON', async () => {
    const spy = serve()
    renderLogin()
    await fill()
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/dashboard'))
    const call = spy.mock.calls.find(([url]) => url === '/api/auth/login') as unknown as [string, RequestInit]
    expect(JSON.parse(call[1].body as string)).toEqual({ username: 'alice', password: 'correct horse battery' })
  })

  it('goes back to the page asked for', async () => {
    serve()
    renderLogin('/login?next=%2Freview%2Fjob-1')
    await fill()
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/review/job-1'))
  })

  it('does not follow a next that leaves the site', async () => {
    serve()
    renderLogin('/login?next=%2F%2Fevil.example%2Fx')
    await fill()
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/dashboard'))
  })

  it('says the username or password is wrong, in an alert, and empties the password', async () => {
    serve({ login: new Response('{"detail":"Invalid username or password"}', { status: 401 }) })
    renderLogin()
    await fill('alice', 'wrong password!!')
    const message = await screen.findByText('Invalid username or password.')
    expect(message.closest('[role="alert"]')).not.toBeNull()
    expect(screen.getByLabelText('Password')).toHaveValue('')
    expect(screen.queryByTestId('where')).toBeNull()
  })

  it('says how long to wait after too many attempts', async () => {
    serve({ login: new Response('{"detail":"Too many failed sign-in attempts; try again later"}', {
      status: 429, headers: { 'Retry-After': '900' },
    }) })
    renderLogin()
    await fill()
    expect(await screen.findByText('Too many attempts. Try again in 15 minutes.')).toBeInTheDocument()
  })

  it('says seconds for a short wait', async () => {
    serve({ login: new Response('{}', { status: 429, headers: { 'Retry-After': '30' } }) })
    renderLogin()
    await fill()
    expect(await screen.findByText('Too many attempts. Try again in 30 seconds.')).toBeInTheDocument()
  })

  it('shows the error the identity provider sent back', async () => {
    serve()
    renderLogin('/login?error=access_denied')
    expect(await screen.findByText('The identity provider did not let you in.')).toBeInTheDocument()
  })

  it('links to the organisation sign-in only when it is on, and keeps next', async () => {
    serve({ methods: { auth_mode: 'both', local: true, oidc: true } })
    renderLogin('/login?next=%2Fgraph%2Fj1')
    const link = await screen.findByRole('link', { name: 'Sign in with your organisation' })
    expect(link).toHaveAttribute('href', '/api/auth/oidc/login?next=%2Fgraph%2Fj1')
    expect(screen.getByLabelText('Username')).toBeInTheDocument()
  })

  it('shows no password form when only the organisation sign-in is on', async () => {
    serve({ methods: { auth_mode: 'oidc', local: false, oidc: true } })
    renderLogin()
    expect(await screen.findByRole('link', { name: 'Sign in with your organisation' })).toBeInTheDocument()
    expect(screen.queryByLabelText('Username')).not.toBeInTheDocument()
  })

  it('works from the keyboard: Enter in the password field submits', async () => {
    serve()
    renderLogin()
    fireEvent.change(await screen.findByLabelText('Username'), { target: { value: 'alice' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'correct horse battery' } })
    fireEvent.submit(screen.getByLabelText('Password').closest('form')!)
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/dashboard'))
  })
})
