import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Layout from './Layout'
import { ThemeProvider } from '../context/ThemeContext'
import { AuthContext, type AuthState } from '../context/AuthContext'
import { roleAtLeast, type Me, type Role } from '../api/auth'
import packageJson from '../../package.json'

function state(role: Role | null, mode: Me['auth_mode'] = 'local', signOut = vi.fn(() => Promise.resolve())): AuthState {
  const me: Me | null = role
    ? { auth_mode: mode, username: 'alice', display_name: 'Alice Martin', role, auth_source: 'local', csrf_token: 'c' }
    : null
  return {
    status: mode === 'off' ? 'off' : 'signed-in', me,
    can: minimum => roleAtLeast(role, minimum, mode),
    setMe: () => undefined, signOut, refresh: () => Promise.resolve(),
  }
}

function renderLayout(auth: AuthState) {
  const qc = new QueryClient()
  render(
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <AuthContext.Provider value={auth}>
          <MemoryRouter initialEntries={['/dashboard']}>
            <Routes>
              <Route element={<Layout />}>
                <Route path="/dashboard" element={<p>dashboard page</p>} />
              </Route>
              <Route path="/login" element={<p>login page</p>} />
            </Routes>
          </MemoryRouter>
        </AuthContext.Provider>
      </QueryClientProvider>
    </ThemeProvider>,
  )
}

afterEach(() => vi.unstubAllGlobals())

describe('Layout footer', () => {
  it('names CTIParsor and the frontend package version, not the old project name', () => {
    renderLayout(state('reader'))
    expect(screen.getByText(`CTIParsor ${packageJson.version}`)).toBeInTheDocument()
    expect(screen.queryByText(/cti-to-stix/)).not.toBeInTheDocument()
  })
})

describe('Layout and the signed-in user', () => {
  it('with authentication off shows no user menu and hides nothing', () => {
    renderLayout(state(null, 'off'))
    expect(screen.queryByRole('button', { name: /Sign out/ })).not.toBeInTheDocument()
    for (const name of ['Dashboard', 'Policy', 'Settings']) {
      expect(screen.getByRole('link', { name })).toBeInTheDocument()
    }
  })

  it('shows the name, the role and Sign out', () => {
    renderLayout(state('analyst'))
    expect(screen.getByText('Alice Martin')).toBeInTheDocument()
    expect(screen.getByText('analyst')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Sign out/ })).toBeInTheDocument()
  })

  it('hides the pages for administrators from anyone else', () => {
    renderLayout(state('analyst'))
    expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Policy' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument()
  })

  it('shows them to an admin', () => {
    renderLayout(state('admin'))
    expect(screen.getByRole('link', { name: 'Policy' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Settings' })).toBeInTheDocument()
  })

  it('signs out, then goes to the sign-in page', async () => {
    const signOut = vi.fn(() => Promise.resolve())
    renderLayout(state('reader', 'local', signOut))
    fireEvent.click(screen.getByRole('button', { name: /Sign out/ }))
    await waitFor(() => expect(screen.getByText('login page')).toBeInTheDocument())
    expect(signOut).toHaveBeenCalledTimes(1)
  })
})
