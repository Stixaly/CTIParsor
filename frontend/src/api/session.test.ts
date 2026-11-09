import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch, deleteJob, fetchJobs } from './client'
import { loginUrl, resetSession, safeNext, setCsrfToken, setSessionEndedHandler } from './session'

function answer(status: number, body: unknown = {}) {
  vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status }))))
}

const call = (n = 0) => vi.mocked(fetch).mock.calls[n]
const sentHeaders = (n = 0) => new Headers(call(n)[1]?.headers)

beforeEach(() => {
  resetSession()
  window.history.pushState({}, '', '/')
})
afterEach(() => vi.unstubAllGlobals())

describe('the CSRF token', () => {
  it('goes on a write and not on a read, and every call sends the cookie', async () => {
    answer(200, [])
    setCsrfToken('tok-123')
    await fetchJobs()
    await deleteJob('j1')
    expect(sentHeaders(0).has('X-CSRF-Token')).toBe(false)
    expect(sentHeaders(1).get('X-CSRF-Token')).toBe('tok-123')
    expect(call(0)[1]?.credentials).toBe('same-origin')
    expect(call(1)[1]?.credentials).toBe('same-origin')
  })

  it('is sent on POST, PUT and PATCH too, with the headers the call has', async () => {
    answer(200)
    setCsrfToken('tok-123')
    for (const method of ['POST', 'PUT', 'PATCH']) {
      await apiFetch('/api/x', { method, headers: { 'Content-Type': 'application/json' } })
    }
    for (const n of [0, 1, 2]) {
      expect(sentHeaders(n).get('X-CSRF-Token')).toBe('tok-123')
      expect(sentHeaders(n).get('Content-Type')).toBe('application/json')
    }
  })

  it('is not sent when none is known (authentication off)', async () => {
    answer(200)
    await apiFetch('/api/x', { method: 'POST' })
    expect(sentHeaders(0).has('X-CSRF-Token')).toBe(false)
  })

  it('is kept in memory, never in browser storage', () => {
    setCsrfToken('tok-secret')
    expect(JSON.stringify({ ...localStorage })).not.toContain('tok-secret')
    expect(JSON.stringify({ ...sessionStorage })).not.toContain('tok-secret')
  })
})

describe('a 401', () => {
  it('goes to /login with the page to come back to, once', async () => {
    answer(401, { detail: 'Authentication required' })
    const go = vi.fn()
    setSessionEndedHandler(go)
    window.history.pushState({}, '', '/review/job-1?tab=text')
    await expect(fetchJobs()).rejects.toThrow('401')
    await expect(fetchJobs()).rejects.toThrow('401')
    expect(go).toHaveBeenCalledTimes(1)
    expect(go).toHaveBeenCalledWith('/login?next=%2Freview%2Fjob-1%3Ftab%3Dtext')
  })

  it('does nothing on the sign-in page itself', async () => {
    answer(401)
    const go = vi.fn()
    setSessionEndedHandler(go)
    window.history.pushState({}, '', '/login?next=%2Fdashboard')
    await apiFetch('/api/x')
    expect(go).not.toHaveBeenCalled()
  })

  it('can happen again after a sign-in', async () => {
    answer(401)
    const go = vi.fn()
    setSessionEndedHandler(go)
    window.history.pushState({}, '', '/dashboard')
    await apiFetch('/api/x')
    setCsrfToken('new-session')
    await apiFetch('/api/x')
    expect(go).toHaveBeenCalledTimes(2)
  })

  it('leaves a 403 to the caller, with the server message', async () => {
    answer(403, { detail: 'This operation needs the admin role' })
    const go = vi.fn()
    setSessionEndedHandler(go)
    await expect(fetchJobs()).rejects.toThrow('This operation needs the admin role')
    expect(go).not.toHaveBeenCalled()
  })
})

describe('where to go after a sign-in', () => {
  it('keeps a local path and refuses anything that leaves the site', () => {
    expect(safeNext('/review/abc?x=1')).toBe('/review/abc?x=1')
    for (const bad of ['//evil.example', '/\\evil.example', 'https://evil.example', 'javascript:alert(1)', '', null, undefined]) {
      expect(safeNext(bad)).toBeNull()
    }
  })

  it('builds the login address', () => {
    expect(loginUrl('/graph/j 1')).toBe('/login?next=%2Fgraph%2Fj%201')
    expect(loginUrl('//evil')).toBe('/login')
    expect(loginUrl('/login?next=%2Fx')).toBe('/login')
  })
})
