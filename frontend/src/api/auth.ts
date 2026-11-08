// Sign-in, sign-out and "who am I" (ADR-0097).  Plain `fetch` for the calls that
// must not send the browser to /login on a 401: an anonymous /me and a wrong
// password are answers, not a session that ended.
import { apiFetch } from './client'
import { setCsrfToken } from './session'

export type Role = 'reader' | 'analyst' | 'admin'
const RANK: Record<Role, number> = { reader: 0, analyst: 1, admin: 2 }

export interface Me {
  auth_mode: 'off' | 'local' | 'oidc' | 'both'
  username: string | null
  display_name: string | null
  role: Role | null
  auth_source: 'local' | 'oidc' | null
  csrf_token: string | null
}

export interface SignInMethods {
  auth_mode: Me['auth_mode']
  local: boolean
  oidc: boolean
}

/** Does `role` reach `minimum`?  Authentication off (no role) reaches everything. */
export function roleAtLeast(role: Role | null | undefined, minimum: Role, mode: Me['auth_mode'] = 'local'): boolean {
  if (mode === 'off') return true
  return !!role && RANK[role] >= RANK[minimum]
}

/** The signed-in user, `null` when the server says nobody is (401).  Keeps the CSRF token. */
export async function fetchMe(): Promise<Me | null> {
  const res = await fetch('/api/auth/me', { credentials: 'same-origin' })
  if (res.status === 401) {
    setCsrfToken(null)
    return null
  }
  if (!res.ok) throw new Error(`${res.status}: ${await res.text().catch(() => res.statusText)}`)
  const me = (await res.json()) as Me
  setCsrfToken(me.csrf_token)
  return me
}

export async function fetchSignInMethods(): Promise<SignInMethods> {
  const res = await fetch('/api/auth/methods', { credentials: 'same-origin' })
  if (!res.ok) throw new Error(`${res.status}: ${await res.text().catch(() => res.statusText)}`)
  return (await res.json()) as SignInMethods
}

/** A sign-in the server refused: `status` 401 (wrong name or password), 429 (locked or too many tries,
 *  `retryAfter` seconds), or another. */
export class SignInError extends Error {
  readonly status: number
  readonly retryAfter: number | null

  constructor(status: number, message: string, retryAfter: number | null = null) {
    super(message)
    this.name = 'SignInError'
    this.status = status
    this.retryAfter = retryAfter
  }
}

async function detailOf(res: Response): Promise<string> {
  const text = await res.text().catch(() => '')
  try {
    const detail = (JSON.parse(text) as { detail?: unknown }).detail
    if (typeof detail === 'string' && detail) return detail
  } catch { /* not JSON */ }
  return text || res.statusText || `HTTP ${res.status}`
}

export async function signIn(username: string, password: string): Promise<Me> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!res.ok) {
    const retry = Number.parseInt(res.headers.get('Retry-After') ?? '', 10)
    throw new SignInError(res.status, await detailOf(res), Number.isFinite(retry) && retry > 0 ? retry : null)
  }
  const me = (await res.json()) as Me
  setCsrfToken(me.csrf_token)
  return me
}

export async function signOut(): Promise<void> {
  // The session is over whatever the answer: do not leave the token behind.
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' })
  } finally {
    setCsrfToken(null)
  }
}
