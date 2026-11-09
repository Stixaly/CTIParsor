// The browser's side of the session (ADR-0097): the CSRF token, and what to do
// when the server says the session is over.  The token lives in memory only: a
// reload asks `GET /api/auth/me` for it again, and the cookie is HttpOnly.

export const CSRF_HEADER = 'X-CSRF-Token'
const WRITES = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

let csrfToken: string | null = null
let redirecting = false
let onSessionEnded: ((loginUrl: string) => void) | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
  if (token) redirecting = false
}

export function isWrite(method: string | undefined): boolean {
  return WRITES.has((method ?? 'GET').toUpperCase())
}

/** The headers a write needs on top of its own: the CSRF token when one is known. */
export function withCsrf(method: string | undefined, headers: HeadersInit | undefined): HeadersInit | undefined {
  if (!csrfToken || !isWrite(method)) return headers
  return { ...Object.fromEntries(new Headers(headers)), [CSRF_HEADER]: csrfToken }
}

/** A local path that is safe to go back to after signing in, else null.
 *  `//host` and `/\host` are other sites for a browser. */
export function safeNext(next: string | null | undefined): string | null {
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return null
  return next
}

export function loginUrl(next?: string): string {
  const safe = safeNext(next)
  return safe && !safe.startsWith('/login') ? `/login?next=${encodeURIComponent(safe)}` : '/login'
}

/** The App registers how to navigate (a router `navigate`); without one the page is reloaded at /login. */
export function setSessionEndedHandler(handler: ((loginUrl: string) => void) | null): void {
  onSessionEnded = handler
}

/** A call answered 401: go to the sign-in page, once.  Nothing happens on the sign-in page itself. */
export function sessionEnded(): void {
  const { pathname, search, hash } = window.location
  if (pathname.startsWith('/login') || redirecting) return
  redirecting = true
  csrfToken = null
  const url = loginUrl(`${pathname}${search}${hash}`)
  if (onSessionEnded) onSessionEnded(url)
  else window.location.assign(url)
}

/** For tests. */
export function resetSession(): void {
  csrfToken = null
  redirecting = false
  onSessionEnded = null
}
