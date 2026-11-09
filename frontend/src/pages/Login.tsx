import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchSignInMethods, signIn, SignInError } from '../api/auth'
import { safeNext } from '../api/session'
import { useAuth } from '../context/AuthContext'

/** What `?error=<code>` says.  The identity-provider callback sends the code; an unknown one is shown as it is. */
// The codes GET /api/auth/oidc/callback sends back (api/routes/auth.py, api/auth/oidc.py).
const ERROR_TEXT: Record<string, string> = {
  state: 'The sign-in took too long, or was started in another window or browser. Try again.',
  denied: 'The identity provider did not let you in.',
  no_role: 'Your account is in no group that gives access to CTIParsor. Ask an administrator.',
  disabled: 'This account is disabled.',
  token: "The identity provider's answer could not be verified. Try again, or tell an administrator.",
  idp: 'The identity provider is not reachable or answered wrongly. Try again later.',
  config: 'Sign-in with the identity provider is not configured correctly. Tell an administrator.',
  busy: 'Too many sign-ins are in progress. Try again in a minute.',
}

function errorText(code: string | null): string | null {
  if (!code) return null
  return ERROR_TEXT[code] ?? `Sign-in failed (${code.slice(0, 64)}).`
}

function waitText(seconds: number | null): string {
  if (seconds === null) return 'Too many attempts. Try again later.'
  const minutes = Math.ceil(seconds / 60)
  return seconds > 90
    ? `Too many attempts. Try again in ${minutes} minutes.`
    : `Too many attempts. Try again in ${seconds} ${seconds === 1 ? 'second' : 'seconds'}.`
}

const field: React.CSSProperties = {
  width: '100%', boxSizing: 'border-box', padding: '8px 10px', fontSize: 14,
  border: '1px solid var(--rule)', borderRadius: 6, background: 'var(--bg-soft)', color: 'var(--ink)',
}

export default function Login() {
  const auth = useAuth()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next')) ?? '/dashboard'
  const methods = useQuery({ queryKey: ['sign-in-methods'], queryFn: fetchSignInMethods, retry: false })
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const first = useRef<HTMLInputElement>(null)

  useEffect(() => { first.current?.focus() }, [methods.data?.local])

  // Signed in already (or authentication is off): nothing to do here.
  if (auth.status === 'signed-in' || auth.status === 'off') return <Navigate to={next} replace />

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setFailure(null)
    try {
      const me = await signIn(username.trim(), password)
      setPassword('')
      auth.setMe(me)
      navigate(next, { replace: true })
    } catch (err) {
      if (err instanceof SignInError && err.status === 401) setFailure('Invalid username or password.')
      else if (err instanceof SignInError && err.status === 429) setFailure(waitText(err.retryAfter))
      else if (err instanceof SignInError) setFailure(`${err.status}: ${err.message}`)
      else setFailure('The server did not answer. Try again.')
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  const message = failure ?? errorText(params.get('error'))
  const local = methods.data?.local ?? false
  const oidc = methods.data?.oidc ?? false

  return (
    <div className="t-app" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg)' }}>
      <main style={{
        width: 340, maxWidth: 'calc(100vw - 32px)', padding: 24, borderRadius: 10,
        border: '1px solid var(--rule)', background: 'var(--bg-elev)', color: 'var(--ink)',
      }}>
        <img src="/logo.png" alt="CTIParsor" style={{ width: 164, height: 'auto', filter: 'var(--logo-filter, none)' }} />
        <h1 style={{ fontSize: 17, margin: '16px 0 12px' }}>Sign in</h1>

        <div role="alert" style={{ minHeight: message ? undefined : 0 }}>
          {message && (
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--no)' }}>{message}</p>
          )}
        </div>

        {methods.isLoading && <p style={{ fontSize: 13, color: 'var(--ink-3)' }}>Loading…</p>}
        {methods.isError && (
          <p role="alert" style={{ fontSize: 13, color: 'var(--no)' }}>
            The server did not say how to sign in. Reload the page.
          </p>
        )}

        {local && (
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <label style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 4 }}>
              Username
              <input
                ref={first} style={field} type="text" name="username" autoComplete="username"
                autoCapitalize="none" spellCheck={false} required
                value={username} onChange={e => setUsername(e.target.value)}
              />
            </label>
            <label style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 4 }}>
              Password
              <input
                style={field} type="password" name="password" autoComplete="current-password" required
                value={password} onChange={e => setPassword(e.target.value)}
              />
            </label>
            <button type="submit" className="btn-primary" disabled={busy} style={{ justifyContent: 'center' }}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        )}

        {oidc && (
          <p style={{ margin: local ? '16px 0 0' : 0 }}>
            <a
              className={local ? 'btn-ghost' : 'btn-primary'}
              style={{ display: 'flex', justifyContent: 'center', textDecoration: 'none' }}
              href={`/api/auth/oidc/login?next=${encodeURIComponent(next)}`}
            >
              Sign in with your organisation
            </a>
          </p>
        )}
      </main>
    </div>
  )
}
