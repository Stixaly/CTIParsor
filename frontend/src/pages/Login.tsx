import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchSignInMethods, signIn, SignInError } from '../api/auth'
import { safeNext } from '../api/session'
import { useAuth } from '../context/AuthContext'
import { FileText } from 'lucide-react'

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

/** The example graph on the sign-in page; coordinates are in the 1440 x 900 design frame. */
const TREE = [
  'M 456 839.8 L 456 424.2',
  'M 456 454.8 C 407.1 424.2 272.7 442.6 168.8 375.3',
  'M 456 454.8 C 437.7 393.7 333.8 357 272.7 338.7',
  'M 456 454.8 C 474.3 393.7 578.2 357 639.3 338.7',
  'M 456 454.8 C 504.9 424.2 639.3 442.6 743.2 375.3',
  'M 456 503.7 C 566 503.7 718.8 503.7 810.4 485.3',
  'M 456 503.7 C 346 503.7 199.3 503.7 101.6 485.3',
  'M 456 693.1 C 419.3 742 260.4 766.4 150.4 803.1',
  'M 456 693.1 C 437.7 766.4 358.2 815.3 303.2 839.8',
  'M 456 693.1 C 474.3 766.4 553.8 815.3 614.9 839.8',
  'M 456 693.1 C 492.7 742 651.6 766.4 767.7 803.1',
]

// `at`: reveal start in seconds (the arrowhead fades in 0.7 s later); `pill`: left, top, width.
const RELS = [
  { type: 'uses', line: 'M 410.1 361.5 L 209.9 438.5', head: 'M 215.3 433.2 L 209.9 438.5 L 217.5 438.8', at: 3.0, pill: [259, 373, 38] },
  { type: 'uses', line: 'M 469.9 361.5 L 670.1 438.5', head: 'M 662.5 438.8 L 670.1 438.5 L 664.7 433.2', at: 3.85, pill: [573, 373, 38] },
  { type: 'uses', line: 'M 440 382 L 440 503', head: 'M 437 496 L 440 503 L 443 496', at: 4.7, pill: [454, 427, 38] },
  { type: 'located-at', line: 'M 471.9 348.2 L 758.1 331.8', head: 'M 751.2 335.2 L 758.1 331.8 L 750.9 329.2', at: 5.55, pill: [580, 317, 74] },
  { type: 'indicates', line: 'M 150.4 630 L 409.6 545', head: 'M 403.9 550 L 409.6 545 L 402 544.3', at: 6.4, pill: [242, 566, 68] },
  { type: 'drops', line: 'M 421.6 561.2 L 318.4 708.8', head: 'M 319.9 701.3 L 318.4 708.8 L 324.8 704.8', at: 7.25, pill: [318, 627, 44] },
  { type: 'communicates-with', line: 'M 459.2 560.6 L 570.8 709.4', head: 'M 564.2 705.6 L 570.8 709.4 L 569 702', at: 8.1, pill: [485, 635, 116] },
  { type: 'communicates-with', line: 'M 470.7 544.2 L 759.3 630.8', head: 'M 751.8 631.7 L 759.4 630.8 L 753.5 625.9', at: 8.95, pill: [629, 553, 116] },
]

// `at`: when the extraction ring pulses, in seconds.
const NODES = [
  { label: 'threat-actor', x: 440, y: 350, color: '#c03a6b', abbr: 'TA', realm: 'Asgard', at: 1.6 },
  { label: 'tool', x: 180, y: 450, color: '#1e8a4e', abbr: 'TL', realm: 'Svartalfheim', at: 2.1 },
  { label: 'attack-pattern', x: 700, y: 450, color: '#c2702a', abbr: 'AP', realm: 'Muspelheim', at: 2.6 },
  { label: 'malware', x: 440, y: 535, color: '#c8394a', abbr: 'MW', realm: 'Helheim', at: 3.1 },
  { label: 'indicator', x: 120, y: 640, color: '#6e8b1e', abbr: 'IN', realm: 'Alfheim', at: 3.6 },
  { label: 'file', x: 300, y: 735, color: '#d0582a', abbr: 'FL', realm: 'Niflheim', at: 4.1 },
  { label: 'domain-name', x: 590, y: 735, color: '#4466d0', abbr: 'DN', realm: 'Midgard', at: 4.6 },
  { label: 'ipv4-addr', x: 790, y: 640, color: '#8b3a2f', abbr: 'IP', realm: 'Vanaheim', at: 5.1 },
  { label: 'location', x: 790, y: 330, color: '#1e9a5e', abbr: 'LC', realm: 'Jotunheim', at: 5.6 },
]

/** Decorative: the CSS draws it once on load (`signin-*` rules in index.css). */
function SigninGraph() {
  return (
    <svg className="signin-graph" viewBox="0 290 900 540" aria-hidden="true" focusable="false">
      {TREE.map(d => <path key={d} className="signin-tree" d={d} />)}
      {RELS.map((r, i) => (
        <g key={i} className="signin-rel">
          <path className="signin-rel-base" d={r.line} />
          <path className="signin-rel-draw" d={r.line} pathLength={1} style={{ '--d': `${r.at}s` } as React.CSSProperties} />
          <path className="signin-rel-head" d={r.head} style={{ '--d': `${(r.at + 0.7).toFixed(2)}s` } as React.CSSProperties} />
        </g>
      ))}
      {RELS.map((r, i) => (
        <g key={i} className="signin-pill">
          <rect x={r.pill[0]} y={r.pill[1]} width={r.pill[2]} height={20} rx={4} />
          <text x={r.pill[0] + r.pill[2] / 2} y={r.pill[1] + 10} textAnchor="middle" dominantBaseline="central">{r.type}</text>
        </g>
      ))}
      {NODES.map(n => (
        <g key={n.label} className="signin-node" style={{ '--c': n.color, '--d': `${n.at}s` } as React.CSSProperties}>
          <circle className="signin-ring" cx={n.x} cy={n.y} r={36} />
          <circle className="signin-disc" cx={n.x} cy={n.y} r={28} />
          <text className="signin-abbr" x={n.x} y={n.y} textAnchor="middle" dominantBaseline="central">{n.abbr}</text>
          <text className="signin-label" x={n.x} y={n.y + 52} textAnchor="middle">{n.label}</text>
          <text className="signin-realm" x={n.x} y={n.y + 71} textAnchor="middle">{n.realm}</text>
        </g>
      ))}
    </svg>
  )
}

const ARROW = (
  <svg className="signin-arrow" width="38" height="12" viewBox="0 0 38 12" aria-hidden="true" focusable="false">
    <path d="M0 6 L38 6 M32 0 L38 6 L32 12" />
  </svg>
)

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
    <div className="t-app signin">
      <section className="signin-left">
        <p className="signin-eyebrow">CTI Parsor / Cyber Threat Intelligence</p>
        <p className="signin-headline">From documents to meaningful connections.</p>
        <div className="signin-pipeline">
          <div className="signin-step" style={{ flex: '226 1 0', background: 'var(--bg-elev)' }}>
            <FileText size={16} color="var(--ink-3)" aria-hidden="true" />
            <div><p className="signin-eyebrow">01 / Document</p><p className="signin-step-title">Threat report</p></div>
          </div>
          {ARROW}
          <div className="signin-step" style={{ flex: '226 1 0', background: 'var(--bg-soft)' }}>
            <div><p className="signin-eyebrow">02 / Extraction</p><p className="signin-step-title">Entities &amp; context</p></div>
          </div>
          {ARROW}
          <div className="signin-step" style={{ flex: '242 1 0', background: 'var(--bg-elev)' }}>
            <div><p className="signin-eyebrow">03 / Structuring</p><p className="signin-step-title">STIX 2.1 objects &amp; relationships</p></div>
          </div>
        </div>
        <SigninGraph />
        <div className="signin-captions">
          <p className="signin-mono"><span>Huginn / Extract</span><span>Muninn / Connect</span></p>
          <p className="signin-note">9 realms, a visual metaphor · Examples of STIX 2.1 objects and relationships</p>
        </div>
      </section>
      <div className="signin-sep" />
      <p className="signin-eyebrow signin-access">Access CTI Parsor</p>
      <main className="login-card" style={{
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
      <div className="signin-below">
        <p className="signin-tagline">Extract. Structure. Connect.</p>
        <p className="signin-lede">Turn your documents into STIX 2.1 objects and relationships.</p>
        <p className="signin-footer">Document → Objects → Relationships</p>
      </div>
    </div>
  )
}
