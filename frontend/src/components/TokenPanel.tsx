import { useId, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { errorDetail } from '../api/client'
import type { TokenCreated, TokenRecord, UserRecord } from '../api/admin'

export const inputStyle: React.CSSProperties = {
  padding: '6px 8px', border: '1px solid var(--rule)', borderRadius: 4,
  background: 'var(--bg-soft)', color: 'var(--ink)', fontSize: 13,
}
export const buttonStyle: React.CSSProperties = {
  whiteSpace: 'nowrap', padding: '5px 10px', border: '1px solid var(--rule)', borderRadius: 4,
  background: 'var(--bg-elev)', color: 'var(--ink)', fontSize: 12, cursor: 'pointer',
}
export const cell: React.CSSProperties = { textAlign: 'left', padding: '6px 8px', borderBottom: '1px solid var(--rule-soft)', fontSize: 13 }

export const when = (iso: string | null): string => (iso ? iso.slice(0, 16).replace('T', ' ') : 'never')

export function ErrorLine({ message }: { message: string | null }) {
  return <div role="alert">{message && <p style={{ color: 'var(--no)', fontSize: 13, margin: '8px 0' }}>{message}</p>}</div>
}

/** Two clicks for what cannot be undone: the first asks, the second does it. */
export function ConfirmButton({ label, confirmLabel, onConfirm, disabled, title }: {
  label: string; confirmLabel: string; onConfirm: () => void; disabled?: boolean; title?: string
}) {
  const [asking, setAsking] = useState(false)
  if (!asking) {
    return <button type="button" style={buttonStyle} disabled={disabled} title={title} onClick={() => setAsking(true)}>{label}</button>
  }
  return (
    <span role="group" aria-label={`Confirm: ${label}`} style={{ display: 'inline-flex', gap: 4 }}>
      <button type="button" style={{ ...buttonStyle, borderColor: 'var(--no)', color: 'var(--no)' }}
        onClick={() => { setAsking(false); onConfirm() }}>{confirmLabel}</button>
      <button type="button" style={buttonStyle} onClick={() => setAsking(false)}>Cancel</button>
    </span>
  )
}

/** A token shown once: the secret, a copy button and the warning. */
export function NewTokenNotice({ created, onDismiss }: { created: TokenCreated; onDismiss: () => void }) {
  const [copied, setCopied] = useState<'yes' | 'no' | null>(null)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.token)
      setCopied('yes')
    } catch {
      setCopied('no')
    }
  }
  return (
    <section aria-label="New token" style={{ border: '1px solid var(--warn)', borderRadius: 6, padding: 12, margin: '12px 0', background: 'var(--bg-elev)' }}>
      <p style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 600 }}>
        Token “{created.name}” for {created.username}. This token will not be shown again: copy it now.
      </p>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <input readOnly aria-label="Token" value={created.token} style={{ ...inputStyle, flex: 1, fontFamily: 'monospace' }}
          onFocus={e => e.currentTarget.select()} />
        <button type="button" style={buttonStyle} onClick={() => void copy()}>Copy</button>
        <button type="button" style={buttonStyle} onClick={onDismiss}>I have copied it</button>
      </div>
      <p role="status" style={{ margin: '6px 0 0', fontSize: 12, color: 'var(--ink-3)' }}>
        {copied === 'yes' && 'Copied.'}
        {copied === 'no' && 'The browser refused to copy: select the token and copy it by hand.'}
      </p>
    </section>
  )
}

export function tokenState(t: TokenRecord, now = Date.now()): 'revoked' | 'expired' | 'active' {
  if (t.revoked_at) return 'revoked'
  return Date.parse(t.expires_at) <= now ? 'expired' : 'active'
}

interface Props {
  title: string
  /** Query key and loader of the tokens listed. */
  queryKey: string[]
  load: () => Promise<TokenRecord[]>
  create: (name: string, days: number, userId: string) => Promise<TokenCreated>
  revoke: (id: string) => Promise<unknown>
  /** For an admin: the users a token can be made for. Absent: the token is for the caller. */
  users?: UserRecord[]
  showUser: boolean
}

/** The tokens table with its creation form: all tokens for an admin, one's own on the Account page. */
export default function TokenPanel({ title, queryKey, load, create, revoke, users, showUser }: Props) {
  const qc = useQueryClient()
  const tokens = useQuery({ queryKey, queryFn: load })
  const [name, setName] = useState('')
  const [days, setDays] = useState('90')
  const [userId, setUserId] = useState('')
  const [created, setCreated] = useState<TokenCreated | null>(null)
  const [error, setError] = useState<string | null>(null)

  const makeToken = useMutation({
    mutationFn: () => create(name.trim(), Number(days), userId),
    onSuccess: made => {
      setCreated(made)
      setName('')
      setError(null)
      void qc.invalidateQueries({ queryKey })
    },
    onError: err => setError(errorDetail(err)),
  })
  const revokeToken = useMutation({
    mutationFn: (id: string) => revoke(id),
    onSuccess: () => { setError(null); void qc.invalidateQueries({ queryKey }) },
    onError: err => setError(errorDetail(err)),
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setError(null)
    makeToken.mutate()
  }
  const headingId = useId()

  return (
    <section aria-labelledby={headingId} style={{ margin: '24px 0' }}>
      <h2 id={headingId} style={{ fontSize: 15, margin: '0 0 8px' }}>{title}</h2>
      {/* Keyed by token: a new token gets a fresh notice, so the "Copied" state of the previous one is not kept (#627). */}
      {created && <NewTokenNotice key={created.id} created={created} onDismiss={() => setCreated(null)} />}

      <form onSubmit={submit} style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 8 }}>
        {users && (
          <label style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 2 }}>
            For user
            <select required value={userId} onChange={e => setUserId(e.target.value)} style={inputStyle}>
              <option value="" disabled>Choose…</option>
              {users.filter(u => !u.disabled).map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
            </select>
          </label>
        )}
        <label style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 2 }}>
          Token name
          <input required maxLength={128} value={name} onChange={e => setName(e.target.value)} style={inputStyle} placeholder="nightly-import" />
        </label>
        <label style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 2 }}>
          Days (1 to 365)
          <input type="number" min={1} max={365} required value={days} onChange={e => setDays(e.target.value)} style={{ ...inputStyle, width: 90 }} />
        </label>
        <button type="submit" className="btn-primary" disabled={makeToken.isPending}>Create token</button>
      </form>
      <ErrorLine message={error} />

      {tokens.isError && <p role="alert" style={{ color: 'var(--no)', fontSize: 13 }}>Could not load the tokens: {errorDetail(tokens.error)}</p>}
      {tokens.data && tokens.data.length === 0 && <p style={{ fontSize: 13, color: 'var(--ink-3)' }}>No tokens.</p>}
      {tokens.data && tokens.data.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <caption style={{ position: 'absolute', left: -9999 }}>{title}</caption>
          <thead>
            <tr>
              <th scope="col" style={cell}>Name</th>
              {showUser && <th scope="col" style={cell}>User</th>}
              <th scope="col" style={cell}>Created</th>
              <th scope="col" style={cell}>Expires</th>
              <th scope="col" style={cell}>Last used</th>
              <th scope="col" style={cell}>State</th>
              <th scope="col" style={cell}><span style={{ position: 'absolute', left: -9999 }}>Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {tokens.data.map(t => {
              const state = tokenState(t)
              return (
                <tr key={t.id}>
                  <td style={cell}>{t.name}</td>
                  {showUser && <td style={cell}>{t.username}</td>}
                  <td style={cell}>{when(t.created_at)}</td>
                  <td style={cell}>{when(t.expires_at)}</td>
                  <td style={cell}>{when(t.last_used_at)}</td>
                  <td style={cell}>{state}</td>
                  <td style={cell}>
                    {state === 'active' && (
                      <ConfirmButton label="Revoke" confirmLabel={`Revoke ${t.name}`} onConfirm={() => revokeToken.mutate(t.id)} />
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </section>
  )
}
