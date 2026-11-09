import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { errorDetail } from '../api/client'
import {
  createAdminToken, createUser, listAdminTokens, listUsers, patchUser, revokeAdminToken, setUserPassword,
  type UserRecord,
} from '../api/admin'
import type { Role } from '../api/auth'
import { useAuth } from '../context/AuthContext'
import TokenPanel, { buttonStyle, cell, ConfirmButton, ErrorLine, inputStyle, when } from '../components/TokenPanel'

const ROLES: Role[] = ['reader', 'analyst', 'admin']

function NewUserForm({ onError }: { onError: (message: string | null) => void }) {
  const qc = useQueryClient()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<Role>('reader')
  const [password, setPassword] = useState('')
  const make = useMutation({
    mutationFn: () => createUser({ username: username.trim(), role, display_name: displayName.trim(), password }),
    onSuccess: () => {
      setUsername(''); setDisplayName(''); setPassword(''); setRole('reader'); onError(null)
      void qc.invalidateQueries({ queryKey: ['admin', 'users'] })
    },
    onError: err => onError(errorDetail(err)),
  })
  const submit = (event: FormEvent) => { event.preventDefault(); onError(null); make.mutate() }
  const label: React.CSSProperties = { fontSize: 12, display: 'flex', flexDirection: 'column', gap: 2 }
  return (
    <form onSubmit={submit} aria-label="New user" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 8 }}>
      <label style={label}>Username
        <input required autoComplete="off" value={username} onChange={e => setUsername(e.target.value)} style={inputStyle} />
      </label>
      <label style={label}>Display name
        <input autoComplete="off" value={displayName} onChange={e => setDisplayName(e.target.value)} style={inputStyle} />
      </label>
      <label style={label}>Role
        <select value={role} onChange={e => setRole(e.target.value as Role)} style={inputStyle}>
          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
        </select>
      </label>
      <label style={label}>Password (12 characters or more)
        <input required type="password" autoComplete="new-password" value={password}
          onChange={e => setPassword(e.target.value)} style={inputStyle} />
      </label>
      <button type="submit" className="btn-primary" disabled={make.isPending}>Create user</button>
    </form>
  )
}

function PasswordForm({ user, onDone, onError }: {
  user: UserRecord; onDone: () => void; onError: (message: string | null) => void
}) {
  const [password, setPassword] = useState('')
  const save = useMutation({
    mutationFn: () => setUserPassword(user.id, password),
    onSuccess: () => { setPassword(''); onError(null); onDone() },
    onError: err => onError(errorDetail(err)),
  })
  return (
    <form onSubmit={(e: FormEvent) => { e.preventDefault(); save.mutate() }} style={{ display: 'inline-flex', gap: 4 }}>
      <input required type="password" autoComplete="new-password" aria-label={`New password for ${user.username}`}
        value={password} onChange={e => setPassword(e.target.value)} style={{ ...inputStyle, width: 160 }} />
      <button type="submit" style={buttonStyle} disabled={save.isPending}>Save password</button>
      <button type="button" style={buttonStyle} onClick={onDone}>Cancel</button>
    </form>
  )
}

function UsersTable({ users, selfId, onError }: {
  users: UserRecord[]; selfId: string | null; onError: (message: string | null) => void
}) {
  const qc = useQueryClient()
  const [passwordFor, setPasswordFor] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const change = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof patchUser>[1] }) => patchUser(id, body),
    onSuccess: () => { onError(null); void qc.invalidateQueries({ queryKey: ['admin', 'users'] }) },
    onError: err => onError(errorDetail(err)),
  })
  const own = (u: UserRecord) => u.id === selfId
  return (
    <>
      <p role="status" style={{ fontSize: 12, color: 'var(--ink-3)', margin: '4px 0' }}>{notice}</p>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <caption style={{ position: 'absolute', left: -9999 }}>Users</caption>
        <thead>
          <tr>
            {['Username', 'Name', 'Role', 'Source', 'State', 'Last sign-in'].map(h => <th key={h} scope="col" style={cell}>{h}</th>)}
            <th scope="col" style={cell}><span style={{ position: 'absolute', left: -9999 }}>Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.id}>
              <td style={cell}>{u.username}</td>
              <td style={cell}>{u.display_name}</td>
              <td style={cell}>
                <select aria-label={`Role of ${u.username}`} value={u.role} disabled={own(u)}
                  title={own(u) ? 'You cannot change your own role' : undefined} style={inputStyle}
                  onChange={e => change.mutate({ id: u.id, body: { role: e.target.value as Role } })}>
                  {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </td>
              <td style={cell}>{u.auth_source}</td>
              <td style={cell}>{u.disabled ? 'disabled' : 'active'}</td>
              <td style={cell}>{when(u.last_login_at)}</td>
              <td style={{ ...cell, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {u.disabled ? (
                  <button type="button" style={buttonStyle} onClick={() => change.mutate({ id: u.id, body: { disabled: false } })}>Enable</button>
                ) : (
                  <ConfirmButton label="Disable" confirmLabel={`Disable ${u.username}`} disabled={own(u)}
                    title={own(u) ? 'You cannot disable your own account' : undefined}
                    onConfirm={() => change.mutate({ id: u.id, body: { disabled: true } })} />
                )}
                {u.auth_source === 'local' && (passwordFor === u.id ? (
                  <PasswordForm user={u} onError={onError}
                    onDone={() => { setPasswordFor(null); setNotice(`Password of ${u.username} saved; their sessions ended.`) }} />
                ) : (
                  <button type="button" style={buttonStyle} onClick={() => { setNotice(null); setPasswordFor(u.id) }}>Set password</button>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

/** Users and tokens, for an admin (ADR-0097).  The command line does the same: `python -m api.admin`. */
export default function Access() {
  const auth = useAuth()
  const users = useQuery({ queryKey: ['admin', 'users'], queryFn: listUsers })
  const [error, setError] = useState<string | null>(null)
  const selfName = auth.me?.username
  const selfId = users.data?.find(u => u.username === selfName)?.id ?? null

  return (
    <div style={{ padding: '20px 24px', maxWidth: 1100 }}>
      <h1 style={{ fontSize: 18, margin: '0 0 4px' }}>Access</h1>
      <p style={{ fontSize: 13, color: 'var(--ink-3)', margin: '0 0 16px' }}>
        Disabling a user ends their sessions and revokes none of their tokens; a disabled user&rsquo;s tokens are refused
        until the account is enabled again. Revoking a token cannot be undone.
      </p>
      <ErrorLine message={error} />

      <section aria-labelledby="access-users">
        <h2 id="access-users" style={{ fontSize: 15, margin: '0 0 8px' }}>Users</h2>
        <NewUserForm onError={setError} />
        {users.isError && <p role="alert" style={{ color: 'var(--no)', fontSize: 13 }}>Could not load the users: {errorDetail(users.error)}</p>}
        {users.data && <UsersTable users={users.data} selfId={selfId} onError={setError} />}
      </section>

      <TokenPanel
        title="Tokens" queryKey={['admin', 'tokens']} load={listAdminTokens} showUser
        users={users.data ?? []}
        create={(name, days, userId) => createAdminToken({ user_id: userId, name, days })}
        revoke={revokeAdminToken}
      />
    </div>
  )
}
