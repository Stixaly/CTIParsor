import { createOwnToken, listOwnTokens, revokeOwnToken } from '../api/admin'
import { useAuth } from '../context/AuthContext'
import TokenPanel from '../components/TokenPanel'

/** The signed-in user's own page: who they are and their API tokens (ADR-0097). */
export default function Account() {
  const { me } = useAuth()
  return (
    <div style={{ padding: '20px 24px', maxWidth: 1100 }}>
      <h1 style={{ fontSize: 18, margin: '0 0 4px' }}>Account</h1>
      {me && (
        <p style={{ fontSize: 13, color: 'var(--ink-3)', margin: '0 0 16px' }}>
          Signed in as {me.display_name || me.username} ({me.username}), role {me.role}.
        </p>
      )}
      <p style={{ fontSize: 13, color: 'var(--ink-3)' }}>
        A token lets a script call the API as you, with your role: <code>Authorization: Bearer ctp_&hellip;</code>.
        It is shown once, when you create it.
      </p>
      <TokenPanel
        title="My tokens" queryKey={['own', 'tokens']} load={listOwnTokens} showUser={false}
        create={(name, days) => createOwnToken({ name, days })}
        revoke={revokeOwnToken}
      />
    </div>
  )
}
