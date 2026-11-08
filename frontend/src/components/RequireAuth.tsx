import { useEffect } from 'react'
import { Navigate, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { setSessionEndedHandler, loginUrl } from '../api/session'
import { useAuth } from '../context/AuthContext'
import type { Role } from '../api/auth'

/** Everything but /login: waits for "who am I", sends an anonymous visitor to /login?next=,
 *  and takes the session-ended signal of any API call (a 401) to the same place.
 *  With authentication off it renders its children as before. */
export function RequireAuth() {
  const auth = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { refresh } = auth

  useEffect(() => {
    setSessionEndedHandler(url => {
      queryClient.clear()
      void refresh().finally(() => navigate(url, { replace: true }))
    })
    return () => setSessionEndedHandler(null)
  }, [refresh, navigate, queryClient])

  if (auth.status === 'loading') return <p role="status" style={{ padding: 24, color: 'var(--ink-3)' }}>Loading…</p>
  if (auth.status === 'error') {
    return <p role="alert" style={{ padding: 24, color: 'var(--no)' }}>The server did not answer. Reload the page.</p>
  }
  if (auth.status === 'anonymous') {
    return <Navigate to={loginUrl(`${location.pathname}${location.search}`)} replace />
  }
  return <Outlet />
}

/** A page for one role and above; anyone else goes to the dashboard (the server refuses the calls anyway). */
export function RequireRole({ role }: { role: Role }) {
  const auth = useAuth()
  return auth.can(role) ? <Outlet /> : <Navigate to="/dashboard" replace />
}
