import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { canWrite, fetchMe, roleAtLeast, signOut as apiSignOut, type Me, type Role } from '../api/auth'

/** loading: /me not answered yet · off: AUTH_MODE=off, no sign-in at all ·
 *  anonymous: authentication is on and nobody is signed in · signed-in. */
export type AuthStatus = 'loading' | 'off' | 'anonymous' | 'signed-in' | 'error'

export interface AuthState {
  status: AuthStatus
  me: Me | null
  /** Does the signed-in user have at least this role?  True when authentication is off. */
  can: (minimum: Role) => boolean
  /** Take the answer of a sign-in. */
  setMe: (me: Me) => void
  signOut: () => Promise<void>
  refresh: () => Promise<void>
}

// Without a provider (a page rendered on its own) the interface is as it is with authentication off.
const OFF: AuthState = {
  status: 'off', me: null, can: () => true,
  setMe: () => undefined, signOut: () => Promise.resolve(), refresh: () => Promise.resolve(),
}

export const AuthContext = createContext<AuthState>(OFF)

export function useAuth(): AuthState {
  return useContext(AuthContext)
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [me, setMeState] = useState<Me | null>(null)

  const refresh = useCallback(async () => {
    try {
      const found = await fetchMe()
      if (found === null) {
        setMeState(null)
        setStatus('anonymous')
      } else if (found.auth_mode === 'off') {
        setMeState(found)
        setStatus('off')
      } else {
        setMeState(found)
        setStatus('signed-in')
      }
    } catch {
      setStatus('error')
    }
  }, [])

  useEffect(() => { void refresh() }, [refresh])

  const setMe = useCallback((next: Me) => {
    setMeState(next)
    setStatus(next.auth_mode === 'off' ? 'off' : 'signed-in')
  }, [])

  const signOut = useCallback(async () => {
    try { await apiSignOut() } finally {
      setMeState(null)
      setStatus('anonymous')
    }
  }, [])

  const value = useMemo<AuthState>(() => ({
    status, me, setMe, signOut, refresh,
    can: (minimum: Role) => status === 'off' || (status === 'signed-in' && roleAtLeast(me?.role, minimum, me?.auth_mode)),
  }), [status, me, setMe, signOut, refresh])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** May the signed-in user change reports (analyst and above, api/auth.ts `canWrite`)?
 *  True when authentication is off. A reader gets the report read-only (#707). */
export function useCanWrite(): boolean {
  const { status, me } = useAuth()
  return status === 'off' || (status === 'signed-in' && canWrite(me?.role, me?.auth_mode))
}
