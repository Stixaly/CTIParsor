// Users and API tokens (ADR-0097): the calls behind the Access and Account pages.
import { req } from './client'
import type { Role } from './auth'

export interface UserRecord {
  id: string
  username: string
  display_name: string
  auth_source: 'local' | 'oidc'
  role: Role
  disabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface TokenRecord {
  id: string
  name: string
  user_id: string
  username: string
  created_at: string
  expires_at: string
  revoked_at: string | null
  last_used_at: string | null
}

/** The answer to a creation: the only time the token itself is sent. */
export interface TokenCreated extends TokenRecord {
  token: string
}

const json = (body: unknown) => JSON.stringify(body)

export const listUsers = () => req<UserRecord[]>('/admin/users')
export const createUser = (body: { username: string; role: Role; display_name?: string; password: string }) =>
  req<UserRecord>('/admin/users', { method: 'POST', body: json(body) })
export const patchUser = (id: string, body: { role?: Role; disabled?: boolean; display_name?: string }) =>
  req<UserRecord>(`/admin/users/${encodeURIComponent(id)}`, { method: 'PATCH', body: json(body) })
export const setUserPassword = (id: string, password: string) =>
  req<{ id: string; username: string; sessions_ended: boolean }>(
    `/admin/users/${encodeURIComponent(id)}/password`, { method: 'POST', body: json({ password }) })

export const listAdminTokens = () => req<TokenRecord[]>('/admin/tokens')
export const createAdminToken = (body: { user_id: string; name: string; days?: number }) =>
  req<TokenCreated>('/admin/tokens', { method: 'POST', body: json(body) })
export const revokeAdminToken = (id: string) =>
  req<{ revoked: string }>(`/admin/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })

export const listOwnTokens = () => req<TokenRecord[]>('/auth/tokens')
export const createOwnToken = (body: { name: string; days?: number }) =>
  req<TokenCreated>('/auth/tokens', { method: 'POST', body: json(body) })
export const revokeOwnToken = (id: string) =>
  req<{ revoked: string }>(`/auth/tokens/${encodeURIComponent(id)}`, { method: 'DELETE' })
