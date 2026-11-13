// What the authenticated journeys share (#707): the accounts scripts/check_browser_e2e.sh
// creates with `python -m api.admin` (--auth local), the sign-in page, the session
// and token calls, a report uploaded by an analyst, and the ending of a session
// through scripts/browser_e2e_db.py.  Passwords are read from E2E_ACCOUNTS_DIR and
// are never printed.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test'
import { fixture, settledStatus } from './journey'

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

/** The usernames scripts/check_browser_e2e.sh --auth local creates. */
export const USERS = { reader: 'e2e-reader', analyst: 'e2e-analyst', admin: 'e2e-admin' } as const
export type Role = keyof typeof USERS

/** The password of a local account, from the file the harness wrote. */
export function passwordOf(role: Role): string {
  const dir = process.env.E2E_ACCOUNTS_DIR
  if (!dir) throw new Error('E2E_ACCOUNTS_DIR is not set: run scripts/check_browser_e2e.sh --auth local')
  return readFileSync(path.join(dir, `${role}.pw`), 'utf8').trim()
}

/** Signs `page` in through the sign-in page, as a person does, and waits for the dashboard. */
export async function signIn(page: Page, role: Role): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Username', { exact: true }).fill(USERS[role])
  await page.getByLabel('Password', { exact: true }).fill(passwordOf(role))
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
  await expect(page.getByRole('heading', { name: 'Threat reports' })).toBeVisible()
}

export interface Me {
  username: string | null
  role: Role | null
  auth_source: 'local' | 'oidc' | null
  csrf_token: string | null
}

/** Who the context's session is (the CSRF token is needed for a write with a session cookie).  With no
 *  session the answer is 401, read here as nobody. */
export async function whoAmI(request: APIRequestContext): Promise<Me> {
  const res = await request.get('/api/auth/me')
  if (res.status() === 401) return { username: null, role: null, auth_source: null, csrf_token: null }
  expect(res.ok()).toBeTruthy()
  return await res.json() as Me
}

/** Uploads the shared sample report as the context's user (an analyst), and returns the job id
 *  once the run has ended for review. */
export async function uploadReport(context: BrowserContext, name: string): Promise<string> {
  const { csrf_token } = await whoAmI(context.request)
  const res = await context.request.post('/api/upload', {
    headers: { 'X-CSRF-Token': csrf_token ?? '' },
    multipart: {
      file: { name, mimeType: 'text/plain', buffer: fixture('sample_report.txt') },
      tlp_level: 'CLEAR',
      pap_level: 'WHITE',
    },
  })
  expect(res.status(), await res.text()).toBe(200)
  const { job_id } = await res.json() as { job_id: string }
  expect(await settledStatus(context.request, job_id)).toBe('for_review')
  return job_id
}

/** Ends every session of `username` in the journey's database (scripts/browser_e2e_db.py
 *  expire-session).  Returns how many it ended. */
export function endSessions(username: string): number {
  const python = process.env.E2E_PYTHON
  const url = process.env.E2E_DB_URL
  if (!python || !url) throw new Error('E2E_PYTHON and E2E_DB_URL are not set: run scripts/check_browser_e2e.sh --auth')
  const helper = path.join(REPO, 'scripts', 'browser_e2e_db.py')
  const out = execFileSync(python, [helper, 'expire-session', url, username], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', LANG: 'C.UTF-8', PYTHON_DOTENV_DISABLED: '1',
      SKIP_HEAVY_MODELS: '1' },
  })
  const match = /^(\d+) session/.exec(out.trim())
  if (!match) throw new Error(`expire-session answered: ${out.trim()}`)
  return Number(match[1])
}

/** The entity rows of a job, as the context's user reads them. */
export async function entityRows(request: APIRequestContext, jobId: string): Promise<{ id: string; accepted: boolean | null }[]> {
  const res = await request.get(`/api/jobs/${jobId}/entities`)
  expect(res.ok()).toBeTruthy()
  return await res.json() as { id: string; accepted: boolean | null }[]
}
