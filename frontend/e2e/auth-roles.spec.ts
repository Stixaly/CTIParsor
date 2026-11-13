// The authenticated journey, local accounts (#707; docs/web-ui.md, docs/api-permissions.md).
// scripts/check_browser_e2e.sh --auth local starts the API with AUTH_MODE=local and creates
// e2e-reader, e2e-analyst and e2e-admin.  Each test signs in through the sign-in page, in its
// own browser context, so the sessions are separate.
import { expect, request as playwrightRequest, test } from '@playwright/test'
import { entityCard, kanbanCard, uniqueName } from './journey'
import { endSessions, entityRows, signIn, uploadReport, USERS, whoAmI } from './auth'

test.skip(process.env.E2E_AUTH !== 'local', 'needs scripts/check_browser_e2e.sh --auth local')

test('a reader opens a report read-only; an analyst decides; the reader sees the decision', async ({ browser }) => {
  const analystContext = await browser.newContext()
  const readerContext = await browser.newContext()
  const analyst = await analystContext.newPage()
  const reader = await readerContext.newPage()
  try {
    await signIn(analyst, 'analyst')
    const name = uniqueName('auth-roles', '.txt')
    const job = await uploadReport(analystContext, name)
    const rows = await entityRows(analystContext.request, job)
    const pending = rows.find(e => e.accepted === null)
    expect(pending, 'the report has a row left pending').toBeDefined()

    // The reader finds the report on the dashboard and opens it: no write leaves the page.
    await signIn(reader, 'reader')
    const writes: string[] = []
    reader.on('request', req => { if (req.method() !== 'GET') writes.push(`${req.method()} ${new URL(req.url()).pathname}`) })
    await reader.goto('/dashboard')
    await kanbanCard(reader, name).getByRole('button', { name: 'Analyse' }).click()
    await expect(reader).toHaveURL(new RegExp(`/review/${job}$`))
    await expect(entityCard(reader, pending!.id)).toBeVisible()
    await expect(reader.getByTitle('Accept (A)')).toHaveCount(0)
    await expect(reader.getByTitle('Reject (R)')).toHaveCount(0)
    await expect(reader.getByRole('button', { name: /Complete Review/ })).toHaveCount(0)
    expect(writes, 'the reader opened the report without a write').toEqual([])

    // Keys that write for an analyst do nothing for a reader.
    await entityCard(reader, pending!.id).click({ position: { x: 4, y: 4 } })
    await reader.keyboard.press('a')
    await reader.keyboard.press('r')
    expect(writes).toEqual([])

    // A direct write is refused by the server: 403, with the role it needs.
    const { csrf_token } = await whoAmI(readerContext.request)
    const refused = await readerContext.request.patch(`/api/jobs/${job}/entities/${pending!.id}`, {
      headers: { 'X-CSRF-Token': csrf_token ?? '' }, data: { accepted: true },
    })
    expect(refused.status()).toBe(403)
    expect(JSON.stringify(await refused.json())).toContain('analyst role')
    expect((await entityRows(readerContext.request, job)).find(e => e.id === pending!.id)?.accepted).toBeNull()

    // Administration is not the analyst's either.
    expect((await analystContext.request.get('/api/admin/users')).status()).toBe(403)

    // The analyst decides in the interface; the reader, refreshing, sees the decision.
    await analyst.goto(`/review/${job}`)
    await entityCard(analyst, pending!.id).getByTitle('Accept (A)').click()
    await expect.poll(async () => (await entityRows(analystContext.request, job)).find(e => e.id === pending!.id)?.accepted)
      .toBe(true)
    await reader.reload()
    await expect(entityCard(reader, pending!.id)).toHaveClass(/\baccepted\b/)
    expect((await entityRows(readerContext.request, job)).find(e => e.id === pending!.id)?.accepted).toBe(true)

    // Sign out (from the dashboard, the page that has the account menu): the review page is no longer served.
    await reader.goto('/dashboard')
    await reader.getByRole('button', { name: 'Sign out', exact: true }).click()
    await expect(reader).toHaveURL(/\/login/)
    await reader.goto(`/review/${job}`)
    await expect(reader).toHaveURL(/\/login\?next=/)
  } finally {
    await analystContext.close()
    await readerContext.close()
  }
})

// The admin account: this journey ends its sessions, and the other journeys' accounts are not its.
test('an expired session sends the browser to the sign-in page, and signing in again works', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await signIn(page, 'admin')
    expect(endSessions(USERS.admin)).toBeGreaterThanOrEqual(1)
    expect((await context.request.get('/api/jobs')).status()).toBe(401)

    // A page opened on the ended session is sent to the sign-in page, with the page to return to.
    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/login\?next=/)

    await signIn(page, 'admin')
    expect((await whoAmI(context.request)).role).toBe('admin')
  } finally {
    await context.close()
  }
})

test('a revoked API token stops working', async ({ browser }) => {
  const context = await browser.newContext()
  const baseURL = process.env.E2E_BASE_URL
  try {
    await signIn(await context.newPage(), 'analyst')
    const { csrf_token } = await whoAmI(context.request)
    const created = await context.request.post('/api/auth/tokens', {
      headers: { 'X-CSRF-Token': csrf_token ?? '' }, data: { name: 'e2e revocation', days: 1 },
    })
    expect(created.status()).toBe(201)
    const { id, token } = await created.json() as { id: string; token: string }

    const bearer = await playwrightRequest.newContext({
      baseURL, extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    })
    try {
      expect((await bearer.get('/api/jobs')).status()).toBe(200)

      const revoked = await context.request.delete(`/api/auth/tokens/${id}`, { headers: { 'X-CSRF-Token': csrf_token ?? '' } })
      expect(revoked.ok()).toBeTruthy()
      expect((await bearer.get('/api/jobs')).status()).toBe(401)
    } finally {
      await bearer.dispose()
    }
  } finally {
    await context.close()
  }
})
