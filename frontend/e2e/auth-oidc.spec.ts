// The authenticated journey through an OpenID Connect provider (#707; docs/deployment.md,
// "Sign-in with an identity provider").  scripts/check_browser_e2e.sh --auth oidc starts the
// API with AUTH_MODE=oidc against the provider of docker/oidc-test (navikt mock-oauth2-server,
// its login page takes a subject and a claims JSON): the groups claim picks the role through
// OIDC_ROLE_MAP, which the harness sets to e2e-readers=reader,e2e-analysts=analyst,e2e-admins=admin.
import { expect, test, type Page } from '@playwright/test'
import { entityCard, uniqueName } from './journey'
import { endSessions, entityRows, uploadReport, whoAmI } from './auth'

test.skip(process.env.E2E_AUTH !== 'oidc', 'needs scripts/check_browser_e2e.sh --auth oidc')

/** Signs `page` in through the provider: the sign-in page's link, the provider's form with `subject` and a
 *  groups claim.  Waits for the provider's form, not for the way back. */
async function signInThroughProvider(page: Page, subject: string, groups: string[]): Promise<void> {
  // From nobody: a session the context still holds would send /login on to the dashboard.
  await page.context().clearCookies()
  await page.goto('/login')
  await page.getByRole('link', { name: 'Sign in with your organisation' }).click()
  await page.locator('input[name="username"]').fill(subject)
  await page.locator('textarea[name="claims"]').fill(JSON.stringify({
    preferred_username: subject, name: subject, groups,
  }))
  await page.getByRole('button', { name: 'Sign-in', exact: true }).click()
}

test('a mapped group signs in with its role, a sign-out ends the session', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await signInThroughProvider(page, 'e2e-oidc-analyst', ['e2e-analysts'])
    await expect(page).toHaveURL(/\/dashboard$/)
    expect(await whoAmI(context.request)).toMatchObject({
      username: 'e2e-oidc-analyst', role: 'analyst', auth_source: 'oidc',
    })
    // The analyst's role lets it upload a report.
    await uploadReport(context, uniqueName('auth-oidc', '.txt'))

    await page.getByRole('button', { name: 'Sign out', exact: true }).click()
    await expect(page).toHaveURL(/\/login/)
    expect(await whoAmI(context.request)).toMatchObject({ role: null, username: null })
  } finally {
    await context.close()
  }
})

test('a signed-in person with no mapped group is refused, with no session', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await signInThroughProvider(page, 'e2e-oidc-nobody', ['e2e-other-team'])
    await expect(page).toHaveURL(/\/login\?error=no_role$/)
    await expect(page.getByText('Your account is in no group that gives access to CTIParsor.')).toBeVisible()
    expect((await whoAmI(context.request)).role).toBeNull()
  } finally {
    await context.close()
  }
})

test('a reader is read-only, an admin administers, the role follows the groups at each sign-in', async ({ browser }) => {
  const analystContext = await browser.newContext()
  const readerContext = await browser.newContext()
  const adminContext = await browser.newContext()
  const analyst = await analystContext.newPage()
  const reader = await readerContext.newPage()
  const admin = await adminContext.newPage()
  try {
    await signInThroughProvider(analyst, 'e2e-oidc-uploader', ['e2e-analysts'])
    await expect(analyst).toHaveURL(/\/dashboard$/)
    const job = await uploadReport(analystContext, uniqueName('auth-oidc-review', '.txt'))
    const pending = (await entityRows(analystContext.request, job)).find(e => e.accepted === null)
    expect(pending, 'the report has a row left pending').toBeDefined()

    // The reader opens the report directly (no dashboard step): no decision control, a write is 403.
    await signInThroughProvider(reader, 'e2e-oidc-reader', ['e2e-readers'])
    await expect(reader).toHaveURL(/\/dashboard$/)
    expect((await whoAmI(readerContext.request)).role).toBe('reader')
    await reader.goto(`/review/${job}`)
    await expect(entityCard(reader, pending!.id)).toBeVisible()
    await expect(reader.getByTitle('Accept (A)')).toHaveCount(0)
    const { csrf_token } = await whoAmI(readerContext.request)
    const refused = await readerContext.request.patch(`/api/jobs/${job}/entities/${pending!.id}`, {
      headers: { 'X-CSRF-Token': csrf_token ?? '' }, data: { accepted: true },
    })
    expect(refused.status()).toBe(403)

    // The administrator reaches the administration API; the analyst does not.
    await signInThroughProvider(admin, 'e2e-oidc-admin', ['e2e-admins'])
    await expect(admin).toHaveURL(/\/dashboard$/)
    expect((await adminContext.request.get('/api/admin/users')).status()).toBe(200)
    expect((await analystContext.request.get('/api/admin/users')).status()).toBe(403)

    // One person, moved from the analyst group to the reader group: each sign-in takes the role of its groups.
    await signInThroughProvider(analyst, 'e2e-oidc-mover', ['e2e-analysts'])
    await expect(analyst).toHaveURL(/\/dashboard$/)
    expect((await whoAmI(analystContext.request)).role).toBe('analyst')
    await signInThroughProvider(analyst, 'e2e-oidc-mover', ['e2e-readers'])
    await expect(analyst).toHaveURL(/\/dashboard$/)
    expect((await whoAmI(analystContext.request)).role).toBe('reader')
  } finally {
    await analystContext.close()
    await readerContext.close()
    await adminContext.close()
  }
})

test('an expired session goes to the sign-in page; signing in again through the provider works', async ({ browser }) => {
  const context = await browser.newContext()
  const page = await context.newPage()
  try {
    await signInThroughProvider(page, 'e2e-oidc-expiry', ['e2e-admins'])
    await expect(page).toHaveURL(/\/dashboard$/)
    expect(endSessions('e2e-oidc-expiry')).toBeGreaterThanOrEqual(1)
    expect((await context.request.get('/api/jobs')).status()).toBe(401)

    await page.goto('/dashboard')
    await expect(page).toHaveURL(/\/login\?next=/)

    await signInThroughProvider(page, 'e2e-oidc-expiry', ['e2e-admins'])
    await expect(page).toHaveURL(/\/dashboard$/)
    expect((await whoAmI(context.request)).role).toBe('admin')
  } finally {
    await context.close()
  }
})
