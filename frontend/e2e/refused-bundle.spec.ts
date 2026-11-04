// A bundle the STIX 2.1 schemas refused is not served (ADR-0094 item 4): the
// report scripts/browser_e2e_db.py seeded, as the worker stores such a run.
// GET /bundle answers 409 with the errors; the graph says the build was
// refused and why, and its download says so instead of saving a file.
import { expect, test } from '@playwright/test'
import { findJob, kanbanCard, recordDialogs } from './journey'

const REFUSED = 'refused-bundle-e2e.txt'

test('a refused bundle is answered 409, and the interface says why', async ({ page, request }) => {
  const job = await findJob(request, REFUSED)
  const res = await request.get(`/api/jobs/${job.id}/bundle`)
  expect(res.status()).toBe(409)
  const { detail } = await res.json() as { detail: { validation: string; errors: string[] } }
  expect(detail.validation).toBe('invalid')
  expect(detail.errors.length).toBeGreaterThan(0)
  expect(detail.errors.join(' ')).toContain('not a lang!')

  await page.goto('/dashboard')
  await kanbanCard(page, REFUSED).getByRole('button', { name: 'Analyse' }).click()
  await expect(page).toHaveURL(new RegExp(`/review/${job.id}$`))
  await page.getByRole('button', { name: 'Graph', exact: true }).click()
  const refusal = page.getByRole('alert').filter({ hasText: 'The last build was refused by the STIX 2.1 schemas and is not served' })
  await expect(refusal).toBeVisible()
  await expect(refusal).toContainText(detail.errors[0])

  // The alert can open while the click is still settling: awaiting the click
  // before handling the dialog then deadlocks (the click waits on the open
  // alert, the alert on the test).  A handler records and dismisses it instead.
  const alerts = recordDialogs(page)
  await page.getByRole('button', { name: 'Download STIX', exact: true }).click()
  await expect.poll(() => alerts.length).toBe(1)
  expect(alerts[0]).toContain('The STIX 2.1 schemas refused this bundle:')
  expect(alerts[0]).toContain(`• ${detail.errors[0]}`)

  // Nothing rebuilt it on the way: still refused.
  expect((await request.get(`/api/jobs/${job.id}/bundle`)).status()).toBe(409)
})
