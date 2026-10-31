// A report that fails (ADR-0094 item 4): an enrich job whose chosen Report the
// STIX 2.1 schemas refuse (its lang is not an RFC 5646 tag).  The preview does
// not run the schemas, so the job starts; the worker refuses the bundle and the
// job fails, and the dashboard says so.  The reason is in the run's last
// progress event (the page does not show it): the test reads it there.
import { expect, test } from '@playwright/test'
import {
  attach, closeProgress, findJob, fixture, getJob, markings, openNewReport, progressEvents, settledStatus, uniqueName,
  type Bundle,
} from './journey'

test('a report the worker cannot use shows as failed on the dashboard', async ({ page, request }) => {
  const name = uniqueName('failed-job', '.txt')
  const bundle = JSON.parse(fixture('baselines', 'opencti_report.json').toString('utf8')) as Bundle
  for (const o of bundle.objects) if (o.type === 'report') o.lang = 'not a lang!'
  const reportId = bundle.objects.find(o => o.type === 'report')!.id

  await page.goto('/dashboard')
  const dialog = await openNewReport(page)
  await dialog.getByRole('radio', { name: 'Enrich an existing STIX 2.1 bundle' }).click()
  await attach(page, dialog.getByRole('button', { name: 'Browse bundle…' }),
    { name: 'bad_lang.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(bundle)) })
  await expect(dialog.getByText(/^\d+ objects kept from the bundle$/)).toBeVisible()
  await attach(page, dialog.getByRole('button', { name: 'Browse files…' }),
    { name, mimeType: 'text/plain', buffer: fixture('baselines', 'opencti_report.txt') })
  await markings(dialog).pap('WHITE').click()
  await dialog.getByRole('button', { name: 'Create job' }).click()
  await expect(dialog).toBeHidden()
  await closeProgress(page)

  const job = await findJob(request, name)
  expect(await settledStatus(request, job.id)).toBe('failed')
  // Why: the baseline error, not any failure.
  const done = (await progressEvents(request, job.id)).filter(e => e.event === 'done')
  expect(done, 'one done event').toHaveLength(1)
  expect(done[0].data.status).toBe('failed')
  expect(String(done[0].data.error)).toContain(`the report '${reportId}' is refused`)
  expect(String(done[0].data.error)).toContain("'not a lang!' is not a valid RFC 5646 language code")
  // The dashboard's activity strip: the report, failed.  No card on the Kanban board.
  const entry = page.locator('div')
    .filter({ has: page.getByText(name, { exact: true }) })
    .filter({ has: page.getByText(/^Pipeline failed · /) })
  await expect(entry.last()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByRole('heading', { name, exact: true })).toHaveCount(0)
  expect((await getJob(request, job.id)).status).toBe('failed')
})
