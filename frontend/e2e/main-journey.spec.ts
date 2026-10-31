// The main journey (ADR-0094 item 4): a report imported from the dashboard,
// followed through its progress events, the page reloaded, the report in
// review; accepted, rejected and retyped rows; the review completed and the
// bundle downloaded, then checked as a STIX 2.1 bundle and against what the
// server holds.
import { expect, test } from '@playwright/test'
import {
  attach, entities, entity, entityCard, expectStixBundle, findJob, fixture, getJob, kanbanCard,
  markings, openNewReport, progressDialog, recordDialogs, reveal, settledStatus, downloadedJson, JOB_TIMEOUT, STAGE_1_EVENT,
  uniqueName,
} from './journey'

test('import, follow, review, complete and download a report', async ({ page, request }) => {
  const alerts = recordDialogs(page)
  const name = uniqueName('main-journey', '.txt')

  // Import: the file through the chooser, the markings, the job.
  await page.goto('/dashboard')
  await expect(page.getByRole('heading', { name: 'Threat reports' })).toBeVisible()
  const dialog = await openNewReport(page)
  await attach(page, dialog.getByRole('button', { name: 'Browse files…' }),
    { name, mimeType: 'text/plain', buffer: fixture('sample_report.txt') })
  await expect(dialog.getByText(name, { exact: true })).toBeVisible()
  await expect(dialog.getByRole('button', { name: 'Set TLP & PAP to continue' })).toBeDisabled()
  await markings(dialog).tlp('CLEAR').click()
  await markings(dialog).pap('WHITE').click()
  await dialog.getByRole('button', { name: 'Create job' }).click()
  await expect(dialog).toBeHidden()

  // Progress: the modal follows the job's events.  It lists the five stages
  // whatever happens; Stage 1's detail line comes only from the run's Stage 1
  // event, so a dead event stream fails here.
  await expect(progressDialog(page)).toBeVisible()
  await expect(progressDialog(page).getByText(STAGE_1_EVENT)).toBeVisible({ timeout: JOB_TIMEOUT })
  const job = await findJob(request, name)

  // A reload forgets the page's state (the modal goes): the report is still on
  // the dashboard, from the server's list, and its run goes on to review.
  // Whether it is still running at the reload is recorded, not asserted: on a
  // warm API the run ends 0.6 to 0.8 s after Stage 1's event (2026-10-31, one
  // report at a time), too close to make it a condition.
  test.info().annotations.push({ type: 'status at the reload', description: (await getJob(request, job.id)).status })
  await page.reload()
  await expect(progressDialog(page)).toBeHidden()
  await expect(page.getByText(name, { exact: true }).first()).toBeVisible()

  // The run ends in review: its card in "For review", opened with Analyse.
  expect(await settledStatus(request, job.id)).toBe('for_review')
  const card = kanbanCard(page, name)
  await expect(card.getByRole('button', { name: 'Analyse' })).toBeVisible({ timeout: 15_000 })
  await card.getByRole('button', { name: 'Analyse' }).click()
  await expect(page).toHaveURL(new RegExp(`/review/${job.id}$`))
  await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toContainText('Reviewing')

  // Review: accept a row left pending, reject one the server accepted, retype one.
  const rows = await entities(request, job.id)
  const accepted = entity(rows, 'APT29', 'threat_actor')
  const rejected = entity(rows, 'update-service.net', 'domain')
  const retyped = entity(rows, 'Cobalt Strike', 'malware')
  expect(accepted.accepted).toBeNull()
  expect(rejected.accepted).toBe(true)
  await entityCard(page, accepted.id).getByTitle('Accept (A)').click()
  await entityCard(page, rejected.id).getByTitle('Reject (R)').click()
  const changeType = entityCard(page, retyped.id).getByTitle('Change type')
  await reveal(page, changeType)
  await changeType.click()
  await page.locator('.type-picker-popup').getByRole('button', { name: 'Tool', exact: true }).click()
  await expect.poll(async () => {
    const now = await entities(request, job.id)
    return [entity(now, 'APT29').accepted, entity(now, 'update-service.net').accepted,
      now.find(e => e.id === retyped.id)?.entity_type]
  }).toEqual([true, false, 'tool'])

  // Complete the review, then download what it built.
  await page.getByRole('button', { name: /^Complete Review/ }).click()
  const downloadButton = page.getByRole('button', { name: 'Download STIX', exact: true })
  await expect(downloadButton).toBeVisible({ timeout: JOB_TIMEOUT })
  const downloading = page.waitForEvent('download')
  await downloadButton.click()
  const download = await downloading
  expect(download.suggestedFilename()).toBe(name.replace(/\.txt$/, '_stix.json'))
  const bundle = expectStixBundle(await downloadedJson(download))

  const named = (type: string, value: string) =>
    bundle.objects.filter(o => o.type === type && (o.name === value || o.value === value))
  expect(named('threat-actor', 'APT29'), 'the accepted actor ships').toHaveLength(1)
  expect(named('domain-name', 'update-service.net'), 'the rejected domain does not ship').toHaveLength(0)
  expect(bundle.objects.filter(o => typeof o.pattern === 'string' && o.pattern.includes('update-service.net')),
    'nor an indicator for it').toHaveLength(0)
  expect(named('tool', 'Cobalt Strike'), 'the retyped row ships as a tool').toHaveLength(1)
  expect(named('malware', 'Cobalt Strike'), 'and no longer as malware').toHaveLength(0)

  // The server: the same bundle, schema-validated; the report completed, the decisions the analyst's.
  const served = await request.get(`/api/jobs/${job.id}/bundle`)
  expect(served.status()).toBe(200)
  expect(served.headers()['x-bundle-validation']).toBe('validated')
  expect(await served.json()).toEqual(bundle)
  expect((await getJob(request, job.id)).status).toBe('completed')
  const after = await entities(request, job.id)
  expect(entity(after, 'APT29')).toMatchObject({ accepted: true, decision_origin: 'human' })
  expect(entity(after, 'update-service.net')).toMatchObject({ accepted: false, decision_origin: 'human' })
  expect(after.find(e => e.id === retyped.id)).toMatchObject({ value: 'Cobalt Strike', entity_type: 'tool' })
  expect(alerts, 'no alert on the way').toEqual([])
})
