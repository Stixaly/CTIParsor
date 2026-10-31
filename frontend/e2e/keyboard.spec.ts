// The essential operations with the keyboard alone (ADR-0094 item 4): import
// a report, decide rows (accept, reject, retype), complete the review and
// download the bundle.  No click and no pointer: Tab and Shift+Tab to reach a
// control, Enter or Space to press it, and the review page's own shortcuts
// (j, a, r, f; ? lists them).  The file chooser is the operating system's,
// which the keyboard drives there; Playwright stands in for it.
import { expect, test, type Locator } from '@playwright/test'
import {
  entities, entity, entityCard, expectStixBundle, findJob, fixture, kanbanCard, progressDialog,
  recordDialogs, settledStatus, downloadedJson, tabTo, uniqueName, JOB_TIMEOUT,
} from './journey'

test('import, decide, complete and download with the keyboard only', async ({ page, request }) => {
  const alerts = recordDialogs(page)
  const name = uniqueName('keyboard', '.txt')
  const press = (key: string) => page.keyboard.press(key)
  const reach = async (target: Locator, backwards = false) => { await tabTo(page, target, { backwards }) }

  // Import.
  await page.goto('/dashboard')
  await reach(page.getByRole('button', { name: 'New report', exact: true }))
  await press('Enter')
  const dialog = page.getByRole('dialog', { name: 'New report' })
  await expect(dialog.getByRole('textbox').last()).toBeFocused()
  await reach(dialog.getByRole('button', { name: 'Browse files…' }), true)
  const chooser = page.waitForEvent('filechooser')
  await press('Enter')
  await (await chooser).setFiles({ name, mimeType: 'text/plain', buffer: fixture('sample_report.txt') })
  await expect(dialog.getByText(name, { exact: true })).toBeVisible()
  await reach(dialog.getByRole('radiogroup', { name: 'TLP marking' }).getByRole('radio', { name: 'CLEAR', exact: true }))
  await press('Space')
  await reach(dialog.getByRole('radiogroup', { name: 'PAP marking' }).getByRole('radio', { name: 'WHITE', exact: true }))
  await press('Space')
  await reach(dialog.getByRole('button', { name: 'Create job' }))
  await press('Enter')
  await expect(dialog).toBeHidden()

  // The progress dialog takes the focus and keeps it: Tab and Shift+Tab stay
  // on its one control.  Escape closes it, and the focus goes back to New
  // report (Create job, which opened it, closed with the new-report dialog).
  await expect(progressDialog(page)).toBeVisible()
  const close = progressDialog(page).getByRole('button')
  await expect(close).toBeFocused()
  await press('Tab')
  await expect(close).toBeFocused()
  await press('Shift+Tab')
  await expect(close).toBeFocused()
  await press('Escape')
  await expect(progressDialog(page)).toBeHidden()
  await expect(page.getByRole('button', { name: 'New report', exact: true })).toBeFocused()

  // Open the report once it is in review.
  const job = await findJob(request, name)
  expect(await settledStatus(request, job.id)).toBe('for_review')
  const analyse = kanbanCard(page, name).getByRole('button', { name: 'Analyse' })
  await expect(analyse).toBeVisible({ timeout: 15_000 })
  await reach(analyse)
  await press('Enter')
  await expect(page).toHaveURL(new RegExp(`/review/${job.id}$`))
  await expect(page.getByRole('button', { name: /^Complete Review/ })).toBeVisible()

  // j: the first row left pending; a accepts it and moves on; r rejects the next.
  const rows = await entities(request, job.id)
  const pending = rows.filter(e => e.accepted === null)
  expect(pending.length, 'rows left pending for the analyst').toBeGreaterThanOrEqual(2)
  const focused = page.locator('.marg.focused')
  await press('j')
  await expect(focused).toHaveCount(1)
  const first = await focused.getAttribute('data-marg-id')
  expect(pending.map(e => e.id)).toContain(first)
  await press('a')
  await expect(focused).not.toHaveAttribute('data-marg-id', first ?? '')
  const second = await focused.getAttribute('data-marg-id')
  expect(pending.map(e => e.id)).toContain(second)
  await press('r')
  await expect.poll(async () => {
    const now = await entities(request, job.id)
    return [now.find(e => e.id === first)?.accepted, now.find(e => e.id === second)?.accepted]
  }).toEqual([true, false])

  // Retype a row: Tab to its "Change type" button, Enter, Tab to the type, Enter.
  const retyped = entity(rows, 'Cobalt Strike', 'malware')
  await reach(entityCard(page, retyped.id).getByTitle('Change type'))
  await press('Enter')
  await reach(page.locator('.type-picker-popup').getByRole('button', { name: 'Tool', exact: true }))
  await press('Enter')
  await expect.poll(async () => (await entities(request, job.id)).find(e => e.id === retyped.id)?.entity_type).toBe('tool')

  // f completes the review; f again downloads the bundle.
  await press('f')
  await expect(page.getByRole('button', { name: 'Download STIX', exact: true })).toBeVisible({ timeout: JOB_TIMEOUT })
  const downloading = page.waitForEvent('download')
  await press('f')
  const bundle = expectStixBundle(await downloadedJson(await downloading))
  const after = await entities(request, job.id)
  const acceptedRow = after.find(e => e.id === first)!
  const rejectedRow = after.find(e => e.id === second)!
  const carries = (v: string) => bundle.objects.filter(o => o.type !== 'report' && (o.name === v || o.value === v))
  expect(carries(acceptedRow.value), `${acceptedRow.value} ships`).not.toEqual([])
  expect(carries(rejectedRow.value), `${rejectedRow.value} does not ship`).toEqual([])
  expect(bundle.objects.some(o => o.type === 'tool' && o.name === 'Cobalt Strike')).toBe(true)
  expect((await (await request.get(`/api/jobs/${job.id}`)).json()).status).toBe('completed')
  expect(alerts, 'no alert on the way').toEqual([])
})
