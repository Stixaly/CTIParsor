// Enriching an existing STIX 2.1 bundle (ADR-0090, ADR-0094 item 4): the
// analyst's bundle and its report imported, reviewed and completed; the graph
// says what Stage 4 changed and how the result stands against the analyst's
// bundle.  Offline, the rows matched are those regex and the gazetteer find.
import { expect, test } from '@playwright/test'
import {
  attach, closeProgress, expectStixBundle, findJob, fixture, kanbanCard, markings, openNewReport,
  recordDialogs, settledStatus, uniqueName, JOB_TIMEOUT, type Bundle,
} from './journey'

interface LedgerRemoval { kind: string; reason: string; stix_id: string; replaced_by?: string | null }
interface LedgerEntity { value: string; entity_type: string; reason?: string; stix_id?: string | null }

// The SHA-256 tests/fixtures/baselines/opencti_report.txt gives for svchost_update.dll.
const SHA256 = '9f2b6c1d4a7e3085b1d6f4e2a9c37d58e0b4a1f6c2d93e7a5b80c4d1f6e3a972'

test('enrich a STIX bundle, then read the differences and the match against it', async ({ page, request }) => {
  const alerts = recordDialogs(page)
  const name = uniqueName('enrichment', '.txt')
  const baseline = JSON.parse(fixture('baselines', 'opencti_report.json').toString('utf8')) as Bundle
  const analystReport = baseline.objects.find(o => o.type === 'report')!

  await page.goto('/dashboard')
  const dialog = await openNewReport(page)
  await dialog.getByRole('radio', { name: 'Enrich an existing STIX 2.1 bundle' }).click()
  await attach(page, dialog.getByRole('button', { name: 'Browse bundle…' }),
    { name: 'opencti_report.json', mimeType: 'application/json', buffer: fixture('baselines', 'opencti_report.json') })
  await expect(dialog.getByText(/^\d+ objects kept from the bundle$/)).toBeVisible()
  await attach(page, dialog.getByRole('button', { name: 'Browse files…' }),
    { name, mimeType: 'text/plain', buffer: fixture('baselines', 'opencti_report.txt') })
  // The bundle carries TLP:AMBER: the TLP is raised to it, the PAP is the analyst's.
  await expect(dialog.getByText('at least TLP:AMBER, from the bundle')).toBeVisible()
  await expect(markings(dialog).tlp('AMBER')).toHaveAttribute('aria-checked', 'true')
  await markings(dialog).pap('WHITE').click()
  await dialog.getByRole('button', { name: 'Create job' }).click()
  await expect(dialog).toBeHidden()
  await closeProgress(page)

  const job = await findJob(request, name)
  expect(job.pipeline_mode).toBe('enrich')
  expect(await settledStatus(request, job.id)).toBe('for_review')
  const card = kanbanCard(page, name)
  await expect(card.getByText('Enrich', { exact: true })).toBeVisible({ timeout: 15_000 })
  await card.getByRole('button', { name: 'Analyse' }).click()
  await expect(page).toHaveURL(new RegExp(`/review/${job.id}$`))

  await page.getByRole('button', { name: /^Complete Review/ }).click()
  await expect(page.getByRole('button', { name: 'Download STIX', exact: true })).toBeVisible({ timeout: JOB_TIMEOUT })

  // What the server built: the analyst's Report re-issued under its own id.
  const served = await request.get(`/api/jobs/${job.id}/bundle`)
  expect(served.status()).toBe(200)
  expect(served.headers()['x-bundle-validation']).toBe('validated')
  const bundle = expectStixBundle(await served.json())
  expect(bundle.objects.map(o => o.id)).toContain(analystReport.id)
  const ledger = await (await request.get(`/api/jobs/${job.id}/bundle/ledger`)).json() as
    { removed: LedgerRemoval[]; entities: LedgerEntity[] }
  const matched = ledger.removed.filter(r => r.kind === 'object' && r.reason === 'baseline_match')
  // Offline, what the report and the analyst's bundle share: the file (the
  // report names it and gives its SHA-256, two objects of CTIParsor's) and
  // APT29 (CTIParsor's threat actor), each replaced by the analyst's object.
  const analysts = new Set(baseline.objects.map(o => o.id))
  const analystFile = baseline.objects.find(o => o.type === 'file' && o.name === 'svchost_update.dll')!.id
  const analystApt29 = baseline.objects.find(o => o.type === 'intrusion-set' && o.name === 'APT29')!.id
  for (const m of matched) expect(analysts.has(m.replaced_by ?? ''), `${m.stix_id} replaced by one of the analyst's objects`).toBe(true)
  expect(matched.map(m => `${m.stix_id.split('--')[0]} → ${m.replaced_by}`).sort(), 'the objects matched').toEqual(
    [`file → ${analystFile}`, `file → ${analystFile}`, `threat-actor → ${analystApt29}`].sort())
  const rows = ledger.entities.filter(e => e.reason === 'baseline_match')
  expect([...new Set(rows.map(e => `${e.entity_type} ${e.value} → ${e.stix_id}`))].sort(), 'the rows matched').toEqual([
    `file svchost_update.dll → ${analystFile}`, `sha256 ${SHA256} → ${analystFile}`, `threat_actor APT29 → ${analystApt29}`,
  ].sort())
  for (const m of matched) expect(bundle.objects.map(o => o.id)).toContain(m.replaced_by)

  // The graph: the differences, then the match against the analyst's bundle.
  await page.getByRole('button', { name: 'Graph', exact: true }).click()
  await expect(page).toHaveURL(new RegExp(`/graph/${job.id}$`))
  await expect(page.getByRole('button', { name: 'STIX bundle', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await page.getByRole('button', { name: /^Differences/ }).click()
  await expect(page.getByText('What Stage 4 changed')).toBeVisible()
  await page.getByRole('button', { name: 'Against your bundle', exact: true }).click()
  await expect(page.getByText('Against your STIX bundle')).toBeVisible()
  const matchedBlock = page.getByRole('button', { name: /^Matched to your objects/ })
  await expect(matchedBlock).toHaveAccessibleName(`Matched to your objects ${matched.length}`)
  await expect(page.getByText(/→ your /)).toHaveCount(matched.length)
  // Offline, what the report adds: SUNBURST (gazetteer) and T1566.001 (regex).
  await expect(page.getByRole('button', { name: /^Added by CTIParsor/ })).toBeVisible()
  await expect(page.getByText('SUNBURST', { exact: true }).first()).toBeVisible()
  expect(alerts, 'no alert on the way').toEqual([])
})
