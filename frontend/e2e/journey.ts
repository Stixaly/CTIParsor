// What the browser journeys share (ADR-0094 item 4): the fixtures, the API
// reads that say what the server holds, and the steps of the interface.
// Waits are on states the page or the API shows, each with a bound: no pause.
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, type APIRequestContext, type Download, type Locator, type Page } from '@playwright/test'

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

/** A file of tests/fixtures: public names, documentation addresses, no secret. */
export function fixture(...parts: string[]): Buffer {
  return readFileSync(path.join(REPO, 'tests', 'fixtures', ...parts))
}

/** A report name no other journey uses: each one finds its own report on the shared dashboard. */
export function uniqueName(stem: string, ext: string): string {
  return `${stem}-${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}${ext}`
}

/** How long one report may take offline, from the upload to its end (the worker's subprocess included). */
export const JOB_TIMEOUT = 150_000

export interface Job {
  id: string
  original_filename: string
  status: string
  pipeline_mode: string
}

export interface Entity {
  id: string
  value: string
  entity_type: string
  accepted: boolean | null
  decision_origin: string | null
  enrichment_status?: string | null
}

export interface StixObject {
  id: string
  type: string
  spec_version?: string
  name?: string
  value?: string
  pattern?: string
  [key: string]: unknown
}

export interface Bundle {
  type: string
  id: string
  objects: StixObject[]
}

/** The report named `filename`, once the API lists it. */
export async function findJob(request: APIRequestContext, filename: string): Promise<Job> {
  let found: Job | undefined
  await expect.poll(async () => {
    const res = await request.get('/api/jobs')
    expect(res.ok()).toBeTruthy()
    found = ((await res.json()) as Job[]).find(j => j.original_filename === filename)
    return found !== undefined
  }, { message: `the API lists no report named ${filename}` }).toBe(true)
  return found as Job
}

export async function getJob(request: APIRequestContext, id: string): Promise<Job> {
  const res = await request.get(`/api/jobs/${id}`)
  expect(res.ok()).toBeTruthy()
  return await res.json() as Job
}

/** The status a report ends its run with: for_review or failed. */
export async function settledStatus(request: APIRequestContext, id: string): Promise<string> {
  let status = ''
  await expect.poll(async () => {
    status = (await getJob(request, id)).status
    return status
  }, { timeout: JOB_TIMEOUT, intervals: [1_000], message: 'the report did not finish its run' })
    .toMatch(/^(for_review|failed)$/)
  return status
}

export async function entities(request: APIRequestContext, id: string): Promise<Entity[]> {
  const res = await request.get(`/api/jobs/${id}/entities`)
  expect(res.ok()).toBeTruthy()
  return await res.json() as Entity[]
}

/** The row of `value`; exactly one must exist. */
export function entity(rows: Entity[], value: string, type?: string): Entity {
  const hits = rows.filter(e => e.value === value && (type === undefined || e.entity_type === type))
  expect(hits, `one ${type ?? 'entity'} ${value}`).toHaveLength(1)
  return hits[0]
}

/** Opens "New report" from the dashboard. */
export async function openNewReport(page: Page): Promise<Locator> {
  await page.getByRole('button', { name: 'New report', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'New report' })
  await expect(dialog).toBeVisible()
  return dialog
}

/** Picks `file` in the file chooser `button` opens. */
export async function attach(page: Page, button: Locator, file: { name: string; mimeType: string; buffer: Buffer }) {
  const chooser = page.waitForEvent('filechooser')
  await button.click()
  await (await chooser).setFiles(file)
}

export function markings(dialog: Locator) {
  return {
    tlp: (level: string) => dialog.getByRole('radiogroup', { name: 'TLP marking' }).getByRole('radio', { name: level, exact: true }),
    pap: (level: string) => dialog.getByRole('radiogroup', { name: 'PAP marking' }).getByRole('radio', { name: level, exact: true }),
  }
}

/** A report's card on the Kanban board. */
export function kanbanCard(page: Page, filename: string): Locator {
  return page.locator('article').filter({ has: page.getByRole('heading', { name: filename, exact: true }) })
}

/** An entity's card in the review margin. */
export function entityCard(page: Page, id: string): Locator {
  return page.locator(`[data-marg-id="${id}"]`)
}

/** Records every alert the page raises and dismisses it; a journey expects none
 *  unless it says which. */
export function recordDialogs(page: Page): string[] {
  const seen: string[] = []
  page.on('dialog', dialog => {
    seen.push(dialog.message())
    void dialog.dismiss()
  })
  return seen
}

/** The JSON of a download. */
export async function downloadedJson(download: Download): Promise<unknown> {
  return JSON.parse(readFileSync(await download.path(), 'utf8'))
}

/** Every `*_ref` and `*_refs` value that names no object of the bundle.  The
 *  properties under an object's `extensions` belong to the extension (OpenCTI
 *  keeps its own internal ids there): STIX does not make them references. */
export function danglingRefs(bundle: Bundle): string[] {
  const ids = new Set(bundle.objects.map(o => o.id))
  const dangling: string[] = []
  const walk = (value: unknown, where: string) => {
    if (Array.isArray(value)) {
      value.forEach(v => walk(v, where))
    } else if (value !== null && typeof value === 'object') {
      for (const [key, v] of Object.entries(value)) {
        if (key === 'extensions') continue
        if (key.endsWith('_ref') && typeof v === 'string' && !ids.has(v)) dangling.push(`${where}.${key} -> ${v}`)
        if (key.endsWith('_refs') && Array.isArray(v)) {
          for (const ref of v) if (typeof ref !== 'string' || !ids.has(ref)) dangling.push(`${where}.${key} -> ${String(ref)}`)
        }
        walk(v, `${where}.${key}`)
      }
    }
  }
  for (const o of bundle.objects) walk(o, o.id)
  return dangling
}

/** A STIX 2.1 bundle: its shape, every object 2.1 and once, every reference inside it. */
export function expectStixBundle(value: unknown): Bundle {
  const bundle = value as Bundle
  expect(bundle.type).toBe('bundle')
  expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/)
  expect(bundle.objects.length).toBeGreaterThan(0)
  for (const o of bundle.objects) {
    expect(o.id, JSON.stringify(o).slice(0, 200)).toMatch(/^[a-z0-9-]+--[0-9a-f-]{36}$/)
    expect(o.id.split('--')[0], o.id).toBe(o.type)
    expect(o.spec_version, o.id).toBe('2.1')
  }
  expect(new Set(bundle.objects.map(o => o.id)).size, 'one object per id').toBe(bundle.objects.length)
  expect(danglingRefs(bundle), 'references to objects outside the bundle').toEqual([])
  return bundle
}

/** Presses Tab (Shift+Tab backwards) until `target` has the focus: a keyboard user's way there. */
export async function tabTo(page: Page, target: Locator, { backwards = false, max = 400 } = {}): Promise<number> {
  await expect(target).toBeVisible()
  for (let presses = 0; presses <= max; presses++) {
    if (await target.evaluate(el => el === document.activeElement)) return presses
    await page.keyboard.press(backwards ? 'Shift+Tab' : 'Tab')
  }
  throw new Error(`the keyboard did not reach ${target} in ${max} presses of Tab`)
}

/** Scrolls `target` to the middle of its scroll container and lets that scroll's
 *  events pass (two frames).  The review margin scrolls under a sticky
 *  relationship rail, and its type menu closes on any scroll: a click that had
 *  to scroll first would land on the rail, or close the menu it opens. */
export async function reveal(page: Page, target: Locator) {
  await target.evaluate(el => el.scrollIntoView({ block: 'center' }))
  await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))))
}

/** The progress dialog Create job opens. */
export function progressDialog(page: Page): Locator {
  return page.getByRole('dialog', { name: 'Processing report' })
}

/** Closes the progress dialog with its button ("Dismiss" while the run goes on, "Close" after). */
export async function closeProgress(page: Page) {
  const dialog = progressDialog(page)
  await dialog.getByTitle(/^(Close|Dismiss — pipeline continues in background)$/).click()
  await expect(dialog).toBeHidden()
}

/** Stage 1's detail line in the progress dialog ("2,345 chars → 1 chunks").  The
 *  dialog lists the five stages whatever happens; this line is drawn only from
 *  the run's Stage 1 event, so seeing it shows the event stream works. */
export const STAGE_1_EVENT = /^[\d,]+ chars → \d+ chunks$/

/** The run's progress events as GET /api/jobs/{id}/progress streams them (the
 *  page's EventSource reads the same): once the job has ended, the stream ends
 *  with its `done` event. */
export async function progressEvents(request: APIRequestContext, id: string): Promise<{ event: string; data: Record<string, unknown> }[]> {
  const res = await request.get(`/api/jobs/${id}/progress`)
  expect(res.ok()).toBeTruthy()
  return (await res.text()).split('\n\n').filter(block => block.trim()).map(block => {
    const field = (name: string) => block.split('\n').find(line => line.startsWith(`${name}: `))?.slice(name.length + 2) ?? ''
    return { event: field('event'), data: JSON.parse(field('data') || '{}') as Record<string, unknown> }
  })
}
