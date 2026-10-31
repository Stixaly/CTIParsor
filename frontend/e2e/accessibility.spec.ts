// The automatic accessibility check of the journey's pages (ADR-0094 item 4):
// axe-core's WCAG 2.0 and 2.1 A and AA rules on the dashboard, the new-report
// dialog, the progress dialog, the review page and the graph.  A violation of
// impact serious or critical fails, unless e2e/a11y-allowlist.json names it
// (its rule, its page and its element, axe's target selector) with why and the
// follow-up: another element breaking the same rule on the same page fails.
// An entry that no longer matches fails too, so the list only shrinks.  Not a
// certification: the keyboard journey and TESTING.md's manual checklist cover
// the rest.
import { readFileSync } from 'node:fs'
import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import {
  attach, findJob, fixture, kanbanCard, markings, openNewReport, progressDialog, settledStatus, uniqueName,
} from './journey'

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']
const BLOCKING = new Set(['serious', 'critical'])

interface Allowed { rule: string; page: string; target: string; why: string; followUp: string }
interface Finding { page: string; rule: string; impact: string; target: string; html: string; summary: string }
const ALLOWED = JSON.parse(readFileSync(new URL('./a11y-allowlist.json', import.meta.url), 'utf8')) as Allowed[]

test('the pages of the journey pass axe (WCAG 2.1 A/AA, serious and critical)', async ({ page, request }) => {
  const found: Finding[] = []
  const all: { page: string; rule: string; impact: string; nodes: number }[] = []
  const audit = async (where: string) => {
    // A dialog fades in: colours are read once the finite animations are over.
    await page.waitForFunction(() => document.getAnimations()
      .every(a => a.playState !== 'running' || a.effect?.getComputedTiming().iterations === Infinity))
    const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze()
    for (const v of violations) {
      all.push({ page: where, rule: v.id, impact: v.impact ?? '', nodes: v.nodes.length })
      if (!BLOCKING.has(v.impact ?? '')) continue
      for (const n of v.nodes) {
        found.push({ page: where, rule: v.id, impact: v.impact ?? '', target: n.target.join(' '),
          html: n.html.slice(0, 160), summary: n.failureSummary ?? '' })
      }
    }
  }
  const name = uniqueName('accessibility', '.txt')

  await page.goto('/dashboard')
  await expect(page.getByRole('heading', { name: 'Threat reports' })).toBeVisible()
  await audit('dashboard')

  const dialog = await openNewReport(page)
  await audit('new-report dialog')
  await attach(page, dialog.getByRole('button', { name: 'Browse files…' }),
    { name, mimeType: 'text/plain', buffer: fixture('sample_report.txt') })
  await markings(dialog).tlp('CLEAR').click()
  await markings(dialog).pap('WHITE').click()
  await audit('new-report dialog, filled')
  await dialog.getByRole('button', { name: 'Create job' }).click()

  await expect(progressDialog(page)).toBeVisible()
  await audit('progress dialog')
  const job = await findJob(request, name)
  expect(await settledStatus(request, job.id)).toBe('for_review')
  await page.goto('/dashboard')
  await expect(kanbanCard(page, name).getByRole('button', { name: 'Analyse' })).toBeVisible()
  await audit('dashboard, with reports')

  await kanbanCard(page, name).getByRole('button', { name: 'Analyse' }).click()
  await expect(page.getByRole('button', { name: /^Complete Review/ })).toBeVisible()
  await audit('review')

  await page.getByRole('button', { name: 'Graph', exact: true }).click()
  await expect(page.getByRole('button', { name: 'STIX bundle', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await audit('graph')

  // Every finding, any impact, for the record; the gate is on serious and critical.
  await test.info().attach('axe-violations.json', { body: JSON.stringify({ blocking: found, all }, null, 2), contentType: 'application/json' })
  // One element per entry: the rule, the page and axe's selector of the element.
  const matches = (a: Allowed, f: Finding) => a.rule === f.rule && a.page === f.page && a.target === f.target
  const stale = ALLOWED.filter(a => !found.some(f => matches(a, f)))
  expect(found.filter(f => !ALLOWED.some(a => matches(a, f))), 'serious or critical violations not in e2e/a11y-allowlist.json')
    .toEqual([])
  expect(stale, 'allowlist entries that no longer match a violation: remove them').toEqual([])
})
