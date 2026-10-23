// Reads the ATT&CK indexes in pipeline/data/ from disk: Node's types, which
// TypeScript 6 no longer includes by default (the app itself runs in the browser).
/// <reference types="node" />
import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as url from 'node:url'

import { TACTIC_LABEL, TACTIC_ORDER, techniqueColumns } from './tactics'
import type { TechMeta } from './tactics'

const DATA = path.resolve(path.dirname(url.fileURLToPath(import.meta.url)), '../../../../pipeline/data')

/** Every committed ATT&CK track (ADR-0087), as [name, its mitre_index.json]:
 *  the default in pipeline/data/, the others in pipeline/data/attack/<version>/. */
function tracks(): [string, string][] {
  const out: [string, string][] = [['default', path.join(DATA, 'mitre_index.json')]]
  const dir = path.join(DATA, 'attack')
  for (const version of fs.existsSync(dir) ? fs.readdirSync(dir).sort() : []) {
    const file = path.join(dir, version, 'mitre_index.json')
    if (fs.existsSync(file)) out.push([version, file])
  }
  return out
}

interface Entry { id?: string; name?: string; domain?: string; shortname?: string; tactics?: string[] }

const load = (file: string) =>
  JSON.parse(fs.readFileSync(file, 'utf8')) as { tactics: Entry[]; techniques: Entry[] }

const enterprise = (e: Entry) => e.domain === 'enterprise-attack'

/** An index entry as Coverage.tsx carries it in its `meta` map. */
const metaOf = (e: Entry): TechMeta =>
  ({ name: e.name ?? e.id ?? '', domain: e.domain ?? '', tactics: e.tactics ?? [] })

describe.each(tracks())('ATT&CK track %s', (_name, file) => {
  it('gives every enterprise tactic a column', () => {
    const index = load(file)
    const tactics = index.tactics.filter(enterprise).map(t => t.shortname ?? '')
    expect(tactics.length).toBeGreaterThan(0)
    const used = new Set([...tactics, ...index.techniques.filter(enterprise).flatMap(t => t.tactics ?? [])])
    expect([...used].filter(t => !TACTIC_ORDER.includes(t)).sort()).toEqual([])
  })

  it('files only enterprise techniques under a tactic, each under all of its tactics', () => {
    const index = load(file)
    const misfiled = index.techniques.filter(t => {
      const want = enterprise(t) && t.tactics?.length ? t.tactics : ['other']
      return techniqueColumns(metaOf(t)).join() !== want.join()
    })
    expect(misfiled.map(t => `${t.id} (${t.domain})`)).toEqual([])
  })

  it('files T1660 Phishing, a mobile technique, under Other', () => {
    const t1660 = load(file).techniques.find(t => t.id === 'T1660')
    expect(t1660).toMatchObject({ domain: 'mobile-attack', tactics: ['initial-access'] })
    expect(techniqueColumns(metaOf(t1660!))).toEqual(['other'])
  })
})

describe('the Coverage columns', () => {
  it('are checked on the default track and on 20.0', () => {
    expect(tracks().map(([name]) => name)).toEqual(expect.arrayContaining(['default', '20.0']))
  })

  it('each have a label', () => {
    expect(TACTIC_ORDER.filter(t => !(t in TACTIC_LABEL))).toEqual([])
  })
})

describe('techniqueColumns', () => {
  const tech = (domain: string, tactics: string[]): TechMeta => ({ name: 'x', domain, tactics })

  it("keeps an enterprise technique's tactics, in its order", () => {
    expect(techniqueColumns(tech('enterprise-attack', ['initial-access']))).toEqual(['initial-access'])
    expect(techniqueColumns(tech('enterprise-attack', ['privilege-escalation', 'persistence'])))
      .toEqual(['privilege-escalation', 'persistence'])
  })

  it('files a mobile, ICS or CAPEC technique under Other, whatever its tactics', () => {
    for (const domain of ['mobile-attack', 'ics-attack', 'capec', '']) {
      expect(techniqueColumns(tech(domain, ['initial-access', 'execution']))).toEqual(['other'])
    }
  })

  it('files an id the index lacks under Other', () => {
    expect(techniqueColumns(undefined)).toEqual(['other'])
  })

  it('drops a tactic that has no column', () => {
    expect(techniqueColumns(tech('enterprise-attack', ['defense-evasion', 'execution']))).toEqual(['execution'])
    expect(techniqueColumns(tech('enterprise-attack', ['defense-evasion']))).toEqual(['other'])
    expect(techniqueColumns(tech('enterprise-attack', []))).toEqual(['other'])
  })
})
