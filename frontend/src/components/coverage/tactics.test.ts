// Reads the ATT&CK indexes in pipeline/data/ from disk: Node's types, which
// TypeScript 6 no longer includes by default (the app itself runs in the browser).
/// <reference types="node" />
import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import * as url from 'node:url'

import { TACTIC_LABEL, TACTIC_ORDER } from './tactics'

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

interface Entry { domain?: string; shortname?: string; tactics?: string[] }

const enterprise = (e: Entry) => e.domain === 'enterprise-attack'

describe.each(tracks())('ATT&CK track %s', (_name, file) => {
  it('gives every enterprise tactic a column', () => {
    const index = JSON.parse(fs.readFileSync(file, 'utf8')) as { tactics: Entry[]; techniques: Entry[] }
    const tactics = index.tactics.filter(enterprise).map(t => t.shortname ?? '')
    expect(tactics.length).toBeGreaterThan(0)
    const used = new Set([...tactics, ...index.techniques.filter(enterprise).flatMap(t => t.tactics ?? [])])
    expect([...used].filter(t => !TACTIC_ORDER.includes(t)).sort()).toEqual([])
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
