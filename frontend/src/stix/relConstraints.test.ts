import { describe, it, expect } from 'vitest'
import { STIX_REL_CONSTRAINTS, UNIVERSAL_VERBS, commonVerbs, pairVerbs, shippedVerbs } from './relConstraints'
import fixture from './shippedVerbs.fixture.json'

describe('relConstraints (shared STIX table)', () => {
  it('pairVerbs appends only related-to to a pair of two types', () => {
    const v = pairVerbs('threat-actor', 'malware')
    expect(v).toEqual(['uses', 'related-to'])
  })

  it('duplicate-of and derived-from link two objects of the same type only (§3.7)', () => {
    for (const u of UNIVERSAL_VERBS) expect(pairVerbs('malware', 'malware')).toContain(u)
    expect(commonVerbs('malware', 'tool')).toEqual(['related-to'])
    expect(commonVerbs('malware', 'malware')).toEqual(UNIVERSAL_VERBS)
  })

  it('pairVerbs returns null for an unconstrained pair', () => {
    expect(pairVerbs('ipv4-addr', 'campaign')).toBeNull()
  })

  it('lists no pair for related-to alone: commonVerbs covers it, and a listed pair is not routed', () => {
    for (const verbs of Object.values(STIX_REL_CONSTRAINTS)) expect(verbs).not.toEqual(['related-to'])
  })

  it('shippedVerbs follows Stage 4: listed, routed through the Indicator, common, or indicates only', () => {
    expect(shippedVerbs('malware', 'domain-name')).toEqual(['communicates-with', 'related-to'])
    expect(shippedVerbs('ipv4-addr', 'malware')).toEqual(['indicates', 'related-to'])
    expect(shippedVerbs('malware', 'mutex')).toEqual(['related-to'])
    expect(shippedVerbs('file', 'file')).toEqual(UNIVERSAL_VERBS)
    expect(shippedVerbs('attack-pattern', 'url')).toEqual(['indicates'])
  })

  it('shippedVerbs matches what Stage 4 ships, for every pair of types', () => {
    // Generated from pipeline/stage4_stix_mapping.verb_ships_as_written by
    // `python -m tests.test_rel_constraints_parity --write`.
    const { types, pairs } = fixture as { types: string[]; pairs: Record<string, string[]> }
    for (const s of types) {
      for (const t of types) {
        expect([...shippedVerbs(s, t)].sort(), `${s}>${t}`).toEqual(pairs[`${s}>${t}`] ?? ['related-to'])
      }
    }
  })

  it('has no duplicate verbs after the universal merge', () => {
    const v = pairVerbs('malware', 'malware')!
    expect(v.length).toBe(new Set(v).size)
  })
})

describe('tokens.ts and relConstraints stay in sync', async () => {
  it('tokens specVerbs delegates to the shared table', async () => {
    const { specVerbs } = await import('../components/review/tokens')
    expect(specVerbs('malware', 'vulnerability')).toEqual(pairVerbs('malware', 'vulnerability'))
    expect(specVerbs('ipv4', 'campaign')).toBeNull()
  })
})
