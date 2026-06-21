import { describe, it, expect } from 'vitest'
import { STIX_REL_CONSTRAINTS, UNIVERSAL_VERBS, pairVerbs } from './relConstraints'

describe('relConstraints (shared STIX table)', () => {
  it('pairVerbs appends the universal verbs to a constrained pair', () => {
    const v = pairVerbs('threat-actor', 'malware')
    expect(v).not.toBeNull()
    expect(v).toContain('uses')
    for (const u of UNIVERSAL_VERBS) expect(v).toContain(u)
  })

  it('pairVerbs returns null for an unconstrained pair', () => {
    expect(pairVerbs('ipv4-addr', 'campaign')).toBeNull()
  })

  it('includes the two pairs that the Policy page used to carry separately', () => {
    expect(STIX_REL_CONSTRAINTS['email-message>email-addr']).toEqual(['related-to'])
    expect(STIX_REL_CONSTRAINTS['file>malware']).toEqual(['related-to'])
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
