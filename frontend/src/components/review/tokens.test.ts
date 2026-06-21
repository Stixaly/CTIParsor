import { describe, it, expect } from 'vitest'
import {
  buildRanges,
  suggestRelType,
  generateDefangedVariants,
  verbsForPair,
  confPct,
} from './tokens'

type E = { id: string; value: string; entity_type: string; accepted: boolean | null }
const ent = (id: string, value: string, entity_type = 'malware', accepted: boolean | null = null): E =>
  ({ id, value, entity_type, accepted })

describe('buildRanges', () => {
  it('highlights a whole-word entity occurrence', () => {
    const text = 'The Emotet loader ran.'
    const ranges = buildRanges(text, [ent('1', 'Emotet')])
    expect(ranges).toHaveLength(1)
    expect(text.slice(ranges[0].start, ranges[0].end)).toBe('Emotet')
  })

  it('skips rejected entities', () => {
    const text = 'Emotet here'
    const ranges = buildRanges(text, [ent('1', 'Emotet', 'malware', false)])
    expect(ranges).toHaveLength(0)
  })

  it('matches all occurrences without overlap', () => {
    const text = 'Emotet and Emotet again'
    const ranges = buildRanges(text, [ent('1', 'Emotet')])
    expect(ranges).toHaveLength(2)
  })

  it('longer entity wins over a shorter overlapping one', () => {
    const text = 'Lazarus Group attacked'
    const ranges = buildRanges(text, [ent('1', 'Lazarus'), ent('2', 'Lazarus Group')])
    // "Lazarus Group" should claim the span, not bare "Lazarus"
    const claimed = ranges.map(r => text.slice(r.start, r.end))
    expect(claimed).toContain('Lazarus Group')
    expect(claimed).not.toContain('Lazarus')
  })

  it('does NOT highlight an entity value that is only a substring of a larger word', () => {
    // "Win" must not match inside "Windows"
    const text = 'Windows host infected'
    const ranges = buildRanges(text, [ent('1', 'Win')])
    expect(ranges).toHaveLength(0)
  })

  it('does NOT match an IP inside a longer dotted number run', () => {
    const text = 'build 11.2.3.40 here'
    const ranges = buildRanges(text, [ent('1', '1.2.3.4', 'ipv4')])
    expect(ranges).toHaveLength(0)
  })

  it('still matches an IoC bordered by punctuation/space', () => {
    const text = 'C2 at 1.2.3.4, port 80'
    const ranges = buildRanges(text, [ent('1', '1.2.3.4', 'ipv4')])
    expect(ranges).toHaveLength(1)
    expect(text.slice(ranges[0].start, ranges[0].end)).toBe('1.2.3.4')
  })
})

describe('generateDefangedVariants', () => {
  it('produces bracketed-dot forms for a domain', () => {
    const v = generateDefangedVariants('evil.com')
    expect(v).toContain('evil[.]com')
  })

  it('produces hxxp + at-sign forms', () => {
    expect(generateDefangedVariants('http://evil.com')).toContain('hxxp://evil.com')
    expect(generateDefangedVariants('a@b.com')).toContain('a[at]b.com')
  })
})

describe('suggestRelType', () => {
  it('suggests a spec verb for a known pair (threat-actor → malware)', () => {
    expect(suggestRelType('threat_actor', 'malware')).toBe('uses')
  })

  it('falls back to related-to for an unconstrained pair', () => {
    expect(suggestRelType('ipv4', 'campaign')).toBe('related-to')
  })
})

describe('verbsForPair', () => {
  it('marks a constrained pair and returns its valid verbs', () => {
    const r = verbsForPair('malware', 'vulnerability')
    expect(r.constrained).toBe(true)
    expect(r.valid).toContain('exploits')
  })

  it('returns all verbs for an unconstrained pair', () => {
    const r = verbsForPair('ipv4', 'campaign')
    expect(r.constrained).toBe(false)
    expect(r.valid.length).toBeGreaterThan(5)
  })
})

describe('confPct', () => {
  it('handles 0-1 and 0-100 inputs', () => {
    expect(confPct(0.9)).toBe(90)
    expect(confPct(90)).toBe(90)
  })
})
