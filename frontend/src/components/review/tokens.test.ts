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

  it('locates a contiguous hash on one line', () => {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const text = `File Hash: ${hash} (SHA-256)`
    const ranges = buildRanges(text, [ent('1', hash, 'sha256')])
    expect(ranges).toHaveLength(1)
    expect(text.slice(ranges[0].start, ranges[0].end)).toBe(hash)
  })

  it('locates a hash wrapped across three lines (de-wrapped stored value)', () => {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const wrapped = `${hash.slice(0, 26)}\n${hash.slice(26, 52)}\n${hash.slice(52)}`
    const text = `IOC table\n${wrapped}\nmeshagent.exe`
    const ranges = buildRanges(text, [ent('1', hash, 'sha256')])
    // One range per wrapped line, all pointing at the same entity.
    expect(ranges).toHaveLength(3)
    expect(new Set(ranges.map(r => r.entityId))).toEqual(new Set(['1']))
    // The ranges together reassemble to the stored hash.
    expect(ranges.map(r => text.slice(r.start, r.end)).join('')).toBe(hash)
  })

  it('does not extend a wrapped-hash highlight over the line breaks', () => {
    // A single range spanning the wrap paints the trailing whitespace of every
    // line — in the reader it runs to the right margin, and in the PDF view it
    // covers the table cells beside the hash.
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const wrapped = `${hash.slice(0, 26)}\n${hash.slice(26, 52)}\n${hash.slice(52)}`
    const text = `IOC table\n${wrapped}\nmeshagent.exe`
    const ranges = buildRanges(text, [ent('1', hash, 'sha256')])
    for (const r of ranges) {
      expect(text.slice(r.start, r.end)).not.toMatch(/\s/)
    }
  })

  it('keeps the first range at the start of a wrapped hash (scroll target)', () => {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const text = `IOC table\n${hash.slice(0, 40)}\n${hash.slice(40)}\nmeshagent.exe`
    const ranges = buildRanges(text, [ent('1', hash, 'sha256')])
    expect(text.slice(ranges[0].start, ranges[0].end)).toBe(hash.slice(0, 40))
  })

  it('highlights stacked hashes in a column as separate entities', () => {
    // Two MD5s in one table column: each must light up on its own row, with no
    // highlight bridging the gap between them.
    const a = 'd41d8cd98f00b204e9800998ecf8427e'
    const b = '5d41402abc4b2a76b9719d911017c592'
    const text = `File Hash\n${a}\n${b}\n`
    const ranges = buildRanges(text, [ent('1', a, 'md5'), ent('2', b, 'md5')])
    expect(ranges).toHaveLength(2)
    expect(text.slice(ranges[0].start, ranges[0].end)).toBe(a)
    expect(text.slice(ranges[1].start, ranges[1].end)).toBe(b)
  })

  it('does not match a hash that is not present in the text', () => {
    const hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    const ranges = buildRanges('No indicators in this narrative report.', [ent('1', hash, 'sha256')])
    expect(ranges).toHaveLength(0)
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
