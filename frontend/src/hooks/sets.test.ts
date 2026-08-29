import { describe, it, expect, beforeEach, vi } from 'vitest'

import { toggleInSet, loadStringSet, saveStringSet } from './sets'

describe('toggleInSet', () => {
  it('adds an absent item', () => {
    const result = toggleInSet(new Set(['a']), 'b')
    expect(result.has('a')).toBe(true)
    expect(result.has('b')).toBe(true)
  })

  it('removes a present item', () => {
    const result = toggleInSet(new Set(['a', 'b']), 'b')
    expect(result.has('a')).toBe(true)
    expect(result.has('b')).toBe(false)
  })

  it('never mutates the input', () => {
    const input = new Set(['a', 'b'])
    const originalSize = input.size
    const result = toggleInSet(input, 'a')
    expect(input.size).toBe(originalSize)
    expect(result).not.toBe(input)
  })
})

describe('loadStringSet', () => {
  beforeEach(() => localStorage.clear())

  it('returns an empty set for a missing key', () => {
    const result = loadStringSet('missing')
    expect(result.size).toBe(0)
  })

  it('reads a stored array of strings', () => {
    localStorage.setItem('key', JSON.stringify(['a', 'b']))
    const result = loadStringSet('key')
    expect(result.size).toBe(2)
  })

  it('drops non-string members', () => {
    localStorage.setItem('key', '["a", 1, null, "b", true]')
    const result = loadStringSet('key')
    expect(result.size).toBe(2)
    expect(result.has('a')).toBe(true)
    expect(result.has('b')).toBe(true)
  })

  it('returns an empty set for invalid JSON', () => {
    localStorage.setItem('key', '{not json')
    const result = loadStringSet('key')
    expect(result.size).toBe(0)
  })

  it('returns an empty set when the stored value is not an array', () => {
    localStorage.setItem('key', '{"a":1}')
    const result = loadStringSet('key')
    expect(result.size).toBe(0)
  })

  it('returns an empty set when localStorage throws', () => {
    const spy = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied')
    })
    const result = loadStringSet('key')
    expect(result.size).toBe(0)
    spy.mockRestore()
  })
})

describe('saveStringSet', () => {
  beforeEach(() => localStorage.clear())

  it('writes the set as a JSON array', () => {
    saveStringSet('key', new Set(['a', 'b']))
    const raw = localStorage.getItem('key')
    expect(raw).not.toBeNull()
    const parsed = JSON.parse(raw as string)
    expect(Array.isArray(parsed)).toBe(true)
    expect(parsed.length).toBe(2)
  })

  it('round-trips through loadStringSet', () => {
    const original = new Set(['a', 'b'])
    saveStringSet('key', original)
    const loaded = loadStringSet('key')
    expect(loaded.size).toBe(original.size)
    expect(loaded.has('a')).toBe(true)
    expect(loaded.has('b')).toBe(true)
  })

  it('does not throw when localStorage throws', () => {
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('denied')
    })
    expect(() => saveStringSet('key', new Set(['a']))).not.toThrow()
    spy.mockRestore()
  })
})
